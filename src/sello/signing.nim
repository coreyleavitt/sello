## sello/signing.nim — Seed/Keypair types, lifecycle, and RFC 8032 keygen
## (RFC-001 Stage B). Backend dispatch (pure-Nim vs. libsodium) lives here
## too (RFC-001 slice 10): `when defined(selloLibsodium)` selects
## `sello/private/backend_sodium` in place of `sello/private/backend`,
## both bound to the same local name `backend` so every call site below
## is backend-agnostic. The facade re-exports from this module and gains
## no conditional logic of its own. `sello/ed25519.verify` has no
## dispatch at all -- it is always the pure-Nim verifier, on both
## backends.
##
## Contracts:
##
## - **Invariant:** `kp.public == derive(kp.seed)`, always. `Keypair`'s
##   fields are private and `keypair(seed)` is the only constructor, so a
##   mismatched pair is unconstructible.
## - **`Seed` is its own nominal type, never interchangeable with
##   `PublicKey`.** Both are 32 raw bytes underneath, and even now that
##   `PublicKey` is `distinct` in its own right (RFC-001 finding 9, see
##   `sello/wire`), that only stops a *bare* `array[32, byte]` (or a
##   different distinct type, like X25519's `X25519Public`) from being
##   accepted where a `PublicKey` belongs — it does nothing to stop a
##   `PublicKey` and a `Seed` from being confused for each other, since
##   they are two independently-defined nominal types with no relation.
##   `Seed`'s own distinctness (and its `=destroy` wipe hook, which
##   `PublicKey` has no need of — see `sello/wire`'s doc comment on why
##   not) is what closes that specific gap. Construction is the explicit,
##   greppable `toSeed(bytes)` at exactly the point where bytes become
##   secret. `wipe` remains for explicit early wiping.
##
## - **`Seed` is move-only** (RFC-002 slice 1), the same `=copy {.error.}`
##   pattern as `Keypair`: `toSeedBytes(kp: Keypair)` (renamed from
##   `toBytes` by round-3 finding A7 -- see that proc's own doc comment) is
##   the persistence escape hatch now (below), so nothing in the public API
##   needs a second live `Seed` copy any more -- the old copyable `Seed`
##   was rationalizing a missing `toSeedBytes`, not serving a real need.
##   `Seed` also has no `==` (RFC-002 slice 1): the X25519 secret family
##   (`x25519.nim`) never had one at all, on the principle that this
##   library does not offer even a vartime comparison on secret material;
##   `Seed`'s old test/tooling-only `==` was the same principle enforced
##   one layer up (facade export list) instead of at the type itself.
##   Tests compare seeds via `toSeedBytes(kp)` on a keypair derived from
##   them, or a raw-pointer probe for a standalone `Seed` (see
##   `test_signing.nim`).
##
##   Two deviations from RFC-001's literal §"Public API" text, both
##   forced by empirical Nim 2.2.10 behavior rather than a judgment call,
##   recorded here so slice 6+ doesn't rediscover them:
##
##   1. **Representation:** the RFC's first-choice `Seed = distinct
##      array[32, byte]` compiles clean with no diagnostic, but its
##      `=destroy` silently never fires for a bare local `Seed` value —
##      ORC only inserts a destroy call for `Seed` when it is a field of
##      another object (`Keypair.seed`, via that object's own
##      compiler-synthesized field-wise destructor), never for a
##      standalone `distinct array` local. Confirmed by inspecting the
##      generated C: no `eqdestroy` call is emitted around such a local
##      at all, vs. a one-field `object` of the same shape, which does
##      get one. That silently defeats the entire point of an
##      auto-wiping `Seed` for any caller holding one standalone (e.g. a
##      `Seed` constructed via `toSeed(bytes)` and held before being
##      passed to `keypair`) — worse than a compiler error, since nothing
##      signals the gap. RFC-001's pre-approved fallback applies: `Seed`
##      below is the one-field object, not a distinct array.
##   2. **Constructor spelling:** the RFC's exact `Seed(bytes)` call
##      syntax is a language feature of `distinct` types specifically
##      (a built-in reinterpret-cast), not something a plain `object` can
##      replicate — Nim rejects a same-named `proc`/`converter` on top of
##      an object type outright ("redefinition of 'Seed'"), so there is
##      no way to keep the literal spelling once the representation
##      changes. `toSeed(bytes)` is the closest legal, idiomatic
##      substitute (an explicit, named conversion, exactly analogous in
##      intent to the distinct-type cast it replaces).
## - **`Keypair` is move-only:** `=copy` is a compile error, not a hygiene
##   footnote; legitimate transfers move (Nim inserts moves at last use).
##   No custom `=sink` is needed. `Seed` follows the same pattern (see
##   above).
## - **`keypair()` raises `OSError` on CSPRNG failure**, one of five
##   fresh-secret constructors across the public surface that share this
##   fail-fast policy (`keypair()`; `x25519.x25519StaticSecret`,
##   `x25519EphemeralSecret`, `x25519StaticPair`, `x25519EphemeralPair` —
##   see `x25519.nim`). Nothing else in the pure-Nim public surface raises
##   -- and that is a declared, compiler-checked effect now (`{.push
##   raises: [].}`/`gcsafe` over every public module, with explicit
##   `{.raises: [OSError].}` on the five constructors; janus consumer
##   finding 3), not a doc-comment promise.
##   Under `-d:selloLibsodium`, `keypair(seed)`/`keypair()`/`sign` can also
##   raise `SodiumInitError` (`private/backend_sodium.nim`) if libsodium's
##   one-time `sodium_init()` call fails — reachable through this module's
##   dispatch, not merely an internal detail of that backend. `keypair()`
##   fills the stack `Seed` in place via
##   `std/sysrand`'s `urandom(dest: var openArray[byte]): bool` overload;
##   the `urandom(size)` convenience overload is never used here because it
##   returns a heap `seq`, which would route the fresh seed through
##   allocated memory before it reaches the stack.
## - **Lifecycle:** `Keypair` and `Seed` both carry `=destroy` wipes (ORC
##   is already the project's memory mode). Never box key material in a
##   `seq`/`ref` container — hold `Keypair` as a stack value.
## - **Concurrency:** everything here is a plain value type; `keypair`
##   calls on independent seeds from multiple threads are safe by
##   construction.
## - **One name:** `keypair`, everywhere — `keypair(seed)` for
##   import/tests/derivation, `keypair()` for a fresh identity. No
##   `keypairFromSeed`.

import std/[options, sysrand]
import sello/wire  # PublicKey/Signature nominal types (RFC-001 finding 9)
import sello/private/ct
import sello/private/secret_hooks

when defined(selloLibsodium):
  # RFC-001 slice 10: libsodium FFI adapter. Same seed-level contract
  # (`derivePublic`, `signDetached`) as the pure-Nim backend below, so
  # nothing past this import needs to know which one is active.
  import sello/private/backend_sodium as backend
else:
  import sello/private/backend

## The raises/gcsafe contract below is compiler-enforced, not prose (janus
## consumer finding 3): before this push, the module doc's "nothing else in
## the pure-Nim public surface raises" promise was held only by downstream
## consumers' own `{.raises: [].}` annotations via cross-module effect
## inference -- a future accidental raise here would keep sello's own build
## green and surface as an opaque effect-inference error at the consumer's
## call site. `keypair()` (the one `std/sysrand` constructor in this
## module) overrides with its own explicit annotation below.
when defined(selloLibsodium):
  # `SodiumInitError` (a hard `sodium_init()` failure -- see
  # `private/backend_sodium.nim`) is reachable through this module's
  # dispatch on this backend, so it is part of the declared effect here.
  # Re-exported so callers can name the type they must handle without
  # importing a `private/` module.
  export backend.SodiumInitError
  {.push raises: [SodiumInitError], gcsafe.}
else:
  {.push raises: [], gcsafe.}

type
  Seed* = object
    ## RFC 8032 private key: 32 uniformly random bytes. Every bit pattern
    ## is a valid seed — there is no decode/rejection path (contrast
    ## `PublicKey`/`Signature`). Not libsodium's 64-byte secret key.
    ## Construct via `toSeed(bytes)`. One-field object — see the module
    ## doc comment for why the RFC's first-choice `distinct
    ## array[32, byte]` is not used here.
    ##
    ## **Move-only, like `Keypair`** (RFC-002 slice 1): `=copy` is a
    ## compile error; legitimate transfers move. `toSeedBytes(kp: Keypair)`
    ## below is the persistence escape hatch, so nothing in the public API
    ## needs a second live `Seed` copy any more -- see the module doc
    ## comment for the fuller rationale.
    ##
    ## **Why move-only rather than copyable-with-self-wiping like
    ## `x25519.X25519StaticSecret` (round-4 finding R9):** the two look
    ## like structurally parallel "reusable secret" roles but are not --
    ## `Seed` is a TRANSIENT raw-seed INPUT to `keypair()`, single custody
    ## en route from CSPRNG (or caller-supplied bytes) to the `Keypair` it
    ## produces, not a long-lived secret a caller holds and reuses on its
    ## own. Move-only is load-bearing here, not incidental: it is what
    ## makes round-4 finding R4's wipe-then-reuse guarantee a compile
    ## error rather than a caller discipline (`wipe(sink Seed)` below
    ## consumes `s`, so a later `keypair(move(s))` on the same variable is
    ## the same `=copy {.error.}` diagnostic reuse already produces --
    ## pinned by `tests/unit/fixtures/reject_seed_wipe_then_use.nim`).
    ## Making `Seed` copyable would silently reopen that hole: a copy taken
    ## before `wipe` could still be fed to `keypair` after the original was
    ## zeroed, with no compile-time signal at all. See the module-group
    ## policy note on `x25519.X25519StaticSecret`'s doc comment for the
    ## copyable side of this design and the general rule it falls under.
    bytes: array[32, byte]

  Keypair* = object
    ## Move-only: `=copy` is declared `{.error.}`. Fields are deliberately
    ## not exported — `keypair(seed)` is the only constructor, so a
    ## mismatched (public, seed) pair is unconstructible.
    ##
    ## Falls under the same move-only-vs-copyable policy as `Seed` above
    ## (round-4 finding R9): `Keypair` is a bundled identity -- secret plus
    ## public plus the invariant tying them together -- and move-only is
    ## what prevents silent whole-identity duplication. See `Seed`'s doc
    ## comment for the fuller policy writeup, cross-linked from
    ## `x25519.X25519StaticSecret`/`X25519EphemeralSecret` on the X25519
    ## side.
    public: PublicKey
    seed: Seed

## Type hooks must be declared immediately after the type they attach to,
## before anything else touches the type by value — otherwise Nim may
## synthesize (and lock in) a default hook first and then reject an
## explicit one declared later with "cannot bind another '=destroy'". The
## `secretHooks*`/`secretHooksMoveOnly*` templates below (round-3 finding
## A5, `sello/private/secret_hooks`) expand to exactly the hand-written
## `=destroy`/`=copy` shape this comment used to introduce directly -- see
## that module's doc comment for the full "why a template, why
## `{.dirty.}`, why `Keypair` stays hand-written" writeup, including
## round-4 finding R10's simplification to a two-argument `(Type, field)`
## signature (no more per-type `zeroizeProc` name).

## RFC-001 slice 8: `Seed`'s `=destroy` (emitted below by
## `secretHooksMoveOnly`) is routed through `ct.wipe` (volatile stores +
## compiler barrier) rather than a plain loop -- the whole point of the
## hook is to guarantee the wipe actually happens, which a
## compiler-eliminable dead store would silently defeat (see
## `sello/private/ct` and the x25519.nim ladder fix in this same slice).
## The `=copy {.error.}` this also emits (RFC-002 slice 1): a second live
## copy of a `Seed` is a compile error, not a runtime hygiene footnote.
## Legitimate transfers move. (Round-4 finding R10: the template no longer
## takes a separate `zeroizeProc` name -- see `secret_hooks.nim`'s doc
## comment.)
secretHooksMoveOnly(Seed, bytes)

proc `=copy`(dst: var Keypair; src: Keypair) {.error.}
  ## A second live copy of the seed is a compile error, not a runtime
  ## hygiene footnote. Legitimate transfers move.

func toSeed*(bytes: array[32, byte]): Seed {.inline.} =
  ## Explicit construction — the point where raw bytes become a secret.
  Seed(bytes: bytes)

proc wipe*(s: sink Seed) =
  ## Explicit early wipe, e.g. right after deriving a `Keypair` when the
  ## caller does not need to retain the raw seed. `=destroy` performs the
  ## same wipe automatically at scope exit; this exists for callers that
  ## want it sooner.
  ##
  ## Takes `sink`, not `var` (round-4 finding R4): `Seed` is move-only and
  ## its whole design point is compiler-enforced single use, but a `var`
  ## `wipe` does not consume its argument, so a caller could write
  ## `wipe(s)` and then still reach a consuming `keypair(move(s))` -- which
  ## compiled and derived a keypair from the just-zeroed, all-zero seed,
  ## silently defeating the single-use guarantee. With `sink`, `wipe`
  ## consumes `s` exactly like `keypair` does, so a later use of the same
  ## variable -- moved or not -- is the same `=copy {.error.}` compile
  ## error `keypair`'s own reuse already produces; see
  ## `tests/unit/fixtures/reject_seed_wipe_then_use.nim`, driven by
  ## `test_signing.nim`, for the regression pin. The type's single
  ## ownership moves to whichever consumes it first, `wipe` or `keypair`,
  ## same as before -- only the enforcement mechanism changed.
  ##
  ## Calls `ct.wipe` directly (round-4 finding R10), not a named
  ## `zeroizeSeed` proc -- see `private/secret_hooks.nim`'s doc comment.
  ct.wipe(s.bytes)

proc wipe*(kp: var Keypair) =
  ## Eager-scrub counterpart to `wipe(var Seed)` (RFC-001 ledger finding
  ## 16): zeroes `kp`'s secret half (its `Seed`, via the same `ct.wipe`
  ## path `Seed`'s own `=destroy` uses) in place, for a caller that wants
  ## the secret gone before `kp` itself goes out of scope. `kp.public` is
  ## not secret and is left untouched -- it stays readable after this call,
  ## unlike the seed. `Keypair`'s own `=destroy` (via its `Seed` field's
  ## `=destroy`) performs the same wipe automatically at scope exit
  ## regardless; this exists for the same "sooner, explicitly" reason
  ## `wipe(var Seed)` does.
  ct.wipe(kp.seed.bytes)

func public*(kp: Keypair): PublicKey =
  ## The keypair's public key (cached at construction — never re-derived).
  kp.public

func toSeedBytes*(kp: Keypair): array[32, byte] {.inline.} =
  ## Persistence escape hatch: the keypair's raw seed bytes (RFC-002
  ## slice 1 -- replaces the old `seed()` accessor, which returned a
  ## `Seed` the public API provided no way to extract bytes from).
  ## **Renamed from `toBytes` (round-3 finding A7):** every other
  ## `toBytes` in this codebase serializes ITS OWN type's identity
  ## (`PublicKey`'s bytes, `X25519Shared`'s bytes, ...) -- this one instead
  ## returns the keypair's SEED, a different (if related) value than "the
  ## keypair itself," which the old name `toBytes(kp: Keypair)` did not
  ## signal at the call site; a reader could easily assume it serializes
  ## the whole keypair (public key included) rather than exposing raw
  ## secret seed material. `toSeedBytes` says exactly what it returns.
  ## Semantics are unchanged: the returned copy is caller-owned and NOT
  ## wiped by this call -- wipe it yourself (e.g. `sello/wipe.wipe`) once
  ## you are done with it, the same register as
  ## `X25519StaticSecret.toBytes` (`sello/x25519`).
  kp.seed.bytes

proc keypair*(seed: sink Seed): Keypair =
  ## The only constructor: derives the public key per RFC 8032 §5.1.5
  ## (`A = clamp(SHA-512(seed))[0..31]) * B`). Deterministic: the same
  ## seed always yields the same `Keypair`. `seed` is consumed: `Seed` is
  ## move-only (RFC-002 slice 1), and `keypair(toSeed(bytes))` (an rvalue
  ## argument) remains the construction idiom.
  ##
  ## `proc`, not `func` (round-3 finding A4): calls `backend.derivePublic`,
  ## which is itself `proc` now on both backends (the sodium adapter has
  ## real FFI/global-state side effects it can no longer hide behind a
  ## false `{.cast(noSideEffect).}` -- see `private/backend_sodium.nim`).
  result.public = toPublicKey(backend.derivePublic(seed.bytes))
  result.seed = seed

proc keypair*(seed: sink Seed; expectedPublic: PublicKey): Option[Keypair] =
  ## Load-time consistency check for PERSISTED keys (janus consumer finding
  ## 2): derives the keypair from `seed` exactly like `keypair(seed)`, then
  ## compares the derived public key against the caller's stored copy --
  ## `some` on a match, `none` on a mismatch. Use this whenever the storage
  ## format carries both halves (the dominant real-world layout is
  ## OpenSSH's/libsodium's `seed(32) ‖ publicKey(32)` secret key), so a
  ## corrupted or mixed-up stored key is rejected at load time instead of
  ## silently signing under a public key the caller never presented --
  ## sello re-derives the public half, so without this gate that failure
  ## mode fails OPEN (the signatures are valid, just not for the identity
  ## the caller thinks it loaded). `keypair(seed)` remains the constructor
  ## for seed-only storage, where no stored public half exists to check.
  ##
  ## `Option`, not a raised exception, for the same reason as `x25519`'s
  ## small-order `none` (round-3 finding A8): a mismatch is a well-defined
  ## negative answer about the caller's input, and the pure surface's
  ## raises contract (see the module-level push above) reserves raising for
  ## CSPRNG/backend failure. On the `none` path the derived keypair's
  ## secret half is wiped by `Keypair`'s own `=destroy` before this proc
  ## returns; nothing secret-derived escapes.
  ##
  ## `Keypair` is move-only, so extract the payload with `move`, via the
  ## `var Option` `get` overload:
  ##
  ## ```nim
  ## var loaded = keypair(toSeed(seedBytes), toPublicKey(storedPublic))
  ## if loaded.isNone: quit("stored key is corrupt")
  ## var kp = move(loaded.get())
  ## ```
  var kp = keypair(seed)
  if kp.public == expectedPublic:
    result = some(move(kp))
  else:
    result = none(Keypair)

## `keypair()` raises `OSError` on CSPRNG failure on top of the module
## default, so it gets its own exact effect region -- an explicit
## per-backend annotation region rather than widening the whole module's
## push to include `OSError`, which would loosen every other declaration
## here for one constructor's sake.
{.pop.}
when defined(selloLibsodium):
  {.push raises: [OSError, SodiumInitError], gcsafe.}
else:
  {.push raises: [OSError], gcsafe.}

proc keypair*(): Keypair =
  ## Fresh identity via `std/sysrand`'s in-place `urandom`. Raises
  ## `OSError` if the OS CSPRNG call fails, the same fail-fast policy
  ## shared by every fresh-secret constructor in the public surface
  ## (see the module doc comment above); callers let it propagate
  ## uncaught (fail-fast on a broken CSPRNG is correct). Never
  ## `std/random`.
  ##
  ## RFC-001's "Seed sourcing" contract requires filling the stack `Seed`
  ## directly via `urandom`'s in-place `openArray[byte]` overload — never a
  ## bare local `array[32, byte]` that gets wrapped afterward, which would
  ## leave the raw seed sitting unwiped in a dead stack slot once `toSeed`
  ## copies it into the `Seed` that actually gets destroyed. Same-module
  ## access to `Seed.bytes` (see the module doc comment) is what makes
  ## filling in place possible.
  var s: Seed
  if not urandom(s.bytes):
    raise newException(OSError, "sello.keypair: sysrand.urandom failed")
  # `move(s)`: `keypair(seed: sink Seed)`'s sink-argument "is this the
  # last read" inference is a whole-scope occurrence count, not a true
  # escape analysis (the same empirical finding `x25519.nim`'s
  # `x25519(sink X25519EphemeralSecret, ...)` doc comment records) -- the
  # `urandom(s.bytes)` field read above is an earlier reference to `s`, so
  # the compiler needs this explicit assertion that the move below is
  # safe.
  result = keypair(move(s))

# End of the OSError region -- back to the module default for `sign`.
{.pop.}
when defined(selloLibsodium):
  {.push raises: [SodiumInitError], gcsafe.}
else:
  {.push raises: [], gcsafe.}

proc sign*(kp: Keypair; msg: openArray[byte]): Signature =
  ## RFC 8032 §5.1.6 detached signature over `msg`. Deterministic and
  ## total: the same `(kp, msg)` pair always yields the same signature, and
  ## it cannot fail for any seed/message — unlike `x25519`, whose `Option`
  ## exists only because of the small-order degenerate input class, which
  ## signing structurally lacks. Dispatches to `backend.signDetached`,
  ## which reaches into `kp.seed`'s private bytes directly (same-module
  ## access — see the module doc comment) and never persists an expanded
  ## key. Passes `kp.public`'s bytes through too (RFC-001 ledger finding
  ## 13): `signDetached` uses the already-derived, already-cached public
  ## key as `A` instead of re-deriving it from the secret scalar on every
  ## call, which is exactly what the `Keypair` invariant
  ## (`kp.public == derive(kp.seed)`) exists to make safe.
  ##
  ## `proc`, not `func` (round-3 finding A4): same reason as `keypair(seed:
  ## sink Seed)` above -- `backend.signDetached` is `proc` on both
  ## backends now.
  toSignature(backend.signDetached(kp.seed.bytes, toBytes(kp.public), msg))

proc sign*(kp: Keypair; msg: string): Signature =
  ## Zero-copy `string` overload: `openArray[byte]` does not accept
  ## `string` in Nim, and `kp.sign("hello")` failing to compile flunks the
  ## ergonomics bar. `msg.toOpenArrayByte` views the string's existing
  ## bytes in place -- no copy, no allocation. `ed25519.verify` gains the
  ## matching additive overload in the same slice. `proc`, not `func`
  ## (round-3 finding A4): calls the `openArray[byte]` overload above,
  ## itself `proc` now.
  kp.sign(msg.toOpenArrayByte(0, msg.len - 1))

{.pop.}
