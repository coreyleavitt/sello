## sello/signing.nim — Seed/Keypair types, lifecycle, and RFC 8032 keygen
## (RFC-001 Stage B). Backend dispatch (pure-Nim vs. libsodium) also lands
## here once the adapter exists (RFC-001 slice 10); the facade re-exports
## from this module and gains no conditional logic of its own.
##
## Contracts:
##
## - **Invariant:** `kp.public == derive(kp.seed)`, always. `Keypair`'s
##   fields are private and `keypair(seed)` is the only constructor, so a
##   mismatched pair is unconstructible.
## - **`Seed` is its own nominal type, never interchangeable with
##   `PublicKey`.** `PublicKey` has the identical raw shape
##   (`array[32, byte]`); with a plain alias the compiler would accept a
##   public key anywhere a seed belongs (including transposed fields
##   inside this module) and no `=destroy` could attach to `Seed`
##   specifically. Construction is the explicit, greppable `toSeed(bytes)`
##   at exactly the point where bytes become secret, and `Seed` carries
##   its own wipe hook, so the copy `seed()` returns — and any
##   caller-held `Seed` — zeroes itself at scope exit instead of relying
##   on a doc comment. `wipe` remains for explicit early wiping. `==` is
##   for tests/tooling only and is vartime.
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
##      auto-wiping `Seed` for any caller holding one outside a
##      `Keypair` (e.g. the `seed()` accessor's return value used
##      standalone) — worse than a compiler error, since nothing signals
##      the gap. RFC-001's pre-approved fallback applies: `Seed` below is
##      the one-field object, not a distinct array.
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
##   No custom `=sink` is needed.
## - **`keypair()` is the only function in sello's public surface that can
##   raise** (`OSError`, on CSPRNG failure) — fail fast on a broken source
##   of randomness. It fills the stack `Seed` in place via
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

import std/sysrand
import sello/ed25519
import sello/private/backend

type
  Seed* = object
    ## RFC 8032 private key: 32 uniformly random bytes. Every bit pattern
    ## is a valid seed — there is no decode/rejection path (contrast
    ## `PublicKey`/`Signature`). Not libsodium's 64-byte secret key.
    ## Construct via `toSeed(bytes)`. One-field object — see the module
    ## doc comment for why the RFC's first-choice `distinct
    ## array[32, byte]` is not used here.
    bytes: array[32, byte]

  Keypair* = object
    ## Move-only: `=copy` is declared `{.error.}`. Fields are deliberately
    ## not exported — `keypair(seed)` is the only constructor, so a
    ## mismatched (public, seed) pair is unconstructible.
    public: PublicKey
    seed: Seed

## Type hooks must be declared immediately after the type they attach to,
## before anything else touches the type by value — otherwise Nim may
## synthesize (and lock in) a default hook first and then reject an
## explicit one declared later with "cannot bind another '=destroy'".

func zeroizeSeed(s: var Seed) {.inline.} =
  for i in 0 ..< 32: s.bytes[i] = 0

proc `=destroy`(s: var Seed) =
  zeroizeSeed(s)

proc `=copy`(dst: var Keypair; src: Keypair) {.error.}
  ## A second live copy of the seed is a compile error, not a runtime
  ## hygiene footnote. Legitimate transfers move.

func toSeed*(bytes: array[32, byte]): Seed {.inline.} =
  ## Explicit construction — the point where raw bytes become a secret.
  Seed(bytes: bytes)

func `==`*(a, b: Seed): bool =
  ## Vartime equality — tests/tooling only, never on a path that mixes
  ## secret and attacker-controlled data.
  a.bytes == b.bytes

proc wipe*(s: var Seed) =
  ## Explicit early wipe, e.g. right after deriving a `Keypair` when the
  ## caller does not need to retain the raw seed. `=destroy` performs the
  ## same wipe automatically at scope exit; this exists for callers that
  ## want it sooner.
  zeroizeSeed(s)

func public*(kp: Keypair): PublicKey =
  ## The keypair's public key (cached at construction — never re-derived).
  kp.public

func seed*(kp: Keypair): Seed =
  ## Persistence escape hatch. The returned copy auto-wipes at scope exit
  ## via `Seed`'s own `=destroy`.
  kp.seed

func keypair*(seed: Seed): Keypair =
  ## The only constructor: derives the public key per RFC 8032 §5.1.5
  ## (`A = clamp(SHA-512(seed))[0..31]) * B`). Deterministic: the same
  ## seed always yields the same `Keypair`.
  result.public = PublicKey(backend.derivePublic(seed.bytes))
  result.seed = seed

proc keypair*(): Keypair =
  ## Fresh identity via `std/sysrand`'s in-place `urandom`. Raises
  ## `OSError` if the OS CSPRNG call fails — the only function in sello's
  ## public surface that can raise; callers let it propagate uncaught
  ## (fail-fast on a broken CSPRNG is correct). Never `std/random`.
  var bytes: array[32, byte]
  if not urandom(bytes):
    raise newException(OSError, "sello.keypair: sysrand.urandom failed")
  result = keypair(toSeed(bytes))

func sign*(kp: Keypair; msg: openArray[byte]): Signature =
  ## RFC 8032 §5.1.6 detached signature over `msg`. Deterministic and
  ## total: the same `(kp, msg)` pair always yields the same signature, and
  ## it cannot fail for any seed/message — unlike `x25519`, whose `Option`
  ## exists only because of the small-order degenerate input class, which
  ## signing structurally lacks. Dispatches to `backend.signDetached`,
  ## which reaches into `kp.seed`'s private bytes directly (same-module
  ## access — see the module doc comment) and never persists an expanded
  ## key.
  backend.signDetached(kp.seed.bytes, msg)
