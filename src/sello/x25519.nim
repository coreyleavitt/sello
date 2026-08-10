## X25519 — Diffie-Hellman key exchange over Curve25519 (RFC 7748 §5)
##
## Montgomery ladder over the u-coordinate only; reuses the GF(2^255-19)
## core from sello/field. Ladder structure follows RFC 7748 / ref10
## scalarmult_curve25519 (public domain).
##
## The scalar is a SECRET (the caller's private key), so the ladder is
## branchless on secret data: bit selection and lane swaps use arithmetic
## masking (feCSwap, marked `{.noinline.}` so the C compiler can't
## re-introduce a branch by inlining it into a context where the masking
## simplifies away), secrets live in fixed-size stack arrays, Nim's runtime
## checks are disabled in the core, and every secret-derived intermediate
## -- the clamped scalar copy, the ladder's own accumulators/temporaries,
## and the raw DH output (round-3 finding A1, extending RFC-001 slice 8's
## original clamped-scalar-only wipe) -- is wiped via `ct.wipe` (volatile
## stores + compiler barrier) once the ladder is done with it. The
## constant-time discipline above is
## backed by `tests/ct/`'s dudect harness, which covers this module's own
## secret-holding call shapes directly (`x25519Base`, the ephemeral
## construct+consume path, and the static-secret fixed-vs-random DH path
## — see `docs/ct-results.md`), not merely by association with ed25519
## signing.
##
## Public API types: role-typed wrappers, one per X25519 role (RFC-001
## ledger #29, revisited on Corey's direction; supersedes the single-
## `X25519Key` design B3 originally chose), with the SECRET role itself
## split in two (the static/ephemeral batch that completed ledger #29,
## mirroring x25519-dalek's `StaticSecret`/`EphemeralSecret` in this
## module's own vocabulary rather than importing dalek's names):
##
## - `X25519StaticSecret` — a clamped, REUSABLE private scalar. One-field
##   object (not `distinct array[32, byte]`) for the exact reason
##   `signing.Seed` is: Nim 2.2.10/ORC silently never fires `=destroy` on a
##   bare `distinct array` local, confirmed by inspecting the generated C
##   — see `signing.Seed`'s doc comment for the full writeup. `=destroy`
##   wipes. Deliberately copyable (like `Seed`, unlike `Keypair`): no
##   `=copy` override, every copy self-wipes independently at its own
##   scope exit.
## - `X25519EphemeralSecret` — a clamped, SINGLE-USE private scalar.
##   Move-only (`=copy {.error.}`, the `Keypair` pattern): constructed
##   ONLY via `x25519EphemeralSecret()` (fresh `std/sysrand`, no from-bytes
##   route — freshness by construction), no `toBytes` either (unpersistable
##   by design). `x25519Base` borrows it (non-consuming); `x25519` takes it
##   by `sink` and CONSUMES it — reuse is a compile error, fixture-verified
##   (see the type's own doc comment for the full contract, the `move()`
##   nuance this enforcement needs in practice, and its honestly-disclosed
##   residual scope).
## - `X25519Public` — a public u-coordinate: `x25519Base`'s result, or a
##   peer's value off the wire. Plain `distinct array[32, byte]`, freely
##   copyable — not secret material, no destructor.
## - `X25519Shared` — a completed DH output. This IS secret material (feed
##   it to a KDF, never use it directly as a key), so it follows
##   `X25519StaticSecret`'s exact shape: one-field object, copyable, wiped.
##
## Why role-typed wrappers instead of B3's one `X25519Key` covering every
## role: RFC 7748 does treat all of them as the identical 32-byte wire
## format, and that reasoning still holds -- but role confusion between
## SECRET and SENDABLE material fails open under one type (nothing stopped
## a shared secret or a private scalar from being handed to code expecting
## a value safe to log/transmit), and encoding "same wire format" as "same
## type" was never required by the format itself. Splitting mirrors the
## `Seed`/`PublicKey` treatment already established on the ed25519 side of
## this library. The further static/ephemeral split on the secret role
## mirrors `Keypair`'s move-only `=copy` closing accidental duplication:
## a single-use secret that the type system, not caller discipline, refuses
## to let outlive one exchange. Prefer `X25519EphemeralSecret` unless you
## specifically need a reusable/static identity.
##
## `toX25519StaticSecret`/`toX25519Public`/`toBytes` are the named conversions
## to/from raw bytes (symmetry with `sello/wire`'s `toPublicKey`/
## `toSignature` and `signing.toSeed`); `x25519StaticSecret()`/
## `x25519EphemeralSecret()` generate a fresh secret from `std/sysrand`.
## `wipe` (`X25519StaticSecret`-, `X25519EphemeralSecret`-, and
## `X25519Shared`-typed here; the generic `array[32, byte]` overload lives
## in `sello/wipe`) is the public, audited route to `private/ct.wipe` for
## X25519 secret material a caller holds directly, alongside the automatic
## `=destroy` wipe every secret-holding type here already carries.

import std/[hashes, options, sysrand]
import sello/field
import sello/private/ct
import sello/private/secret_hooks

## Compiler-enforced effect contract (janus consumer finding 3): nothing
## in this module raises or touches global GC'd state except the four
## `std/sysrand` constructors, which carry their own explicit
## `{.raises: [OSError].}` override below. See `signing.nim`'s module doc
## for the surface-wide policy.
{.push raises: [], gcsafe.}

type
  X25519Public* = distinct array[32, byte]
    ## A public u-coordinate (RFC 7748 §5): the result of `x25519Base`, or
    ## a peer's public value received over the wire. Freely copyable --
    ## this is not secret material.

  X25519StaticSecret* = object
    ## A clamped X25519 private scalar. One-field object, not `distinct
    ## array[32, byte]`: `signing.Seed`'s module doc comment already
    ## establishes, empirically, that a bare `distinct array` local's
    ## `=destroy` silently never fires under ORC on Nim 2.2.10 -- confirmed
    ## by inspecting the generated C, not assumed -- so the same
    ## one-field-object fallback applies here for the same reason. See
    ## `signing.Seed`'s doc comment for the full writeup.
    ##
    ## Deliberately copyable, like `Seed` and unlike `Keypair`: no `=copy`
    ## override, so `var b = a` compiles, and every copy carries its own
    ## `=destroy` and self-wipes independently at its own scope exit. There
    ## is no paired public value whose invariant a second live copy could
    ## violate (contrast `Keypair`), so duplication costs nothing beyond
    ## the copy itself.
    ##
    ## **Move-only-vs-copyable policy (round-4 finding R9):** this type and
    ## `signing.Seed` look like structurally parallel "reusable secret"
    ## roles -- `Seed` is move-only, this is copyable -- but the split is a
    ## coherent policy, not an accident:
    ## - **Move-only** = single-custody or single-use: `Keypair` (a bundled
    ##   identity; silent whole-identity duplication is the accident it
    ##   prevents), `Seed` (a transient raw-seed INPUT to `keypair()`, single
    ##   custody en route -- move-only is load-bearing for round-4 finding
    ##   R4's compile-time wipe-then-reuse guarantee, see `Seed`'s own doc
    ##   comment), `X25519EphemeralSecret` below (single-use by
    ##   construction, the same R4 guarantee).
    ## - **Copyable, self-wiping** = a reusable long-term secret HOLDER
    ##   where duplication is a legitimate ergonomic need and each copy
    ##   scrubs itself independently: `X25519StaticSecret` (this type -- the
    ##   durable X25519 identity; there is no wrapper type, so you hold the
    ##   secret directly and derive publics on demand, meaning reuse/storage
    ##   ergonomics matter the way they don't for a one-shot input --
    ##   x25519-dalek's `StaticSecret` is `Clone` for the same reason),
    ##   `X25519Shared` (a completed DH output you may need to copy into a
    ##   KDF call or similar).
    ##
    ## The through-line: transient/single-use/bundled-identity secrets are
    ## move-only; reusable bare-scalar holders are copyable-with-self-
    ## wiping. Do not make `Seed` copyable to "match" this type, or this
    ## type move-only to "match" `Seed` -- each is already the correct
    ## shape for its own role.
    bytes: array[32, byte]

  X25519Shared* = object
    ## The output of a completed Diffie-Hellman exchange (`x25519`). This
    ## IS secret material -- feed it to a KDF, never use it directly as a
    ## key -- so it follows `X25519StaticSecret`'s exact shape: one-field object,
    ## copyable, `=destroy`-wiped. Falls under the copyable-self-wiping-
    ## holder half of the move-only-vs-copyable policy documented on
    ## `X25519StaticSecret`'s doc comment (round-4 finding R9): a completed
    ## DH output you may need to copy into a KDF call.
    bytes: array[32, byte]

  X25519EphemeralSecret* = object
    ## A single-use X25519 private scalar (x25519-dalek's `EphemeralSecret`,
    ## in this module's own vocabulary). Where `X25519StaticSecret` is
    ## deliberately copyable (an identity you keep using), this type is
    ## deliberately MOVE-ONLY (`=copy` is a compile error, the same
    ## `Keypair` pattern) so that `x25519`'s `sink` parameter can enforce
    ## single use at compile time: consuming an ephemeral in a DH exchange
    ## moves it out of the caller's variable, and any second consuming use
    ## (another `x25519` call, `wipe`, or a bare copy) is a compile error,
    ## not a convention. Falls under the move-only-single-use half of the
    ## move-only-vs-copyable policy documented on `X25519StaticSecret`'s
    ## doc comment (round-4 finding R9), the same guarantee `signing.Seed`
    ## carries for its own single-custody role. `x25519Base` is a separate,
    ## non-consuming borrow (see below) and does not count. Verified empirically against
    ## Nim 2.2.10/ORC's `injectdestructors` pass with checked-in negative
    ## fixtures (`tests/unit/fixtures/reject_ephemeral_reuse.nim`,
    ## `reject_ephemeral_copy.nim`) -- see `tests/unit/test_x25519.nim`'s
    ## subprocess-driven compile tests, same methodology as
    ## `signing.Keypair`'s `reject_keypair_copy.nim`.
    ##
    ## **Prefer `x25519EphemeralPair()`** (RFC-002 slice 1) over calling
    ## `x25519EphemeralSecret()` and `x25519Base(eph)` separately: deriving
    ## the public value inside the constructor means the caller's secret
    ## binding is referenced exactly once (the consuming `x25519` call), so
    ## the natural flow compiles without the `move()` ceremony described
    ## below. `x25519EphemeralSecret()`/`x25519Base(eph)` remain available
    ## for flows that genuinely need the two steps separated.
    ##
    ## Two deliberate ABSENCES, not omissions -- each is exactly what makes
    ## this type "ephemeral" rather than a second spelling of
    ## `X25519StaticSecret`:
    ## - **No `toX25519EphemeralSecret(bytes)` constructor.** The only way
    ##   to get one is `x25519EphemeralSecret()`, fresh from the OS CSPRNG.
    ##   Freshness is a constructor guarantee, not a caller convention --
    ##   there is no way to resurrect or replay a previous ephemeral value.
    ## - **No `toBytes(X25519EphemeralSecret)`.** An ephemeral secret that
    ##   can be exported to bytes could be persisted, defeating the entire
    ##   point (a value meant to be used once and discarded). Both absences
    ##   are pinned as regression tests in `test_facade.nim` (`not
    ##   compiles(...)` -- these two ARE visible to the ordinary compile-time
    ##   checker, unlike the move-only enforcement above).
    ##
    ## One-field object, not `distinct array[32, byte]`, for the same
    ## empirically-established reason as `X25519StaticSecret`/`Seed` (see
    ## their doc comments): a bare `distinct array` local's `=destroy` never
    ## fires under ORC on Nim 2.2.10.
    bytes: array[32, byte]

## Type hooks must be declared immediately after the type they attach to,
## before anything else touches the type by value -- see signing.nim's
## module doc comment for why (Nim may otherwise synthesize a default
## hook first and reject an explicit one declared later). The
## `secretHooks*`/`secretHooksMoveOnly*` templates below (round-3 finding
## A5, `sello/private/secret_hooks`) expand to exactly the hand-written
## `=destroy`/`=copy` shape this comment used to introduce directly for all
## three types here -- see that module's doc comment for the full "why a
## template, why `{.dirty.}`" writeup, including round-4 finding R10's
## simplification to a two-argument `(Type, field)` signature (no more
## per-type `zeroizeProc` name).

## Copyable (no `=copy` restriction, unlike the ephemeral secret below):
## every copy self-wipes independently at its own scope exit.
secretHooks(X25519StaticSecret, bytes)

## Copyable, same reasoning as `X25519StaticSecret` above.
secretHooks(X25519Shared, bytes)

## Move-only, the `Keypair`/RFC-001 slice 5 pattern: a second live copy of
## a single-use secret is a compile error, not a hygiene footnote.
## Legitimate transfers move (`x25519`'s `sink` parameter below).
secretHooksMoveOnly(X25519EphemeralSecret, bytes)

func toX25519StaticSecret*(bytes: array[32, byte]): X25519StaticSecret {.inline.} =
  ## Explicit construction from raw bytes (e.g. straight out of a CSPRNG,
  ## or persisted/loaded material) -- the point where bytes become a
  ## secret. For a fresh secret sourced from the OS CSPRNG directly, use
  ## `x25519StaticSecret()` instead.
  X25519StaticSecret(bytes: bytes)

proc x25519StaticSecret*(): X25519StaticSecret {.raises: [OSError].} =
  ## Fresh secret via `std/sysrand`, filling the object's bytes IN PLACE
  ## (the `signing.keypair()` lesson: never a bare unwiped local that gets
  ## wrapped afterward). Raises `OSError` if the OS CSPRNG call fails --
  ## fail fast on a broken source of randomness, the same policy
  ## `signing.keypair()` follows.
  if not urandom(result.bytes):
    raise newException(OSError, "sello.x25519StaticSecret: sysrand.urandom failed")

func toBytes*(s: X25519StaticSecret): array[32, byte] {.inline.} =
  ## Deliberate export for persistence/interop. The returned copy is
  ## caller-owned and NOT wiped by this call -- wipe it yourself (e.g.
  ## `sello/wipe.wipe`) once you are done with it.
  s.bytes

proc x25519EphemeralSecret*(): X25519EphemeralSecret {.raises: [OSError].} =
  ## The ONLY constructor -- deliberately no `toX25519EphemeralSecret(bytes)`
  ## counterpart (see the type's doc comment: freshness-by-construction is
  ## the whole point). Same `std/sysrand`-in-place-fill / `OSError`-on-
  ## failure contract as `x25519StaticSecret()`/`signing.keypair()`.
  if not urandom(result.bytes):
    raise newException(OSError, "sello.x25519EphemeralSecret: sysrand.urandom failed")

func toX25519Public*(bytes: array[32, byte]): X25519Public {.inline.} =
  ## Explicit construction from raw bytes (e.g. a peer's public value
  ## received over the wire).
  X25519Public(bytes)

func toBytes*(p: X25519Public): array[32, byte] {.inline.} =
  ## Raw bytes back out, e.g. for serialization.
  array[32, byte](p)

func `==`*(a, b: X25519Public): bool {.borrow.}
  ## Comparing two PUBLIC values carries no constant-time requirement --
  ## same reasoning as `PublicKey`/`Signature` (`sello/wire`).
func `$`*(p: X25519Public): string {.borrow.}

func hash*(p: X25519Public): Hash {.inline.} =
  ## Hash of the underlying bytes (RFC-002 slice 1) -- unblocks
  ## Table/HashSet keying. No constant-time requirement, same reasoning
  ## as `==` above.
  hash(array[32, byte](p))

func toBytes*(sh: X25519Shared): array[32, byte] {.inline.} =
  ## Raw DH output. Feed it to a KDF -- never use it directly as a key.
  ## The returned copy is caller-owned and NOT wiped by this call -- wipe
  ## it yourself (e.g. `sello/wipe.wipe`) once you are done with it.
  sh.bytes

const
  X25519BasePoint*: X25519Public = X25519Public([
    9'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
  ])

{.push checks: off.}

func ladder(k: array[32, byte]; u: array[32, byte]): array[32, byte] =
  ## RFC 7748 §5: X25519(k, u) with scalar clamping. The u input's top
  ## bit is masked by feFromBytes, as the RFC requires.
  var e = k
  clampScalar(e)

  let x1 = feFromBytes(u)
  var x2 = FeOne
  var z2 = FeZero
  var x3 = x1
  var z3 = FeOne
  var swap = false

  # Per-iteration temporaries hoisted out of the loop below (round-3
  # finding A1): each iteration fully overwrites every field via
  # feAdd/feSub/feMul before it is ever read, so hoisting the declaration
  # changes no computed value -- it exists so the secret-derived
  # intermediate state the FINAL iteration leaves in these stack slots can
  # be wiped once, below, alongside x2/z2/x3/z3/zInv, instead of going out
  # of scope 255 times with no wipe at all (the gap this finding closes:
  # `backend.nim`'s secrets never had this gap, since its secrets are all
  # declared once at function scope already).
  var a, aa, b, bb, ee, c, d, da, cb, t: Fe
  var zInv: Fe

  # `try`/`finally` (defensive, currently unreachable: every operation in
  # the loop and tail below is fixed-size-array field arithmetic under
  # `checks: off`, with no raising op reachable) -- same net
  # `private/backend.nim`'s secret-holding functions use, so an unwind
  # between a secret's creation and its explicit wipe below cannot leave
  # it live in this stack frame.
  try:
    for pos in countdown(254, 0):
      let bit = ((e[pos shr 3] shr (pos and 7)) and 1) != 0
      swap = swap xor bit
      feCSwap(x2, x3, swap)
      feCSwap(z2, z3, swap)
      swap = bit

      # One ladder step (RFC 7748 §5 pseudocode). Uses the identity
      # AA + 121665*E == BB + 121666*E to reuse feMul121666.
      feAdd(a, x2, z2)          # A  = x2 + z2
      feSq(aa, a)               # AA = A^2
      feSub(b, x2, z2)          # B  = x2 - z2
      feSq(bb, b)               # BB = B^2
      feSub(ee, aa, bb)         # E  = AA - BB
      feAdd(c, x3, z3)          # C  = x3 + z3
      feSub(d, x3, z3)          # D  = x3 - z3
      feMul(da, d, a)           # DA = D*A
      feMul(cb, c, b)           # CB = C*B
      feAdd(t, da, cb)
      feSq(x3, t)               # x3 = (DA + CB)^2
      feSub(t, da, cb)
      feSq(t, t)
      feMul(z3, x1, t)          # z3 = x1 * (DA - CB)^2
      feMul(x2, aa, bb)         # x2 = AA * BB
      feMul121666(t, ee)
      feAdd(t, bb, t)           # BB + 121666*E
      feMul(z2, ee, t)          # z2 = E * (BB + 121666*E)

    feCSwap(x2, x3, swap)
    feCSwap(z2, z3, swap)

    feInvert(zInv, z2)
    feMul(x2, x2, zInv)
    result = feToBytes(x2)

    # RFC-001 slice 8: this was previously a plain `for i in 0 ..< 32:
    # e[i] = 0` loop -- confirmed by disassembly at -d:release to be an
    # unbarriered dead store, entirely absent from the emitted machine code,
    # because nothing reads `e` again after this point. `ct.wipe` survives
    # (re-verified by disassembly after this fix): volatile per-byte stores
    # plus the memory barrier compile to literal store instructions.
    #
    # Round-3 finding A1 extends this from `e` alone (the clamped scalar
    # copy) to every OTHER secret-derived accumulator/temporary the ladder
    # touches -- `x2`/`z2`/`x3`/`z3`/`zInv` and the per-iteration
    # temporaries hoisted above -- bringing this module to the same "wipe
    # every secret intermediate, not just the input" discipline
    # `private/backend.nim` already carries. `x1` (derived from `u`, the
    # PUBLIC peer/base coordinate) and `result` (the caller's own return
    # value, which the `x25519`/`x25519Base` callers below wipe or hand
    # back per their own contracts) are deliberately NOT wiped here.
    ct.wipe(e)
    ct.wipe(x2); ct.wipe(z2); ct.wipe(x3); ct.wipe(z3)
    ct.wipe(a); ct.wipe(aa); ct.wipe(b); ct.wipe(bb); ct.wipe(ee)
    ct.wipe(c); ct.wipe(d); ct.wipe(da); ct.wipe(cb); ct.wipe(t)
    ct.wipe(zInv)
  finally:
    ct.wipe(e)
    ct.wipe(x2); ct.wipe(z2); ct.wipe(x3); ct.wipe(z3)
    ct.wipe(a); ct.wipe(aa); ct.wipe(b); ct.wipe(bb); ct.wipe(ee)
    ct.wipe(c); ct.wipe(d); ct.wipe(da); ct.wipe(cb); ct.wipe(t)
    ct.wipe(zInv)

{.pop.}

func x25519Base*(secret: X25519StaticSecret): X25519Public =
  ## Public key derivation: X25519(secret, 9). Never all-zero for a
  ## clamped scalar, so no Option.
  toX25519Public(ladder(secret.bytes, toBytes(X25519BasePoint)))

func x25519Base*(secret: X25519EphemeralSecret): X25519Public =
  ## Public key derivation for an ephemeral secret. Deliberately
  ## NON-consuming: a plain by-value `X25519EphemeralSecret` parameter is a
  ## borrow when this is not the argument's last use (the `Keypair`
  ## by-value precedent, verified empirically on Nim 2.2.10/ORC -- see
  ## RFC-001's "Key decisions" log), so deriving and sending your public
  ## key ahead of the DH exchange itself compiles and does not consume the
  ## secret -- only `x25519`'s `sink` parameter (below) does that. See
  ## `x25519EphemeralPair()` below for the primary flow, which needs
  ## neither this nor `move()`.
  toX25519Public(ladder(secret.bytes, toBytes(X25519BasePoint)))

proc x25519StaticPair*(): tuple[secret: X25519StaticSecret, public: X25519Public] {.raises: [OSError].} =
  ## Fresh static secret plus its derived public value, in one call
  ## (RFC-003 slice 1 item 5) -- mirrors `x25519EphemeralPair`'s shape and
  ## doc register. The static role is the one X25519 role where
  ## `Keypair`'s rationale (no repeated derivation, no
  ## compiler-unenforced secret/public drift) actually applies: an X25519
  ## operation takes only the secret -- the public half is sent once, not
  ## consulted per-op -- so this bundled constructor captures the whole
  ## benefit without a new nominal type. A full `Keypair`-style invariant
  ## object was considered and declined for exactly that reason (see this
  ## module's header doc comment): there is no per-operation invariant for
  ## a wrapper type to protect the way `Keypair` protects
  ## public-derived-from-this-secret on every `sign` call.
  ##
  ## Unlike `x25519EphemeralPair`, this buys no compile-time ceremony
  ## relief -- `X25519StaticSecret` is already copyable with no
  ## single-use/move rules to work around. It exists purely so the common
  ## case ("I want a reusable identity and its public value together")
  ## needs one call instead of two, the same ergonomic win
  ## `x25519EphemeralPair` gives the ephemeral role. The from-bytes reload
  ## path for an EXISTING secret stays `toX25519StaticSecret` + one
  ## `x25519Base` call, unchanged: one ladder at load time is not a
  ## repeated-derivation cost worth a second constructor.
  if not urandom(result.secret.bytes):
    raise newException(OSError, "sello.x25519StaticPair: sysrand.urandom failed")
  result.public = toX25519Public(ladder(result.secret.bytes, toBytes(X25519BasePoint)))

proc x25519EphemeralPair*(): tuple[secret: X25519EphemeralSecret, public: X25519Public] {.raises: [OSError].} =
  ## Fresh ephemeral secret plus its derived public value, in one call
  ## (RFC-002 slice 1) -- the primary way to get an ephemeral secret.
  ## Deriving the public value INSIDE this constructor, rather than
  ## requiring a separate `x25519Base(eph)` call, means the caller's
  ## `secret` binding is referenced exactly once: the consuming `x25519`
  ## call. That is what lets the natural
  ## `let (eph, pub) = x25519EphemeralPair(); ...; x25519(eph, peer)` flow
  ## compile WITHOUT `move()` -- ordinary last-use inference already
  ## covers it, unlike `x25519EphemeralSecret()` followed by a separate
  ## `x25519Base(eph)` call, which leaves an earlier reference to `eph`
  ## and forces the `move()` ceremony documented on
  ## `x25519(sink X25519EphemeralSecret, ...)` below. `x25519EphemeralSecret()`
  ## plus `x25519Base(eph)` remain available for flows that genuinely need
  ## the two steps separated (e.g. sending the public key well before the
  ## exchange completes).
  if not urandom(result.secret.bytes):
    raise newException(OSError, "sello.x25519EphemeralPair: sysrand.urandom failed")
  result.public = toX25519Public(ladder(result.secret.bytes, toBytes(X25519BasePoint)))

func x25519*(secret: X25519StaticSecret; peer: X25519Public): Option[X25519Shared] =
  ## Shared-secret computation: X25519(secret, peer). Returns none if the
  ## result is all zero -- the peer supplied a small-order point, and the
  ## "shared secret" would be attacker-known (RFC 7748 §6.1 zero-output
  ## check). Callers need no further checks.
  ##
  ## **Why `Option`, not `bool` (round-3 finding A8; contrast
  ## `ed25519.verify`'s plain `bool`):** `verify` is a TOTAL PREDICATE over
  ## public data -- every input has a well-defined true/false answer, so a
  ## `bool` return loses nothing. `x25519` is a PARTIAL FUNCTION: for a
  ## small-order peer point there is no well-defined shared secret to
  ## return at all (the RFC 7748 §6.1 zero-output case), so a `bool` would
  ## have nowhere to put the "yes, and here it is" payload for the success
  ## case, and returning an all-zero `X25519Shared` on failure would hand
  ## callers a value indistinguishable from a genuine (if degenerate)
  ## shared secret. `Option[X25519Shared]` makes the partiality explicit in
  ## the type instead of relying on a sentinel value or a doc comment.
  ##
  ## `s`, the raw ladder output, is secret-derived even on the `none` path
  ## (the peer's small-order point is public, but `s` is still this
  ## caller's own DH output before the zero-check inspects it) -- wiped via
  ## `ct.wipe` (RFC-001 slice 8's one audited primitive, round-3 finding
  ## A1) on BOTH branches below, once its bytes are copied into the `some`
  ## branch's `X25519Shared` (the copy already happened by then, so the
  ## wipe cannot affect the returned value). `try`/`finally` (defensive,
  ## currently unreachable: neither the `or`-accumulation loop nor the
  ## record-construction copy below can raise) so the wipe fires regardless
  ## of which branch runs -- the same net `backend.nim`'s secret-holding
  ## functions use.
  var s = ladder(secret.bytes, array[32, byte](peer))
  var acc: byte = 0
  for b in s: acc = acc or b
  try:
    if acc == 0:
      result = none[X25519Shared]()
    else:
      result = some(X25519Shared(bytes: s))
  finally:
    ct.wipe(s)

func x25519*(secret: sink X25519EphemeralSecret; peer: X25519Public): Option[X25519Shared] =
  ## Shared-secret computation that CONSUMES the ephemeral secret: `sink`
  ## plus `X25519EphemeralSecret`'s move-only `=copy {.error.}` together
  ## make reuse a compile error rather than a documented caller obligation
  ## -- see the type's doc comment and the negative-compile fixtures
  ## (`tests/unit/fixtures/reject_ephemeral_reuse.nim`,
  ## `reject_ephemeral_copy.nim`) that pin this down empirically. `secret`
  ## is a local owned by this proc for the duration of the call and is
  ## wiped by its own `=destroy` when it goes out of scope at return --
  ## the same automatic-wipe guarantee every other secret-holding type in
  ## this codebase carries, here additionally enforced as single-use.
  ## Same zero-output small-order-peer check as the `X25519StaticSecret`
  ## overload above.
  ##
  ## `x25519EphemeralPair()` sidesteps the whole `move()` ceremony below
  ## for the primary flow, by deriving the public value inside the
  ## constructor instead of via a separate `x25519Base(eph)` call -- read
  ## on for why that ceremony exists at all, needed only for callers using
  ## `x25519EphemeralSecret()`/`x25519Base(eph)` directly.
  ##
  ## **Empirical Nim ownership finding (verified against Nim 2.2.10/ORC
  ## with isolated scratch probes, not assumed):** if `x25519Base` (or ANY
  ## other reference at all -- a bare field read and a raw `addr` both
  ## reproduce it) touched the same `X25519EphemeralSecret` variable
  ## earlier in the same scope, calling `x25519(secret, peer)` bare fails
  ## to compile with `'=dup' is not available ...; requires a copy because
  ## it's not the last read of 'secret'` -- Nim's sink-argument "is this
  ## the last read" inference is a simple per-symbol occurrence count over
  ## the whole scope, not a true escape/alias analysis, so it cannot see
  ## that an earlier read-only borrow leaves no live alias behind. The
  ## caller must wrap the argument in `system.move` (`x25519(move(secret),
  ## peer)`, which requires `secret` be declared `var`, not `let`, since
  ## `move` takes a `var T`) to explicitly assert the move is safe. A
  ## secret with NO earlier reference at all (pure single-use) needs no
  ## `move()` -- ordinary last-use inference already covers it, exactly as
  ## in `reject_ephemeral_reuse.nim`'s legitimate first call.
  ##
  ## **Honest residual gap, inherent to Nim's ownership model, not
  ## something this design can close:** `move()` is an explicit override
  ## of the compiler's static analysis, so a caller who writes
  ## `move(secret)` at TWO separate consuming call sites for the same
  ## variable (instead of the natural, unadorned `x25519(secret, peer)`
  ## reuse pattern the negative fixtures cover) would compile -- the
  ## second call would silently run on the wiped-to-zero, moved-from
  ## bytes rather than being rejected. The ORDINARY reuse pattern (no
  ## explicit `move()` anywhere) IS correctly rejected at compile time --
  ## verified by `reject_ephemeral_reuse.nim` -- and that is the shape
  ## every legitimate call site in this codebase's own tests and this
  ## proc's own doc example use. `move()` is Nim's own standard idiom for
  ## "I assert this is safe," the same escape hatch every Nim ARC/ORC
  ## move-only type shares; it is not a sello-specific hole.
  ##
  ## `s` (the raw ladder output) is wiped via `ct.wipe` on both branches,
  ## same as the `X25519StaticSecret` overload above -- see that overload's
  ## doc comment for the `Option`-vs-`bool` rationale (round-3 finding A8)
  ## and the try/finally wipe rationale (round-3 finding A1), not repeated
  ## here.
  var s = ladder(secret.bytes, array[32, byte](peer))
  var acc: byte = 0
  for b in s: acc = acc or b
  try:
    if acc == 0:
      result = none[X25519Shared]()
    else:
      result = some(X25519Shared(bytes: s))
  finally:
    ct.wipe(s)

# ---------------------------------------------------------------------------
# Public wipe
#
# `sello.wipe` was previously `Seed`-only (signing.nim): the one audited
# wipe primitive, `private/ct.wipe`, was reachable only by importing a
# `private/` module directly -- officially unsupported, and exactly the
# kind of gap that pushes a caller toward a hand-rolled scrub loop the
# compiler is free to delete as a dead store (the precise bug class
# RFC-001 slice 8 fixed internally; see `private/ct.nim`'s module doc
# comment). The generic `array[32, byte]` overload lives in `sello/wipe`
# (any 32-byte secret shape); the overloads below are specific to this
# module's own secret-holding types.
# ---------------------------------------------------------------------------

proc wipe*(s: var X25519StaticSecret) =
  ## Explicit early wipe, e.g. right after deriving a public key or a
  ## shared secret when the caller does not need to retain the raw
  ## secret. `=destroy` performs the same wipe automatically at scope
  ## exit; this exists for callers that want it sooner.
  ##
  ## Calls `ct.wipe` directly (round-4 finding R10), not a named
  ## `zeroize<Type>` proc -- see `private/secret_hooks.nim`'s doc comment.
  ct.wipe(s.bytes)

proc wipe*(sh: var X25519Shared) =
  ## Explicit early wipe of a DH output, e.g. right after feeding it to a
  ## KDF. `=destroy` performs the same wipe automatically at scope exit;
  ## this exists for callers that want it sooner.
  ct.wipe(sh.bytes)

proc wipe*(s: sink X25519EphemeralSecret) =
  ## Early disposal of an ephemeral secret that was generated but never
  ## consumed by `x25519` (e.g. the caller decided not to complete the
  ## exchange). `=destroy` performs the same wipe automatically at scope
  ## exit; this exists for callers that want it sooner.
  ##
  ## Takes `sink`, not `var` (round-4 finding R4): this type's whole design
  ## point is compiler-enforced single use, and a `var` `wipe` does not
  ## consume its argument, so a caller could write `wipe(eph)` and then
  ## still reach a consuming `x25519(move(eph), peer)` -- which compiled
  ## and ran the ladder on the just-zeroed bytes, silently defeating the
  ## single-use guarantee (`clampScalar` on an all-zero array is the fixed
  ## public scalar 2^254, neither zero nor small-order, so the ladder's own
  ## small-order check does not catch it either). With `sink`, `wipe`
  ## consumes `s` exactly like `x25519` does, so a later use of the same
  ## variable -- moved or not -- is the same `=copy {.error.}` compile
  ## error `x25519`'s own reuse already produces; see
  ## `tests/unit/fixtures/reject_ephemeral_wipe_then_use.nim`, driven by
  ## `test_x25519.nim`, for the regression pin. The type's single ownership
  ## moves to whichever consumes it first, `wipe` or `x25519`, same as
  ## before -- only the enforcement mechanism changed.
  ##
  ## Calls `ct.wipe` directly (round-4 finding R10), not a named
  ## `zeroize<Type>` proc -- see `private/secret_hooks.nim`'s doc comment.
  ct.wipe(s.bytes)

{.pop.}
