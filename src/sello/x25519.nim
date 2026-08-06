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
## checks are disabled in the core, and the clamped secret copy is wiped
## via `ct.wipe` (volatile stores + compiler barrier — RFC-001 slice 8)
## once the ladder is done with it. The remaining constant-time toolkit
## item (the dudect harness) is tracked with the ed25519 signing milestone.
##
## Public API types: three role-typed wrappers, one per X25519 role
## (RFC-001 ledger #29, revisited on Corey's direction; supersedes the
## single-`X25519Key` design B3 originally chose):
##
## - `X25519Secret` — a clamped private scalar. One-field object (not
##   `distinct array[32, byte]`) for the exact reason `signing.Seed` is:
##   Nim 2.2.10/ORC silently never fires `=destroy` on a bare `distinct
##   array` local, confirmed by inspecting the generated C — see
##   `signing.Seed`'s doc comment for the full writeup. `=destroy` wipes.
##   Deliberately copyable (like `Seed`, unlike `Keypair`): no `=copy`
##   override, every copy self-wipes independently at its own scope exit.
## - `X25519Public` — a public u-coordinate: `x25519Base`'s result, or a
##   peer's value off the wire. Plain `distinct array[32, byte]`, freely
##   copyable — not secret material, no destructor.
## - `X25519Shared` — a completed DH output. This IS secret material (feed
##   it to a KDF, never use it directly as a key), so it follows
##   `X25519Secret`'s exact shape: one-field object, copyable, wiped.
##
## Why three types instead of B3's one `X25519Key` covering all three
## roles: RFC 7748 does treat all three as the identical 32-byte wire
## format, and that reasoning still holds -- but role confusion between
## SECRET and SENDABLE material fails open under one type (nothing stopped
## a shared secret or a private scalar from being handed to code expecting
## a value safe to log/transmit), and encoding "same wire format" as "same
## type" was never required by the format itself. Splitting mirrors the
## `Seed`/`PublicKey` treatment already established on the ed25519 side of
## this library, in this module's own established vocabulary
## (`X25519Secret`/`X25519Public`/`X25519Shared`, not dalek's
## `EphemeralSecret`/`StaticSecret`/`PublicKey`/`SharedSecret`). What this
## design does NOT do, by explicit decision: a static/ephemeral secret
## split (x25519-dalek's consume-on-use `EphemeralSecret`, which makes
## `x25519` take the secret by value and never allows reuse). That is a
## genuinely different, larger API shape -- deferred, not built here.
##
## `toX25519Secret`/`toX25519Public`/`toBytes` are the named conversions
## to/from raw bytes (symmetry with `sello/types`'s `toPublicKey`/
## `toSignature` and `signing.toSeed`); `x25519Secret()` generates a fresh
## secret from `std/sysrand`. `wipe` (`X25519Secret`- and
## `X25519Shared`-typed here; the generic `array[32, byte]` overload lives
## in `sello/types`) is the public, audited route to `private/ct.wipe` for
## X25519 secret material a caller holds directly, alongside the automatic
## `=destroy` wipe both secret-holding types already carry.

import std/[options, sysrand]
import sello/field
import sello/private/ct

type
  X25519Public* = distinct array[32, byte]
    ## A public u-coordinate (RFC 7748 §5): the result of `x25519Base`, or
    ## a peer's public value received over the wire. Freely copyable --
    ## this is not secret material.

  X25519Secret* = object
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
    bytes: array[32, byte]

  X25519Shared* = object
    ## The output of a completed Diffie-Hellman exchange (`x25519`). This
    ## IS secret material -- feed it to a KDF, never use it directly as a
    ## key -- so it follows `X25519Secret`'s exact shape: one-field object,
    ## copyable, `=destroy`-wiped.
    bytes: array[32, byte]

## Type hooks must be declared immediately after the type they attach to,
## before anything else touches the type by value -- see signing.nim's
## module doc comment for why (Nim may otherwise synthesize a default
## hook first and reject an explicit one declared later).

func zeroizeX25519Secret(s: var X25519Secret) {.inline.} =
  ct.wipe(s.bytes)

proc `=destroy`(s: var X25519Secret) =
  zeroizeX25519Secret(s)

func zeroizeX25519Shared(s: var X25519Shared) {.inline.} =
  ct.wipe(s.bytes)

proc `=destroy`(s: var X25519Shared) =
  zeroizeX25519Shared(s)

func toX25519Secret*(bytes: array[32, byte]): X25519Secret {.inline.} =
  ## Explicit construction from raw bytes (e.g. straight out of a CSPRNG,
  ## or persisted/loaded material) -- the point where bytes become a
  ## secret. For a fresh secret sourced from the OS CSPRNG directly, use
  ## `x25519Secret()` instead.
  X25519Secret(bytes: bytes)

proc x25519Secret*(): X25519Secret =
  ## Fresh secret via `std/sysrand`, filling the object's bytes IN PLACE
  ## (the `signing.keypair()` lesson: never a bare unwiped local that gets
  ## wrapped afterward). Raises `OSError` if the OS CSPRNG call fails --
  ## fail fast on a broken source of randomness, the same policy
  ## `signing.keypair()` follows.
  if not urandom(result.bytes):
    raise newException(OSError, "sello.x25519Secret: sysrand.urandom failed")

func toBytes*(s: X25519Secret): array[32, byte] {.inline.} =
  ## Deliberate export for persistence/interop. The returned copy is
  ## caller-owned and NOT wiped by this call -- wipe it yourself (e.g.
  ## `sello/types.wipe`) once you are done with it.
  s.bytes

func toX25519Public*(bytes: array[32, byte]): X25519Public {.inline.} =
  ## Explicit construction from raw bytes (e.g. a peer's public value
  ## received over the wire).
  X25519Public(bytes)

func toBytes*(p: X25519Public): array[32, byte] {.inline.} =
  ## Raw bytes back out, e.g. for serialization.
  array[32, byte](p)

func `==`*(a, b: X25519Public): bool {.borrow.}
  ## Comparing two PUBLIC values carries no constant-time requirement --
  ## same reasoning as `PublicKey`/`Signature` (`sello/types`).
func `$`*(p: X25519Public): string {.borrow.}

func toBytes*(sh: X25519Shared): array[32, byte] {.inline.} =
  ## Raw DH output. Feed it to a KDF -- never use it directly as a key.
  ## The returned copy is caller-owned and NOT wiped by this call -- wipe
  ## it yourself (e.g. `sello/types.wipe`) once you are done with it.
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

  for pos in countdown(254, 0):
    let bit = ((e[pos shr 3] shr (pos and 7)) and 1) != 0
    swap = swap xor bit
    feCSwap(x2, x3, swap)
    feCSwap(z2, z3, swap)
    swap = bit

    # One ladder step (RFC 7748 §5 pseudocode). Uses the identity
    # AA + 121665*E == BB + 121666*E to reuse feMul121666.
    var a, aa, b, bb, ee, c, d, da, cb, t: Fe
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

  var zInv: Fe
  feInvert(zInv, z2)
  feMul(x2, x2, zInv)
  result = feToBytes(x2)

  # RFC-001 slice 8: this was previously a plain `for i in 0 ..< 32:
  # e[i] = 0` loop -- confirmed by disassembly at -d:release to be an
  # unbarriered dead store, entirely absent from the emitted machine code,
  # because nothing reads `e` again after this point. `ct.wipe` survives
  # (re-verified by disassembly after this fix): volatile per-byte stores
  # plus the memory barrier compile to literal store instructions.
  ct.wipe(e)

{.pop.}

func x25519Base*(secret: X25519Secret): X25519Public =
  ## Public key derivation: X25519(secret, 9). Never all-zero for a
  ## clamped scalar, so no Option.
  toX25519Public(ladder(secret.bytes, toBytes(X25519BasePoint)))

func x25519*(secret: X25519Secret; peer: X25519Public): Option[X25519Shared] =
  ## Shared-secret computation: X25519(secret, peer). Returns none if the
  ## result is all zero -- the peer supplied a small-order point, and the
  ## "shared secret" would be attacker-known (RFC 7748 §6.1 zero-output
  ## check). Callers need no further checks.
  let s = ladder(secret.bytes, array[32, byte](peer))
  var acc: byte = 0
  for b in s: acc = acc or b
  if acc == 0:
    none[X25519Shared]()
  else:
    some(X25519Shared(bytes: s))

# ---------------------------------------------------------------------------
# Public wipe
#
# `sello.wipe` was previously `Seed`-only (signing.nim): the one audited
# wipe primitive, `private/ct.wipe`, was reachable only by importing a
# `private/` module directly -- officially unsupported, and exactly the
# kind of gap that pushes a caller toward a hand-rolled scrub loop the
# compiler is free to delete as a dead store (the precise bug class
# RFC-001 slice 8 fixed internally; see `private/ct.nim`'s module doc
# comment). The generic `array[32, byte]` overload lives in `sello/types`
# (any 32-byte secret shape); the two overloads below are specific to this
# module's own secret-holding types.
# ---------------------------------------------------------------------------

proc wipe*(s: var X25519Secret) =
  ## Explicit early wipe, e.g. right after deriving a public key or a
  ## shared secret when the caller does not need to retain the raw
  ## secret. `=destroy` performs the same wipe automatically at scope
  ## exit; this exists for callers that want it sooner.
  zeroizeX25519Secret(s)

proc wipe*(sh: var X25519Shared) =
  ## Explicit early wipe of a DH output, e.g. right after feeding it to a
  ## KDF. `=destroy` performs the same wipe automatically at scope exit;
  ## this exists for callers that want it sooner.
  zeroizeX25519Shared(sh)
