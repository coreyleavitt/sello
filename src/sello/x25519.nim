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
## Public API types (RFC-001 findings 9/11/26): `X25519Key` is a nominal
## `distinct array[32, byte]` wrapper covering all three X25519 roles
## (secret scalar, public u-coordinate, shared secret) -- see its doc
## comment (below) for why those three are deliberately NOT split into
## separate types. `toX25519Key`/`toBytes` are the named conversions to/
## from raw bytes, for symmetry with `sello/types`'s `toPublicKey`/
## `toSignature` and `signing.toSeed` (round-2 finding 26). `wipe`
## (`X25519Key`-typed here; the generic `array[32, byte]` overload lives
## in `sello/types`, round-2 finding 28) is the public, audited route to
## `private/ct.wipe` for X25519 secret material a caller holds outside
## this module -- before finding 11, `sello.wipe` only covered `Seed`
## (signing.nim), and the private primitive was reachable only by
## importing a `private/` module directly.

import std/options
import sello/field
import sello/private/ct

type
  X25519Key* = distinct array[32, byte]
    ## A 32-byte X25519 wire value (RFC 7748 §5): a clamped secret scalar,
    ## a public u-coordinate, or a shared secret — RFC 7748 itself treats
    ## all three as the same 32-byte encoding (`X25519(k, u) -> u`), and a
    ## Diffie-Hellman shared secret is, by construction, exactly the same
    ## shape as a public key. RFC-001 finding 9 considered splitting this
    ## into separate `Secret`/`PublicKey`/`SharedSecret` distinct types
    ## (mirroring ed25519's `PublicKey`/`Signature` split) and deliberately
    ## did NOT: ed25519's split works because a compressed point and a
    ## detached signature are genuinely different wire formats (32 vs. 64
    ## bytes, different decode rules) representing different protocol
    ## roles, but X25519's three roles are the identical 32-byte format by
    ## the algorithm's own design — inventing three distinct types here
    ## would add ceremony without encoding a real distinction, and would
    ## still not stop e.g. `x25519(secret, secret)` (same role, wrong
    ## argument) the way it stops `verify(sig, msg, x25519Key)` (wrong
    ## role entirely).
    ##
    ## What this type DOES close, at zero ergonomics cost: the exact
    ## cross-algorithm mixup finding 9 names as its motivating example.
    ## Before this type existed, X25519 keys were bare `array[32, byte]`
    ## and `ed25519.PublicKey` was a plain alias for the same shape, so
    ## `verify(sig, msg, x25519Key)` compiled silently. Now that both
    ## `ed25519.PublicKey` and `X25519Key` are independently-defined
    ## `distinct` types, neither converts to the other (nor to a bare
    ## array) without an explicit cast, so that misuse is a compile error
    ## in both directions.
    ##
    ## No `=destroy`/wipe hook, same reasoning as `ed25519.PublicKey`/
    ## `Signature` (see `sello/types`'s doc comment): unlike `Signature`
    ## the value MAY be secret (a clamped scalar, a shared secret), but
    ## unlike `Seed` this type has no fixed field layout to attach a
    ## destructor to that would need to differ from a plain array's —
    ## wiping is opt-in via the `wipe` procs below (finding 11), called
    ## explicitly by a caller who is done with a given value, exactly
    ## because (unlike `Seed`) a `X25519Key` is not always secret and this
    ## module cannot tell which role a given value is playing.

func `==`*(a, b: X25519Key): bool {.borrow.}
  ## Comparing two X25519 values (public keys, or a shared secret against
  ## another shared secret in a test) is not itself a secret-dependent
  ## branch requiring CT treatment here -- same reasoning as
  ## `ed25519.PublicKey`/`Signature`'s borrowed `==` (see `sello/types`'s
  ## doc comment). Callers comparing a live secret scalar against
  ## attacker-controlled input on a security-relevant path should not
  ## reach for this; nothing in sello's own API does.
func `$`*(k: X25519Key): string {.borrow.}

func toX25519Key*(bytes: array[32, byte]): X25519Key {.inline.} =
  ## Explicit construction from raw bytes (e.g. a decoded wire value) --
  ## for symmetry with `toPublicKey`/`toSignature` (`sello/types`, RFC-001
  ## finding 9) and `toSeed` (`signing.nim`), and for the same
  ## grep-discoverability reason those converters exist: searching for
  ## "toX25519Key" finds every place a caller turns raw bytes into this
  ## type. The free `X25519Key(bytes)` cast every distinct type gets works
  ## identically -- this wrapper exists so the construction site is
  ## greppable by name, not because the cast needs help to compile
  ## (RFC-001 finding 26).
  X25519Key(bytes)

func toBytes*(key: X25519Key): array[32, byte] {.inline.} =
  ## Raw bytes back out, e.g. for serialization or interop with another
  ## API's `array[32, byte]`-shaped X25519 surface (RFC-001 finding 26).
  array[32, byte](key)

const
  X25519BasePoint*: X25519Key = X25519Key([
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

func x25519*(secret: X25519Key; peerPublic: X25519Key): Option[X25519Key] =
  ## Shared-secret computation: X25519(secret, peerPublic).
  ## Returns none if the result is all zero — the peer supplied a
  ## small-order point, and the "shared secret" would be attacker-known
  ## (RFC 7748 §6.1 zero-output check). Callers need no further checks.
  let s = ladder(array[32, byte](secret), array[32, byte](peerPublic))
  var acc: byte = 0
  for b in s: acc = acc or b
  if acc == 0:
    none[X25519Key]()
  else:
    some(X25519Key(s))

func x25519Base*(secret: X25519Key): X25519Key =
  ## Public key derivation: X25519(secret, 9). Never all-zero for a
  ## clamped scalar, so no Option.
  X25519Key(ladder(array[32, byte](secret), array[32, byte](X25519BasePoint)))

# ---------------------------------------------------------------------------
# Public wipe (RFC-001 finding 11)
#
# `sello.wipe` was previously `Seed`-only (signing.nim): the one audited
# wipe primitive, `private/ct.wipe`, was reachable only by importing a
# `private/` module directly -- officially unsupported, and exactly the
# kind of gap that pushes a caller toward a hand-rolled scrub loop the
# compiler is free to delete as a dead store (the precise bug class
# RFC-001 slice 8 fixed internally; see `private/ct.nim`'s module doc
# comment). X25519 secrets (a caller's own scalar, a shared secret they
# are done with) had no supported way to opt into the same wipe.
#
# Round-2 finding 28: the generic `array[32, byte]` overload that used to
# sit beside this one moved to `sello/types` -- it wiped any 32-byte
# secret, not just X25519 material, so it had no more business living in
# this module than in `signing.nim`. Only the `X25519Key`-typed overload,
# which IS specific to this module's own type, stays here.
# ---------------------------------------------------------------------------

proc wipe*(key: var X25519Key) =
  ## Audited wipe (volatile stores + compiler barrier, see
  ## `private/ct.nim`) of key material already wrapped in `X25519Key`. For
  ## an X25519 secret already unwrapped into a raw `array[32, byte]` (e.g.
  ## for interop with another API), use `sello/types.wipe` instead -- the
  ## same audited primitive, generic over any 32-byte secret shape.
  ct.wipe(key)
