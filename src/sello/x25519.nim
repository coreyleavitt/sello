## X25519 — Diffie-Hellman key exchange over Curve25519 (RFC 7748 §5)
##
## Montgomery ladder over the u-coordinate only; reuses the GF(2^255-19)
## core from sello/field. Ladder structure follows RFC 7748 / ref10
## scalarmult_curve25519 (public domain).
##
## The scalar is a SECRET (the caller's private key), so the ladder is
## branchless on secret data: bit selection and lane swaps use arithmetic
## masking (feCSwap), secrets live in fixed-size stack arrays, and Nim's
## runtime checks are disabled in the core. The remaining constant-time
## toolkit items (volatile wipe, dudect harness) are tracked with the
## ed25519 signing milestone.

import std/options
import sello/field

const
  X25519BasePoint*: array[32, byte] = [
    9'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
  ]

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

  # Best-effort scrub of the clamped secret copy.
  for i in 0 ..< 32: e[i] = 0

{.pop.}

func x25519*(secret: array[32, byte];
             peerPublic: array[32, byte]): Option[array[32, byte]] =
  ## Shared-secret computation: X25519(secret, peerPublic).
  ## Returns none if the result is all zero — the peer supplied a
  ## small-order point, and the "shared secret" would be attacker-known
  ## (RFC 7748 §6.1 zero-output check). Callers need no further checks.
  let s = ladder(secret, peerPublic)
  var acc: byte = 0
  for b in s: acc = acc or b
  if acc == 0:
    none[array[32, byte]]()
  else:
    some(s)

func x25519Base*(secret: array[32, byte]): array[32, byte] =
  ## Public key derivation: X25519(secret, 9). Never all-zero for a
  ## clamped scalar, so no Option.
  ladder(secret, X25519BasePoint)
