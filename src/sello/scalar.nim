## Curve25519 group operations and scalar multiplication
##
## Extended homogeneous coordinates (X:Y:Z:T) with T = X*Y/Z.
##
## Addition formulas from Hisil-Wong-Carter-Dawson "Twisted Edwards Curves
## Revisited" (2008), as implemented in ref10 / TweetNaCl (public domain).

import nimcrypto/sha2
import sello/field

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

type
  GeP2* = object
    x*, y*, z*: Fe

  GeP3* = object
    x*, y*, z*, t*: Fe

  GeP1P1* = object
    x*, y*, z*, t*: Fe

  GeCached* = object
    yPlusX*, yMinusX*, z*, t2d*: Fe

# ---------------------------------------------------------------------------
# Curve constants (ref10)
# ---------------------------------------------------------------------------

const
  Ed25519D_Raw*: array[10, int32] = [
    -10913610'i32, 13857413, -15372611, 6949391, 114729,
    -8787816, -6275908, -3247719, -18696448, -12055116
  ]

  Ed25519Gx_Raw*: array[10, int32] = [
    -14297830'i32, -7645148, 16144683, -16471763, 27570974,
    -2696100, -26142465, 8378389, 20764389, 8758491
  ]

  Ed25519Gy_Raw*: array[10, int32] = [
    -26843541'i32, -6710886, 13421773, -13421773, 26843546,
    6710886, -13421773, 13421773, -26843546, -6710886
  ]

  SqrtM1_Raw*: array[10, int32] = [
    -32595792'i32, -7943725, 9377950, 3500415, 12389472,
    -272473, -25146209, -2005654, 326686, 11406482
  ]

# ---------------------------------------------------------------------------
# Conversions
# ---------------------------------------------------------------------------

func geP3ToCached*(r: var GeCached; p: GeP3) {.inline.} =
  feAdd(r.yPlusX, p.y, p.x)
  feSub(r.yMinusX, p.y, p.x)
  r.z = p.z
  var D: Fe
  D.limbs = Ed25519D_Raw
  var tD: Fe
  feMul(tD, p.t, D)
  feAdd(r.t2d, tD, tD)  # t2d = 2*d*T

func geP1P1ToP2*(r: var GeP2; p: GeP1P1) {.inline.} =
  feMul(r.x, p.x, p.t)
  feMul(r.y, p.y, p.z)
  feMul(r.z, p.z, p.t)

func geP1P1ToP3*(r: var GeP3; p: GeP1P1) {.inline.} =
  feMul(r.x, p.x, p.t)
  feMul(r.y, p.y, p.z)
  feMul(r.z, p.z, p.t)
  feMul(r.t, p.x, p.y)

func geP3ToP2*(r: var GeP2; p: GeP3) {.inline.} =
  r.x = p.x
  r.y = p.y
  r.z = p.z

# ---------------------------------------------------------------------------
# Group operations
# ---------------------------------------------------------------------------

func geP2Dbl*(r: var GeP1P1; p: GeP2) {.inline.} =
  ## Point doubling: 2*P  (input P2, output completed P1P1).
  ## Verbatim ref10 ge_p2_dbl (public domain). The P1P1 stores the four
  ## completed-point components; geP1P1ToP2/P3 forms the products. (a = -1.)
  var t0: Fe
  feSq(r.x, p.x)            # X^2
  feSq(r.z, p.y)            # Y^2
  feSq2(r.t, p.z)           # 2*Z^2
  feAdd(r.y, p.x, p.y)      # X+Y
  feSq(t0, r.y)             # (X+Y)^2
  feAdd(r.y, r.z, r.x)      # Y^2 + X^2
  feSub(r.z, r.z, r.x)      # Y^2 - X^2
  feSub(r.x, t0, r.y)       # (X+Y)^2 - (X^2+Y^2)
  feSub(r.t, r.t, r.z)      # 2*Z^2 - (Y^2-X^2)

func geAdd*(r: var GeP1P1; p: GeP3; q: GeCached) {.inline.} =
  ## Group addition: p + q  (p in P3, q in GeCached, result in completed P1P1).
  ## Verbatim ref10 ge_add (public domain).
  var A, B, C, D: Fe
  feAdd(A, p.y, p.x)        # Y+X
  feSub(B, p.y, p.x)        # Y-X
  feMul(A, A, q.yPlusX)     # (Y+X)(Yq+Xq)
  feMul(B, B, q.yMinusX)    # (Y-X)(Yq-Xq)
  feMul(C, q.t2d, p.t)      # 2d*Tq*T
  feMul(D, p.z, q.z)        # Z*Zq
  feAdd(D, D, D)            # 2*Z*Zq
  feSub(r.x, A, B)          # X = (Y+X)(Yq+Xq) - (Y-X)(Yq-Xq)
  feAdd(r.y, A, B)          # Y = (Y+X)(Yq+Xq) + (Y-X)(Yq-Xq)
  feAdd(r.z, D, C)          # Z = 2*Z*Zq + C
  feSub(r.t, D, C)          # T = 2*Z*Zq - C

func geSub*(r: var GeP1P1; p: GeP3; q: GeCached) {.inline.} =
  ## Group subtraction: p - q  (swaps Yq+Xq and Yq-Xq, and the Z/T signs).
  ## Verbatim ref10 ge_sub (public domain).
  var A, B, C, D: Fe
  feAdd(A, p.y, p.x)        # Y+X
  feSub(B, p.y, p.x)        # Y-X
  feMul(A, A, q.yMinusX)    # (Y+X)(Yq-Xq)
  feMul(B, B, q.yPlusX)     # (Y-X)(Yq+Xq)
  feMul(C, q.t2d, p.t)      # 2d*Tq*T
  feMul(D, p.z, q.z)        # Z*Zq
  feAdd(D, D, D)            # 2*Z*Zq
  feSub(r.x, A, B)          # X = (Y+X)(Yq-Xq) - (Y-X)(Yq+Xq)
  feAdd(r.y, A, B)          # Y = (Y+X)(Yq-Xq) + (Y-X)(Yq+Xq)
  feSub(r.z, D, C)          # Z = 2*Z*Zq - C
  feAdd(r.t, D, C)          # T = 2*Z*Zq + C

# ---------------------------------------------------------------------------
# Scalar multiplication: variable-base, unsigned 4-bit windows
# ---------------------------------------------------------------------------

func scalarmult*(r: var GeP3; s: array[32, byte]; p: GeP3) =
  ## r = [s]p — variable-base scalar multiplication.
  ## Uses unsigned 4-bit windows (nibbles 0..15), high-first.
  var pts: array[16, GeP3]
  var cch: array[16, GeCached]
  var tmp2: GeP2
  var dbl: GeP1P1

  # Build pts[0] = identity, pts[1] = P, pts[2] = 2P, ..., pts[15] = 15P
  # Then cch[k] = cached(pts[k]).
  pts[0].x = FeZero; pts[0].y = FeOne; pts[0].z = FeOne; pts[0].t = FeZero
  geP3ToCached(cch[0], pts[0])

  pts[1] = p
  geP3ToCached(cch[1], pts[1])

  for i in countup(2, 15):
    geAdd(dbl, pts[i-1], cch[1])   # pts[i] = pts[i-1] + P
    geP1P1ToP3(pts[i], dbl)
    geP3ToCached(cch[i], pts[i])

  # Process nibbles from high to low
  var started = false

  for i in countdown(63, 0):
    let b = int(s[i shr 1])
    let window = (b shr (4 * (i and 1))) and 0xF

    if started:
      # Double r four times (16 = 2^4)
      geP3ToP2(tmp2, r)
      for j in 0..<4:
        geP2Dbl(dbl, tmp2)
        if j < 3:
          geP1P1ToP2(tmp2, dbl)
        else:
          geP1P1ToP3(r, dbl)

    if window != 0:
      if not started:
        r = pts[window]
        started = true
      else:
        geAdd(dbl, r, cch[window])
        geP1P1ToP3(r, dbl)

# ---------------------------------------------------------------------------
# Point encoding, scalar reduction/canonicity, and the shared challenge hash
# (RFC 8032 §5.1) — relocated from ed25519.nim / extracted from its verify.
#
# RFC 8032 signing must run scReduce over secret-derived values (the nonce
# hash) and needs pointEncode for R and A, but ed25519.nim's whole identity
# is "verify-only, never touches a secret" — so this group lives here
# instead (ref10 keeps the sc25519_*/ge_* families together for the same
# reason), and ed25519.nim imports it back. Pushed checks-off: these
# functions index fixed-size arrays at compile-time-constant offsets (not a
# CT requirement by itself), and will see secret-derived input once signing
# lands. verify's calls into this group now also run checks-off as an
# accepted side effect, not because verify needs it.
# ---------------------------------------------------------------------------

{.push checks: off.}

func pointEncode*(p: GeP3): array[32, byte] =
  var zInv, x, y: Fe
  feInvert(zInv, p.z)
  feMul(x, p.x, zInv)
  feMul(y, p.y, zInv)
  var enc = feToBytes(y)
  if feIsNegative(x):
    enc[31] = enc[31] or 0x80'u8
  return enc

# Subgroup order L (RFC 8032 §5.1).
const
  L*: array[32, byte] = [
    0xED'u8, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58,
    0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
  ]

func load3(s: openArray[byte]; off: int): int64 {.inline.} =
  int64(s[off]) or (int64(s[off + 1]) shl 8) or (int64(s[off + 2]) shl 16)

func load4(s: openArray[byte]; off: int): int64 {.inline.} =
  int64(s[off]) or (int64(s[off + 1]) shl 8) or
    (int64(s[off + 2]) shl 16) or (int64(s[off + 3]) shl 24)

func scReduce*(o: var array[32, byte]; s: array[64, byte]) =
  ## Reduce 512-bit scalar modulo L. Ported from libsodium ref10 sc25519_reduce.
  const M = 0x1FFFFF'i64
  var s0  = M and load3(s, 0)
  var s1  = M and (load4(s, 2) shr 5)
  var s2  = M and (load3(s, 5) shr 2)
  var s3  = M and (load4(s, 7) shr 7)
  var s4  = M and (load4(s, 10) shr 4)
  var s5  = M and (load3(s, 13) shr 1)
  var s6  = M and (load4(s, 15) shr 6)
  var s7  = M and (load3(s, 18) shr 3)
  var s8  = M and load3(s, 21)
  var s9  = M and (load4(s, 23) shr 5)
  var s10 = M and (load3(s, 26) shr 2)
  var s11 = M and (load4(s, 28) shr 7)
  var s12 = M and (load4(s, 31) shr 4)
  var s13 = M and (load3(s, 34) shr 1)
  var s14 = M and (load4(s, 36) shr 6)
  var s15 = M and (load3(s, 39) shr 3)
  var s16 = M and load3(s, 42)
  var s17 = M and (load4(s, 44) shr 5)
  var s18 = M and (load3(s, 47) shr 2)
  var s19 = M and (load4(s, 49) shr 7)
  var s20 = M and (load4(s, 52) shr 4)
  var s21 = M and (load3(s, 55) shr 1)
  var s22 = M and (load4(s, 57) shr 6)
  var s23 = load4(s, 60) shr 3

  s11 += s23 * 666643
  s12 += s23 * 470296
  s13 += s23 * 654183
  s14 -= s23 * 997805
  s15 += s23 * 136657
  s16 -= s23 * 683901

  s10 += s22 * 666643
  s11 += s22 * 470296
  s12 += s22 * 654183
  s13 -= s22 * 997805
  s14 += s22 * 136657
  s15 -= s22 * 683901

  s9 += s21 * 666643
  s10 += s21 * 470296
  s11 += s21 * 654183
  s12 -= s21 * 997805
  s13 += s21 * 136657
  s14 -= s21 * 683901

  s8 += s20 * 666643
  s9 += s20 * 470296
  s10 += s20 * 654183
  s11 -= s20 * 997805
  s12 += s20 * 136657
  s13 -= s20 * 683901

  s7 += s19 * 666643
  s8 += s19 * 470296
  s9 += s19 * 654183
  s10 -= s19 * 997805
  s11 += s19 * 136657
  s12 -= s19 * 683901

  s6 += s18 * 666643
  s7 += s18 * 470296
  s8 += s18 * 654183
  s9 -= s18 * 997805
  s10 += s18 * 136657
  s11 -= s18 * 683901

  var carry6  = (s6  + (1'i64 shl 20)) shr 21; s7  += carry6;  s6  -= carry6 shl 21
  var carry8  = (s8  + (1'i64 shl 20)) shr 21; s9  += carry8;  s8  -= carry8 shl 21
  var carry10 = (s10 + (1'i64 shl 20)) shr 21; s11 += carry10; s10 -= carry10 shl 21
  var carry12 = (s12 + (1'i64 shl 20)) shr 21; s13 += carry12; s12 -= carry12 shl 21
  var carry14 = (s14 + (1'i64 shl 20)) shr 21; s15 += carry14; s14 -= carry14 shl 21
  var carry16 = (s16 + (1'i64 shl 20)) shr 21; s17 += carry16; s16 -= carry16 shl 21

  var carry7  = (s7  + (1'i64 shl 20)) shr 21; s8  += carry7;  s7  -= carry7 shl 21
  var carry9  = (s9  + (1'i64 shl 20)) shr 21; s10 += carry9;  s9  -= carry9 shl 21
  var carry11 = (s11 + (1'i64 shl 20)) shr 21; s12 += carry11; s11 -= carry11 shl 21
  var carry13 = (s13 + (1'i64 shl 20)) shr 21; s14 += carry13; s13 -= carry13 shl 21
  var carry15 = (s15 + (1'i64 shl 20)) shr 21; s16 += carry15; s15 -= carry15 shl 21

  s5 += s17 * 666643
  s6 += s17 * 470296
  s7 += s17 * 654183
  s8 -= s17 * 997805
  s9 += s17 * 136657
  s10 -= s17 * 683901

  s4 += s16 * 666643
  s5 += s16 * 470296
  s6 += s16 * 654183
  s7 -= s16 * 997805
  s8 += s16 * 136657
  s9 -= s16 * 683901

  s3 += s15 * 666643
  s4 += s15 * 470296
  s5 += s15 * 654183
  s6 -= s15 * 997805
  s7 += s15 * 136657
  s8 -= s15 * 683901

  s2 += s14 * 666643
  s3 += s14 * 470296
  s4 += s14 * 654183
  s5 -= s14 * 997805
  s6 += s14 * 136657
  s7 -= s14 * 683901

  s1 += s13 * 666643
  s2 += s13 * 470296
  s3 += s13 * 654183
  s4 -= s13 * 997805
  s5 += s13 * 136657
  s6 -= s13 * 683901

  s0 += s12 * 666643
  s1 += s12 * 470296
  s2 += s12 * 654183
  s3 -= s12 * 997805
  s4 += s12 * 136657
  s5 -= s12 * 683901
  s12 = 0

  var carry0 = (s0 + (1'i64 shl 20)) shr 21; s1 += carry0; s0 -= carry0 shl 21
  var carry2 = (s2 + (1'i64 shl 20)) shr 21; s3 += carry2; s2 -= carry2 shl 21
  var carry4 = (s4 + (1'i64 shl 20)) shr 21; s5 += carry4; s4 -= carry4 shl 21
  carry6 = (s6 + (1'i64 shl 20)) shr 21; s7 += carry6; s6 -= carry6 shl 21
  carry8 = (s8 + (1'i64 shl 20)) shr 21; s9 += carry8; s8 -= carry8 shl 21
  carry10 = (s10 + (1'i64 shl 20)) shr 21; s11 += carry10; s10 -= carry10 shl 21

  var carry1 = (s1 + (1'i64 shl 20)) shr 21; s2 += carry1; s1 -= carry1 shl 21
  var carry3 = (s3 + (1'i64 shl 20)) shr 21; s4 += carry3; s3 -= carry3 shl 21
  var carry5 = (s5 + (1'i64 shl 20)) shr 21; s6 += carry5; s5 -= carry5 shl 21
  carry7 = (s7 + (1'i64 shl 20)) shr 21; s8 += carry7; s7 -= carry7 shl 21
  carry9 = (s9 + (1'i64 shl 20)) shr 21; s10 += carry9; s9 -= carry9 shl 21
  carry11 = (s11 + (1'i64 shl 20)) shr 21; s12 += carry11; s11 -= carry11 shl 21

  s0 += s12 * 666643
  s1 += s12 * 470296
  s2 += s12 * 654183
  s3 -= s12 * 997805
  s4 += s12 * 136657
  s5 -= s12 * 683901
  s12 = 0

  carry0 = s0 shr 21; s1 += carry0; s0 -= carry0 shl 21
  carry1 = s1 shr 21; s2 += carry1; s1 -= carry1 shl 21
  carry2 = s2 shr 21; s3 += carry2; s2 -= carry2 shl 21
  carry3 = s3 shr 21; s4 += carry3; s3 -= carry3 shl 21
  carry4 = s4 shr 21; s5 += carry4; s4 -= carry4 shl 21
  carry5 = s5 shr 21; s6 += carry5; s5 -= carry5 shl 21
  carry6 = s6 shr 21; s7 += carry6; s6 -= carry6 shl 21
  carry7 = s7 shr 21; s8 += carry7; s7 -= carry7 shl 21
  carry8 = s8 shr 21; s9 += carry8; s8 -= carry8 shl 21
  carry9 = s9 shr 21; s10 += carry9; s9 -= carry9 shl 21
  carry10 = s10 shr 21; s11 += carry10; s10 -= carry10 shl 21
  carry11 = s11 shr 21; s12 += carry11; s11 -= carry11 shl 21

  s0 += s12 * 666643
  s1 += s12 * 470296
  s2 += s12 * 654183
  s3 -= s12 * 997805
  s4 += s12 * 136657
  s5 -= s12 * 683901

  carry0 = s0 shr 21; s1 += carry0; s0 -= carry0 shl 21
  carry1 = s1 shr 21; s2 += carry1; s1 -= carry1 shl 21
  carry2 = s2 shr 21; s3 += carry2; s2 -= carry2 shl 21
  carry3 = s3 shr 21; s4 += carry3; s3 -= carry3 shl 21
  carry4 = s4 shr 21; s5 += carry4; s4 -= carry4 shl 21
  carry5 = s5 shr 21; s6 += carry5; s5 -= carry5 shl 21
  carry6 = s6 shr 21; s7 += carry6; s6 -= carry6 shl 21
  carry7 = s7 shr 21; s8 += carry7; s7 -= carry7 shl 21
  carry8 = s8 shr 21; s9 += carry8; s8 -= carry8 shl 21
  carry9 = s9 shr 21; s10 += carry9; s9 -= carry9 shl 21
  carry10 = s10 shr 21; s11 += carry10; s10 -= carry10 shl 21

  o[ 0] = byte(s0 shr 0)
  o[ 1] = byte(s0 shr 8)
  o[ 2] = byte((s0 shr 16) or (s1 shl 5))
  o[ 3] = byte(s1 shr 3)
  o[ 4] = byte(s1 shr 11)
  o[ 5] = byte((s1 shr 19) or (s2 shl 2))
  o[ 6] = byte(s2 shr 6)
  o[ 7] = byte((s2 shr 14) or (s3 shl 7))
  o[ 8] = byte(s3 shr 1)
  o[ 9] = byte(s3 shr 9)
  o[10] = byte((s3 shr 17) or (s4 shl 4))
  o[11] = byte(s4 shr 4)
  o[12] = byte(s4 shr 12)
  o[13] = byte((s4 shr 20) or (s5 shl 1))
  o[14] = byte(s5 shr 7)
  o[15] = byte((s5 shr 15) or (s6 shl 6))
  o[16] = byte(s6 shr 2)
  o[17] = byte(s6 shr 10)
  o[18] = byte((s6 shr 18) or (s7 shl 3))
  o[19] = byte(s7 shr 5)
  o[20] = byte(s7 shr 13)
  o[21] = byte(s8 shr 0)
  o[22] = byte(s8 shr 8)
  o[23] = byte((s8 shr 16) or (s9 shl 5))
  o[24] = byte(s9 shr 3)
  o[25] = byte(s9 shr 11)
  o[26] = byte((s9 shr 19) or (s10 shl 2))
  o[27] = byte(s10 shr 6)
  o[28] = byte((s10 shr 14) or (s11 shl 7))
  o[29] = byte(s11 shr 1)
  o[30] = byte(s11 shr 9)
  o[31] = byte(s11 shr 17)

func scIsCanonical*(s: array[32, byte]): bool =
  ## Returns true iff s < L. RFC 8032 §5.1.3 step 12.
  for i in countdown(31, 0):
    if s[i] < L[i]: return true
    if s[i] > L[i]: return false
  return false

func scMulAdd*(a, b, c: array[32, byte]): array[32, byte] =
  ## s = (a*b + c) mod L. Ported from ref10 sc_muladd (public domain;
  ## also shipped as libsodium's sc25519_muladd). Same radix-2^21,
  ## 12-limb decomposition as scReduce, but here the limbs come straight
  ## from 32-byte inputs (not a 64-byte hash) and are combined via a full
  ## schoolbook multiply before the same carry-propagation/reduction tail.
  ## a, b are secret in the sign path (the nonce r and clamped scalar a);
  ## this function indexes fixed-size arrays at compile-time-constant
  ## offsets only, so checks-off carries no additional CT burden here.
  let a0  = 0x1FFFFF'i64 and load3(a, 0)
  let a1  = 0x1FFFFF'i64 and (load4(a, 2) shr 5)
  let a2  = 0x1FFFFF'i64 and (load3(a, 5) shr 2)
  let a3  = 0x1FFFFF'i64 and (load4(a, 7) shr 7)
  let a4  = 0x1FFFFF'i64 and (load4(a, 10) shr 4)
  let a5  = 0x1FFFFF'i64 and (load3(a, 13) shr 1)
  let a6  = 0x1FFFFF'i64 and (load4(a, 15) shr 6)
  let a7  = 0x1FFFFF'i64 and (load3(a, 18) shr 3)
  let a8  = 0x1FFFFF'i64 and load3(a, 21)
  let a9  = 0x1FFFFF'i64 and (load4(a, 23) shr 5)
  let a10 = 0x1FFFFF'i64 and (load3(a, 26) shr 2)
  let a11 = load4(a, 28) shr 7

  let b0  = 0x1FFFFF'i64 and load3(b, 0)
  let b1  = 0x1FFFFF'i64 and (load4(b, 2) shr 5)
  let b2  = 0x1FFFFF'i64 and (load3(b, 5) shr 2)
  let b3  = 0x1FFFFF'i64 and (load4(b, 7) shr 7)
  let b4  = 0x1FFFFF'i64 and (load4(b, 10) shr 4)
  let b5  = 0x1FFFFF'i64 and (load3(b, 13) shr 1)
  let b6  = 0x1FFFFF'i64 and (load4(b, 15) shr 6)
  let b7  = 0x1FFFFF'i64 and (load3(b, 18) shr 3)
  let b8  = 0x1FFFFF'i64 and load3(b, 21)
  let b9  = 0x1FFFFF'i64 and (load4(b, 23) shr 5)
  let b10 = 0x1FFFFF'i64 and (load3(b, 26) shr 2)
  let b11 = load4(b, 28) shr 7

  let c0  = 0x1FFFFF'i64 and load3(c, 0)
  let c1  = 0x1FFFFF'i64 and (load4(c, 2) shr 5)
  let c2  = 0x1FFFFF'i64 and (load3(c, 5) shr 2)
  let c3  = 0x1FFFFF'i64 and (load4(c, 7) shr 7)
  let c4  = 0x1FFFFF'i64 and (load4(c, 10) shr 4)
  let c5  = 0x1FFFFF'i64 and (load3(c, 13) shr 1)
  let c6  = 0x1FFFFF'i64 and (load4(c, 15) shr 6)
  let c7  = 0x1FFFFF'i64 and (load3(c, 18) shr 3)
  let c8  = 0x1FFFFF'i64 and load3(c, 21)
  let c9  = 0x1FFFFF'i64 and (load4(c, 23) shr 5)
  let c10 = 0x1FFFFF'i64 and (load3(c, 26) shr 2)
  let c11 = load4(c, 28) shr 7

  var s0  = c0 + a0*b0
  var s1  = c1 + a0*b1 + a1*b0
  var s2  = c2 + a0*b2 + a1*b1 + a2*b0
  var s3  = c3 + a0*b3 + a1*b2 + a2*b1 + a3*b0
  var s4  = c4 + a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0
  var s5  = c5 + a0*b5 + a1*b4 + a2*b3 + a3*b2 + a4*b1 + a5*b0
  var s6  = c6 + a0*b6 + a1*b5 + a2*b4 + a3*b3 + a4*b2 + a5*b1 + a6*b0
  var s7  = c7 + a0*b7 + a1*b6 + a2*b5 + a3*b4 + a4*b3 + a5*b2 + a6*b1 + a7*b0
  var s8  = c8 + a0*b8 + a1*b7 + a2*b6 + a3*b5 + a4*b4 + a5*b3 + a6*b2 +
            a7*b1 + a8*b0
  var s9  = c9 + a0*b9 + a1*b8 + a2*b7 + a3*b6 + a4*b5 + a5*b4 + a6*b3 +
            a7*b2 + a8*b1 + a9*b0
  var s10 = c10 + a0*b10 + a1*b9 + a2*b8 + a3*b7 + a4*b6 + a5*b5 + a6*b4 +
            a7*b3 + a8*b2 + a9*b1 + a10*b0
  var s11 = c11 + a0*b11 + a1*b10 + a2*b9 + a3*b8 + a4*b7 + a5*b6 + a6*b5 +
            a7*b4 + a8*b3 + a9*b2 + a10*b1 + a11*b0
  var s12 = a1*b11 + a2*b10 + a3*b9 + a4*b8 + a5*b7 + a6*b6 + a7*b5 +
            a8*b4 + a9*b3 + a10*b2 + a11*b1
  var s13 = a2*b11 + a3*b10 + a4*b9 + a5*b8 + a6*b7 + a7*b6 + a8*b5 +
            a9*b4 + a10*b3 + a11*b2
  var s14 = a3*b11 + a4*b10 + a5*b9 + a6*b8 + a7*b7 + a8*b6 + a9*b5 +
            a10*b4 + a11*b3
  var s15 = a4*b11 + a5*b10 + a6*b9 + a7*b8 + a8*b7 + a9*b6 + a10*b5 + a11*b4
  var s16 = a5*b11 + a6*b10 + a7*b9 + a8*b8 + a9*b7 + a10*b6 + a11*b5
  var s17 = a6*b11 + a7*b10 + a8*b9 + a9*b8 + a10*b7 + a11*b6
  var s18 = a7*b11 + a8*b10 + a9*b9 + a10*b8 + a11*b7
  var s19 = a8*b11 + a9*b10 + a10*b9 + a11*b8
  var s20 = a9*b11 + a10*b10 + a11*b9
  var s21 = a10*b11 + a11*b10
  var s22 = a11*b11
  var s23 = 0'i64

  var carry0  = (s0  + (1'i64 shl 20)) shr 21; s1  += carry0;  s0  -= carry0 shl 21
  var carry2  = (s2  + (1'i64 shl 20)) shr 21; s3  += carry2;  s2  -= carry2 shl 21
  var carry4  = (s4  + (1'i64 shl 20)) shr 21; s5  += carry4;  s4  -= carry4 shl 21
  var carry6  = (s6  + (1'i64 shl 20)) shr 21; s7  += carry6;  s6  -= carry6 shl 21
  var carry8  = (s8  + (1'i64 shl 20)) shr 21; s9  += carry8;  s8  -= carry8 shl 21
  var carry10 = (s10 + (1'i64 shl 20)) shr 21; s11 += carry10; s10 -= carry10 shl 21
  var carry12 = (s12 + (1'i64 shl 20)) shr 21; s13 += carry12; s12 -= carry12 shl 21
  var carry14 = (s14 + (1'i64 shl 20)) shr 21; s15 += carry14; s14 -= carry14 shl 21
  var carry16 = (s16 + (1'i64 shl 20)) shr 21; s17 += carry16; s16 -= carry16 shl 21
  var carry18 = (s18 + (1'i64 shl 20)) shr 21; s19 += carry18; s18 -= carry18 shl 21
  var carry20 = (s20 + (1'i64 shl 20)) shr 21; s21 += carry20; s20 -= carry20 shl 21
  var carry22 = (s22 + (1'i64 shl 20)) shr 21; s23 += carry22; s22 -= carry22 shl 21

  var carry1  = (s1  + (1'i64 shl 20)) shr 21; s2  += carry1;  s1  -= carry1 shl 21
  var carry3  = (s3  + (1'i64 shl 20)) shr 21; s4  += carry3;  s3  -= carry3 shl 21
  var carry5  = (s5  + (1'i64 shl 20)) shr 21; s6  += carry5;  s5  -= carry5 shl 21
  var carry7  = (s7  + (1'i64 shl 20)) shr 21; s8  += carry7;  s7  -= carry7 shl 21
  var carry9  = (s9  + (1'i64 shl 20)) shr 21; s10 += carry9;  s9  -= carry9 shl 21
  var carry11 = (s11 + (1'i64 shl 20)) shr 21; s12 += carry11; s11 -= carry11 shl 21
  var carry13 = (s13 + (1'i64 shl 20)) shr 21; s14 += carry13; s13 -= carry13 shl 21
  var carry15 = (s15 + (1'i64 shl 20)) shr 21; s16 += carry15; s15 -= carry15 shl 21
  var carry17 = (s17 + (1'i64 shl 20)) shr 21; s18 += carry17; s17 -= carry17 shl 21
  var carry19 = (s19 + (1'i64 shl 20)) shr 21; s20 += carry19; s19 -= carry19 shl 21
  var carry21 = (s21 + (1'i64 shl 20)) shr 21; s22 += carry21; s21 -= carry21 shl 21

  s11 += s23 * 666643
  s12 += s23 * 470296
  s13 += s23 * 654183
  s14 -= s23 * 997805
  s15 += s23 * 136657
  s16 -= s23 * 683901
  s23 = 0

  s10 += s22 * 666643
  s11 += s22 * 470296
  s12 += s22 * 654183
  s13 -= s22 * 997805
  s14 += s22 * 136657
  s15 -= s22 * 683901
  s22 = 0

  s9 += s21 * 666643
  s10 += s21 * 470296
  s11 += s21 * 654183
  s12 -= s21 * 997805
  s13 += s21 * 136657
  s14 -= s21 * 683901
  s21 = 0

  s8 += s20 * 666643
  s9 += s20 * 470296
  s10 += s20 * 654183
  s11 -= s20 * 997805
  s12 += s20 * 136657
  s13 -= s20 * 683901
  s20 = 0

  s7 += s19 * 666643
  s8 += s19 * 470296
  s9 += s19 * 654183
  s10 -= s19 * 997805
  s11 += s19 * 136657
  s12 -= s19 * 683901
  s19 = 0

  s6 += s18 * 666643
  s7 += s18 * 470296
  s8 += s18 * 654183
  s9 -= s18 * 997805
  s10 += s18 * 136657
  s11 -= s18 * 683901
  s18 = 0

  carry6  = (s6  + (1'i64 shl 20)) shr 21; s7  += carry6;  s6  -= carry6 shl 21
  carry8  = (s8  + (1'i64 shl 20)) shr 21; s9  += carry8;  s8  -= carry8 shl 21
  carry10 = (s10 + (1'i64 shl 20)) shr 21; s11 += carry10; s10 -= carry10 shl 21
  carry12 = (s12 + (1'i64 shl 20)) shr 21; s13 += carry12; s12 -= carry12 shl 21
  carry14 = (s14 + (1'i64 shl 20)) shr 21; s15 += carry14; s14 -= carry14 shl 21
  carry16 = (s16 + (1'i64 shl 20)) shr 21; s17 += carry16; s16 -= carry16 shl 21

  carry7  = (s7  + (1'i64 shl 20)) shr 21; s8  += carry7;  s7  -= carry7 shl 21
  carry9  = (s9  + (1'i64 shl 20)) shr 21; s10 += carry9;  s9  -= carry9 shl 21
  carry11 = (s11 + (1'i64 shl 20)) shr 21; s12 += carry11; s11 -= carry11 shl 21
  carry13 = (s13 + (1'i64 shl 20)) shr 21; s14 += carry13; s13 -= carry13 shl 21
  carry15 = (s15 + (1'i64 shl 20)) shr 21; s16 += carry15; s15 -= carry15 shl 21

  s5 += s17 * 666643
  s6 += s17 * 470296
  s7 += s17 * 654183
  s8 -= s17 * 997805
  s9 += s17 * 136657
  s10 -= s17 * 683901
  s17 = 0

  s4 += s16 * 666643
  s5 += s16 * 470296
  s6 += s16 * 654183
  s7 -= s16 * 997805
  s8 += s16 * 136657
  s9 -= s16 * 683901
  s16 = 0

  s3 += s15 * 666643
  s4 += s15 * 470296
  s5 += s15 * 654183
  s6 -= s15 * 997805
  s7 += s15 * 136657
  s8 -= s15 * 683901
  s15 = 0

  s2 += s14 * 666643
  s3 += s14 * 470296
  s4 += s14 * 654183
  s5 -= s14 * 997805
  s6 += s14 * 136657
  s7 -= s14 * 683901
  s14 = 0

  s1 += s13 * 666643
  s2 += s13 * 470296
  s3 += s13 * 654183
  s4 -= s13 * 997805
  s5 += s13 * 136657
  s6 -= s13 * 683901
  s13 = 0

  s0 += s12 * 666643
  s1 += s12 * 470296
  s2 += s12 * 654183
  s3 -= s12 * 997805
  s4 += s12 * 136657
  s5 -= s12 * 683901
  s12 = 0

  carry0 = s0 shr 21; s1 += carry0; s0 -= carry0 shl 21
  carry1 = s1 shr 21; s2 += carry1; s1 -= carry1 shl 21
  carry2 = s2 shr 21; s3 += carry2; s2 -= carry2 shl 21
  carry3 = s3 shr 21; s4 += carry3; s3 -= carry3 shl 21
  carry4 = s4 shr 21; s5 += carry4; s4 -= carry4 shl 21
  carry5 = s5 shr 21; s6 += carry5; s5 -= carry5 shl 21
  carry6 = s6 shr 21; s7 += carry6; s6 -= carry6 shl 21
  carry7 = s7 shr 21; s8 += carry7; s7 -= carry7 shl 21
  carry8 = s8 shr 21; s9 += carry8; s8 -= carry8 shl 21
  carry9 = s9 shr 21; s10 += carry9; s9 -= carry9 shl 21
  carry10 = s10 shr 21; s11 += carry10; s10 -= carry10 shl 21
  carry11 = s11 shr 21; s12 += carry11; s11 -= carry11 shl 21

  s0 += s12 * 666643
  s1 += s12 * 470296
  s2 += s12 * 654183
  s3 -= s12 * 997805
  s4 += s12 * 136657
  s5 -= s12 * 683901
  s12 = 0

  carry0 = s0 shr 21; s1 += carry0; s0 -= carry0 shl 21
  carry1 = s1 shr 21; s2 += carry1; s1 -= carry1 shl 21
  carry2 = s2 shr 21; s3 += carry2; s2 -= carry2 shl 21
  carry3 = s3 shr 21; s4 += carry3; s3 -= carry3 shl 21
  carry4 = s4 shr 21; s5 += carry4; s4 -= carry4 shl 21
  carry5 = s5 shr 21; s6 += carry5; s5 -= carry5 shl 21
  carry6 = s6 shr 21; s7 += carry6; s6 -= carry6 shl 21
  carry7 = s7 shr 21; s8 += carry7; s7 -= carry7 shl 21
  carry8 = s8 shr 21; s9 += carry8; s8 -= carry8 shl 21
  carry9 = s9 shr 21; s10 += carry9; s9 -= carry9 shl 21
  carry10 = s10 shr 21; s11 += carry10; s10 -= carry10 shl 21

  result[ 0] = byte(s0 shr 0)
  result[ 1] = byte(s0 shr 8)
  result[ 2] = byte((s0 shr 16) or (s1 shl 5))
  result[ 3] = byte(s1 shr 3)
  result[ 4] = byte(s1 shr 11)
  result[ 5] = byte((s1 shr 19) or (s2 shl 2))
  result[ 6] = byte(s2 shr 6)
  result[ 7] = byte((s2 shr 14) or (s3 shl 7))
  result[ 8] = byte(s3 shr 1)
  result[ 9] = byte(s3 shr 9)
  result[10] = byte((s3 shr 17) or (s4 shl 4))
  result[11] = byte(s4 shr 4)
  result[12] = byte(s4 shr 12)
  result[13] = byte((s4 shr 20) or (s5 shl 1))
  result[14] = byte(s5 shr 7)
  result[15] = byte((s5 shr 15) or (s6 shl 6))
  result[16] = byte(s6 shr 2)
  result[17] = byte(s6 shr 10)
  result[18] = byte((s6 shr 18) or (s7 shl 3))
  result[19] = byte(s7 shr 5)
  result[20] = byte(s7 shr 13)
  result[21] = byte(s8 shr 0)
  result[22] = byte(s8 shr 8)
  result[23] = byte((s8 shr 16) or (s9 shl 5))
  result[24] = byte(s9 shr 3)
  result[25] = byte(s9 shr 11)
  result[26] = byte((s9 shr 19) or (s10 shl 2))
  result[27] = byte(s10 shr 6)
  result[28] = byte((s10 shr 14) or (s11 shl 7))
  result[29] = byte(s11 shr 1)
  result[30] = byte(s11 shr 9)
  result[31] = byte(s11 shr 17)

func challenge*(R, A: array[32, byte]; msg: openArray[byte]): array[32, byte] =
  ## k = SHA-512(R || A || msg) mod L (RFC 8032 §5.1.6 step 4 / §5.1.7 step
  ## 2) — the challenge hash shared by verify and (once implemented)
  ## signDetached. One audited copy of the formula: two hand-maintained
  ## copies would be a latent sign/verify self-consistency break with no
  ## compiler signal. R, A, msg, and k are all public in both protocols, so
  ## this carries no CT requirement of its own despite living beside
  ## scReduce.
  var sha: sha512
  sha.init()
  sha.update(R)
  sha.update(A)
  sha.update(msg)
  var k64: array[64, byte]
  sha.finish(k64)
  scReduce(result, k64)

{.pop.}