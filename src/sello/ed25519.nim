## ed25519 — EdDSA signatures (RFC 8032 §5.1)
##
## Pure-Nim verification (no CT requirements). Signing deferred.
## Uses the shared field and curve core from sello/field and sello/scalar.

import std/options
import nimcrypto/sha2
import sello/field
import sello/scalar

# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------

type
  PublicKey* = array[32, byte]
  SecretKey* = array[32, byte]
  Signature* = array[64, byte]

# ---------------------------------------------------------------------------
# Subgroup order L (RFC 8032 §5.1)
# ---------------------------------------------------------------------------

const
  L*: array[32, byte] = [
    0xED'u8, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58,
    0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
  ]

# ---------------------------------------------------------------------------
# Point encoding / decoding (RFC 8032 §5.1.3)
# ---------------------------------------------------------------------------

func pointEncode*(p: GeP3): array[32, byte] =
  var zInv, x, y: Fe
  feInvert(zInv, p.z)
  feMul(x, p.x, zInv)
  feMul(y, p.y, zInv)
  var enc = feToBytes(y)
  if feIsNegative(x):
    enc[31] = enc[31] or 0x80'u8
  return enc

func pointDecode*(bytes: array[32, byte]): Option[GeP3] =
  ## Decode a compressed point. Returns None if encoding is invalid.
  ## This is the "verification-safe" path; non-constant-time.
  var D, I: Fe
  D.limbs = Ed25519D_Raw
  I = FeOne

  var u, v: Fe
  var y = feFromBytes(bytes)
  var sign = (bytes[31] shr 7) != 0

  # u = y^2 - 1
  feSq(u, y)
  feSub(u, u, I)

  # v = d*y^2 + 1
  var dy2: Fe
  feMul(dy2, D, y)
  feMul(dy2, dy2, y)
  feAdd(v, dy2, I)

  # x = (u/v)^((p+3)/8) using the sqrtRatioM1 approach
  var v3: Fe
  feSq(v3, v)
  feMul(v3, v3, v)          # v^3
  var uv3, uv7: Fe
  feMul(uv3, v3, u)         # u*v^3
  feMul(uv7, uv3, v3)       # u*v^6
  feMul(uv7, uv7, v)        # u*v^7

  var x: Fe
  fePow22523(x, uv7)        # (u*v^7)^((p-5)/8)
  feMul(x, x, v3)           # * v^3
  feMul(x, x, u)            # * u

  # Check: v*x^2 == u or v*x^2 == -u
  var vxx: Fe
  feSq(vxx, x)
  feMul(vxx, vxx, v)
  feSub(vxx, vxx, u)

  if feIsNonZero(vxx):
    feAdd(vxx, vxx, u)      # v*x^2 + u
    feAdd(vxx, vxx, u)      # v*x^2 + u  (re-adding u since vxx was vx^2-u)
    # Actually: need vx^2 - u == 0 or vx^2 + u == 0
    # If vx^2 != u, check vx^2 == -u i.e. vx^2 + u == 0
    var S: Fe
    S.limbs = SqrtM1_Raw
    feMul(x, x, S)          # multiply by sqrt(-1)
    feSq(vxx, x)
    feMul(vxx, vxx, v)
    feSub(vxx, vxx, u)
    if feIsNonZero(vxx):
      return none[GeP3]()

  if feIsNegative(x) != sign:
    feNeg(x, x)

  var encoded: GeP3
  encoded.x = x
  encoded.y = y
  encoded.z = FeOne
  feMul(encoded.t, x, y)
  return some(encoded)

# ---------------------------------------------------------------------------
# Scalar arithmetic (RFC 8032)
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# ed25519 verify (RFC 8032 §5.1.7)
# ---------------------------------------------------------------------------

func verify*(sig: Signature; msg: openArray[byte]; pk: PublicKey): bool =
  ## Verify an ed25519 signature. Returns false for invalid inputs.

  # 1. Decode R
  var rArr: array[32, byte]
  for i in 0..<32: rArr[i] = sig[i]
  let rOpt = pointDecode(rArr)
  if rOpt.isNone: return false

  # 2. Decode A (public key)
  let aOpt = pointDecode(pk)
  if aOpt.isNone: return false

  # 3. Check S < L
  var sArr: array[32, byte]
  for i in 0..<32: sArr[i] = sig[32 + i]
  if not scIsCanonical(sArr): return false

  let R = rOpt.get
  let A = aOpt.get

  # 4. k = SHA-512(R || PK || msg) mod L
  var sha: sha512
  sha.init()
  sha.update(cast[ptr byte](unsafeAddr rArr[0]), 32'u)
  sha.update(cast[ptr byte](unsafeAddr pk[0]), 32'u)
  if msg.len > 0:
    sha.update(cast[ptr byte](unsafeAddr msg[0]), uint(msg.len))
  var k64: array[64, byte]
  sha.finish(k64)

  var kRed: array[32, byte]
  scReduce(kRed, k64)

  # 5. Compute [S]B - [k]A, compare to R
  #    Per RFC: [S]B = R + [k]A  => check pointEncode([S]B - [k]A) == R
  #
  #    Actually RFC says: check [S]B == R + [k]A
  #    So compute lhs = [S]B and rhs = R + [k]A, compare

  # Base point
  var B: GeP3
  B.x.limbs = Ed25519Gx_Raw
  B.y.limbs = Ed25519Gy_Raw
  B.z = FeOne
  feMul(B.t, B.x, B.y)

  # [S]B
  var SB: GeP3
  scalarmult(SB, sArr, B)

  # [k]A
  var kA: GeP3
  scalarmult(kA, kRed, A)

  # R + [k]A
  var cachedR: GeCached
  geP3ToCached(cachedR, R)
  var sum: GeP1P1
  geAdd(sum, kA, cachedR)
  var rhs: GeP3
  geP1P1ToP3(rhs, sum)

  let lhsBytes = pointEncode(SB)
  let rhsBytes = pointEncode(rhs)

  # Constant-time comparison would be better, but verifier has no CT req.
  return lhsBytes == rhsBytes