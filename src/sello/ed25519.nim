## ed25519 — EdDSA signatures (RFC 8032 §5.1)
##
## Pure-Nim verification (no CT requirements). Signing deferred.
## Uses the shared field and curve core from sello/field and sello/scalar.

import std/options
import sello/field
import sello/scalar

# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------

type
  PublicKey* = array[32, byte]
  Signature* = array[64, byte]

# ---------------------------------------------------------------------------
# Point decoding (RFC 8032 §5.1.3)
# ---------------------------------------------------------------------------

func pointDecode*(bytes: array[32, byte]): Option[GeP3] =
  ## Decode a compressed point per RFC 8032 §5.1.3. Returns None if the
  ## encoding is invalid: y >= p, no square root exists, or x = 0 with
  ## the sign bit set. Non-constant-time; verify-path only.
  if not feBytesCanonical(bytes):
    return none[GeP3]()

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
    # v*x^2 != u; retry with x*sqrt(-1), which squares to -x^2.
    # Valid iff v*x^2 == -u; anything else means u/v is not a square.
    var S: Fe
    S.limbs = SqrtM1_Raw
    feMul(x, x, S)
    feSq(vxx, x)
    feMul(vxx, vxx, v)
    feSub(vxx, vxx, u)
    if feIsNonZero(vxx):
      return none[GeP3]()

  # RFC 8032 §5.1.3 step 4: x = 0 with sign bit set is invalid.
  if sign and not feIsNonZero(x):
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

  # 4. k = SHA-512(R || PK || msg) mod L — the same audited formula
  #    signDetached will call once signing lands (sign/verify
  #    self-consistency; see sello/scalar.challenge).
  let kRed = challenge(rArr, pk, msg)

  # 5. Check the group equation [S]B == R + [k]A (RFC 8032 §5.1.7 step 3,
  #    cofactorless form): compare canonical encodings of both sides.

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
