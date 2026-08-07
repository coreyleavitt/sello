## ed25519 — EdDSA signatures (RFC 8032 §5.1)
##
## Pure-Nim verification (no CT requirements). Signing deferred.
## Uses the shared field and curve core from sello/field and sello/scalar.

import std/options
import sello/field
import sello/scalar
import sello/challenge
import sello/wire

# `PublicKey`/`Signature` are defined in `sello/wire` (RFC-001 finding 9;
# relocated out of `sello/scalar` by round-2 finding 27, then out of the
# combined `types.nim` by RFC-002 slice 2 item 5, which split it into
# `wire.nim` (these types) and `wipe.nim` (the unrelated generic secret
# wipe) -- see `wire.nim`'s module doc for the rationale), not here: both
# the verify path (this module) and the signing path (`signing.nim`) need
# them, so they live on a shared leaf module both depend on downward,
# rather than `signing.nim` importing this verify-only module just to
# borrow two type aliases. Re-exported here so `import sello/ed25519`
# alone (the pre-existing habit) still finds them.
export wire.PublicKey, wire.Signature
export wire.toPublicKey, wire.toSignature, wire.toBytes
export wire.`==`, wire.`$`

# ---------------------------------------------------------------------------
# Point decoding (RFC 8032 §5.1.3)
# ---------------------------------------------------------------------------

func pointDecode*(bytes: array[32, byte]): Option[GeP3] =
  ## Decode a compressed point per RFC 8032 §5.1.3. Returns None if the
  ## encoding is invalid: y >= p, no square root exists, or x = 0 with
  ## the sign bit set. Non-constant-time; verify-path only.
  if not feBytesCanonical(bytes):
    return none[GeP3]()

  let D = feFromLimbs(Ed25519D_Raw)
  let I = FeOne

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

  # x = sqrt(u/v), retrying with sqrt(-1) if the first candidate root
  # doesn't check out (RFC 8032 §5.1.3 step 3) -- extracted to
  # field.feSqrtRatioVartime (RFC-003 slice 1 item 3), so this call is the
  # entire dance, not just the candidate-root formula.
  let xOpt = feSqrtRatioVartime(u, v)
  if xOpt.isNone:
    return none[GeP3]()
  var x = xOpt.get

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

func verify*(pk: PublicKey; msg: openArray[byte]; sig: Signature): bool =
  ## Verify an ed25519 signature. Returns false for invalid inputs.
  ##
  ## Actor-first: `pk.verify(msg, sig)`, matching RFC 8032's own
  ## VERIFY(pk, M, sig) notation and ed25519-dalek's
  ## `VerifyingKey::verify(message, signature)`.
  ##
  ## **Malleability (RFC-001 ledger finding 19):** this checks the RFC
  ## 8032 §5.1.7 group equation in its cofactorless form (`[S]B == R +
  ## [k]A`), as the RFC itself specifies -- it does not multiply through by
  ## the cofactor. That equation admits low-order components: for a given
  ## valid `(pk, msg, sig)`, adding a small-order point's contribution to
  ## `R` (and adjusting `S` to compensate) can produce a second, distinct
  ## signature that this function ALSO accepts for the same `(msg, pk)`.
  ## This is standard, RFC-conformant ed25519 behavior, not a bug specific
  ## to this implementation -- but it does mean signature bytes are not a
  ## unique identifier for a `(msg, pk)` pair. Callers must not build
  ## dedup/uniqueness/replay-detection logic keyed on the signature bytes
  ## themselves; key such logic on `(msg, pk)`, or another value chosen for
  ## that purpose, instead.
  let sigBytes = toBytes(sig)
  let pkBytes = toBytes(pk)

  # 1. Decode R
  var rArr: array[32, byte]
  for i in 0..<32: rArr[i] = sigBytes[i]
  let rOpt = pointDecode(rArr)
  if rOpt.isNone: return false

  # 2. Decode A (public key)
  let aOpt = pointDecode(pkBytes)
  if aOpt.isNone: return false

  # 3. Check S < L
  var sArr: array[32, byte]
  for i in 0..<32: sArr[i] = sigBytes[32 + i]
  if not scIsCanonical(sArr): return false

  let R = rOpt.get
  let A = aOpt.get

  # 4. k = SHA-512(R || PK || msg) mod L — the same audited formula
  #    signDetached also calls, for sign/verify self-consistency (see
  #    sello/challenge.challenge).
  let kRed = challenge(rArr, pkBytes, msg)

  # 5. Check the group equation [S]B == R + [k]A (RFC 8032 §5.1.7 step 3,
  #    cofactorless form): compare canonical encodings of both sides.

  # Base point (RFC-003 slice 1 item 1: the constructor, not a second
  # hand-maintained copy of scalar.geBasePoint's byte-identical construction).
  let B = geBasePoint()

  # [S]B
  var SB: GeP3
  scalarmultVartime(SB, sArr, B)

  # [k]A
  var kA: GeP3
  scalarmultVartime(kA, kRed, A)

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

func verify*(pk: PublicKey; msg: string; sig: Signature): bool =
  ## Zero-copy `string` overload, matching `signing.sign`'s: `msg.
  ## toOpenArrayByte` views the string's existing bytes in place, no copy.
  verify(pk, msg.toOpenArrayByte(0, msg.len - 1), sig)
