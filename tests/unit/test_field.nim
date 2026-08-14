import std/unittest
import sello/field

# RFC 8032 §7.1: test vector 1
# Base point y-coordinate: 0x6658...ec58
let basepointY = [
  0x58'u8, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
]

suite "field arithmetic - known values":
  test "feFromBytes/feToBytes preserves basepoint Y":
    let f = feFromBytes(basepointY)
    let bytes = feToBytes(f)
    check bytes == basepointY

  test "feMul of known values":
    # (1) * (1) = 1
    var r: Fe
    feMul(r, FeOne, FeOne)
    check feToBytes(r) == feToBytes(FeOne)

  test "feSq of 2":
    var two: Fe
    two.limbs = [2'i32, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    var r: Fe
    feSq(r, two)
    var four: Fe
    four.limbs = [4'i32, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    check feToBytes(r) == feToBytes(four)

  test "feMul of basepoint Y * basepoint Y (y^2)":
    let y = feFromBytes(basepointY)
    var y2: Fe
    feSq(y2, y)
    # y^2 should convert to/from bytes consistently
    let y2bytes = feToBytes(y2)
    let y2roundtrip = feFromBytes(y2bytes)
    check feToBytes(y2roundtrip) == y2bytes

  test "feInvert of known non-one value":
    var two: Fe
    two.limbs = [2'i32, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    var inv, prod: Fe
    feInvert(inv, two)
    feMul(prod, two, inv)
    check feToBytes(prod) == feToBytes(FeOne)

  test "feAdd commutativity":
    var a, b: Fe
    a.limbs = [1'i32, 2, 3, 4, 5, 6, 7, 8, 9, 0]
    b.limbs = [9'i32, 8, 7, 6, 5, 4, 3, 2, 1, 0]
    var r1, r2: Fe
    feAdd(r1, a, b)
    feAdd(r2, b, a)
    check feToBytes(r1) == feToBytes(r2)

  test "feSq2 same as 2*feSq":
    var twoFe: Fe
    twoFe.limbs = [2'i32, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    var sq2, sqDouble: Fe
    feSq2(sq2, twoFe)
    feSq(sqDouble, twoFe)
    for i in 0..<10:
      sqDouble.limbs[i] = sqDouble.limbs[i] + sqDouble.limbs[i]
    check feToBytes(sq2) == feToBytes(sqDouble)

suite "feAbs (RFC-004 slice 1a)":
  test "negative input becomes non-negative; non-negative unchanged; feAbs(0) == 0":
    # "Negative" here is RFC 8032/9496's field-element sign convention:
    # feIsNegative(f) reads bit 0 of f's canonical (feToBytes) encoding, not
    # a signed-integer notion -- so a "negative" Fe is a value whose
    # canonical representative is odd, and feAbs must always leave a
    # feIsNegative == false result behind (never merely negate unconditionally).
    # 3 is odd, so its canonical encoding's low bit is set: feIsNegative == true.
    var three: Fe
    three.limbs = [3'i32, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    check feIsNegative(three) == true

    var absThree = three
    feAbs(absThree)
    check feIsNegative(absThree) == false
    # feAbs must not change the value's magnitude relationship to its
    # negation: absThree is either three itself (already non-negative -- it
    # is not, per the check above) or -three mod p.
    var negThree: Fe
    feNeg(negThree, three)
    check feToBytes(absThree) == feToBytes(negThree)

    # Non-negative input (2 is even, so feIsNegative == false) is unchanged.
    var two: Fe
    two.limbs = [2'i32, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    check feIsNegative(two) == false
    var absTwo = two
    feAbs(absTwo)
    check feToBytes(absTwo) == feToBytes(two)

    # feAbs(0) == 0.
    var absZero = FeZero
    feAbs(absZero)
    check feToBytes(absZero) == feToBytes(FeZero)

suite "feEqualCT / feIsZeroCT (RFC-004 slice 1a)":
  test "reflexivity and symmetry on known-equal/unequal pairs":
    var three, three2, five: Fe
    three.limbs = [3'i32, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    three2.limbs = [3'i32, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    five.limbs = [5'i32, 0, 0, 0, 0, 0, 0, 0, 0, 0]

    # Reflexivity.
    check feEqualCT(three, three) == true
    check feEqualCT(five, five) == true

    # Symmetry on a known-equal pair (distinct Fe values, same field element).
    check feEqualCT(three, three2) == true
    check feEqualCT(three2, three) == true

    # A known-unequal pair, both directions.
    check feEqualCT(three, five) == false
    check feEqualCT(five, three) == false

  test "two limb representations of the same field element compare equal":
    # `feAdd`/`feMul` on single-small-limb operands never actually exercise
    # a non-minimal representation (no carry into limb 1 occurs), so
    # constructing a genuinely distinct-but-equal representation has to be
    # done by hand: limb 0's place value is 1 and limb 1's is 2^26 (this
    # module's own doc comment coefficient ranges), so
    # `limb0 = V - k*2^26, limb1 = k` represents the same integer V as
    # `limb0 = V` for any k -- deliberately outside limb 0's normal
    # per-limb range (the "lazy"/non-minimal representation the arithmetic
    # core tolerates internally; only `feToBytes` fully normalizes).
    var minimalRepr, splitRepr: Fe
    minimalRepr.limbs = [100_000_000'i32, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    splitRepr.limbs = [100_000_000'i32 - 67108864'i32, 1'i32, 0, 0, 0, 0, 0, 0, 0, 0]

    check minimalRepr.limbs != splitRepr.limbs
    check feToBytes(minimalRepr) == feToBytes(splitRepr)  # sanity: same value
    check feEqualCT(minimalRepr, splitRepr) == true
    check feEqualCT(splitRepr, minimalRepr) == true

  test "feIsZeroCT detects zero and rejects nonzero":
    check feIsZeroCT(FeZero) == true
    var five: Fe
    five.limbs = [5'i32, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    check feIsZeroCT(five) == false
    # A non-trivial representation of zero, by the same limb0/limb1
    # splitting trick as above with V = 0: limb0 = -2^26, limb1 = 1.
    var zeroSplit: Fe
    zeroSplit.limbs = [-67108864'i32, 1'i32, 0, 0, 0, 0, 0, 0, 0, 0]
    check zeroSplit.limbs != FeZero.limbs
    check feToBytes(zeroSplit) == feToBytes(FeZero)  # sanity: same value
    check feIsZeroCT(zeroSplit) == true

suite "feBytesCanonicalCT (RFC-004 slice 1a)":
  test "agrees with feBytesCanonical at p-1, p, p+1, all-0xFF, all-zero, and random canonical encodings":
    # p - 1 = 2^255 - 20: canonical.
    let pMinus1 = [
      0xEC'u8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F
    ]
    # p = 2^255 - 19: non-canonical (this IS p, the boundary itself).
    let pExact = [
      0xED'u8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F
    ]
    # p + 1 = 2^255 - 18: non-canonical.
    let pPlus1 = [
      0xEE'u8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F
    ]
    var allFF: array[32, byte]  # non-canonical (>> p, and bit 255 set)
    for i in 0..<32: allFF[i] = 0xFF'u8
    let allZero: array[32, byte] = default(array[32, byte])  # canonical (0 < p)
    # A random-looking but definitely-canonical encoding: the RFC 8032
    # basepoint Y from this file's own header, already known < p.
    let canonicalRandomish = basepointY

    for b in [pMinus1, pExact, pPlus1, allFF, allZero, canonicalRandomish]:
      check feBytesCanonicalCT(b) == feBytesCanonical(b)

    # Pin the actual expected verdicts too, not just cross-agreement (a
    # bug shared by both functions would otherwise slip through).
    check feBytesCanonicalCT(pMinus1) == true
    check feBytesCanonicalCT(pExact) == false
    check feBytesCanonicalCT(pPlus1) == false
    check feBytesCanonicalCT(allFF) == false
    check feBytesCanonicalCT(allZero) == true
    check feBytesCanonicalCT(canonicalRandomish) == true

suite "FeSqrtM1 (RFC-004 slice 1a: sqrt(-1) exported again)":
  test "FeSqrtM1^2 == -1 mod p (its defining equation)":
    var sq, negOne: Fe
    feSq(sq, FeSqrtM1)
    feNeg(negOne, FeOne)
    check feToBytes(sq) == feToBytes(negOne)

suite "feSqrtRatioM1 (RFC-004 slice 1a: RFC 9496 SQRT_RATIO_M1, constant-time)":
  test "degenerate cases: SQRT_RATIO_M1(0, v) == (true, 0); SQRT_RATIO_M1(u, 0) == (false, 0)":
    var five: Fe
    five.limbs = [5'i32, 0, 0, 0, 0, 0, 0, 0, 0, 0]

    let (wasSquare1, root1) = feSqrtRatioM1(FeZero, five)
    check wasSquare1 == true
    check feToBytes(root1) == feToBytes(FeZero)

    let (wasSquare2, root2) = feSqrtRatioM1(five, FeZero)
    check wasSquare2 == false
    check feToBytes(root2) == feToBytes(FeZero)

  test "RFC 9496 Appendix A.4 vectors, bit-exact":
    # Transcribed verbatim from the published RFC 9496 text
    # (https://www.rfc-editor.org/rfc/rfc9496.txt), Appendix A.4. Values
    # are little-endian byte encodings of field elements, exactly as
    # `feFromBytes`/`feToBytes` already use throughout this codebase.
    type Vec = tuple[u, v: array[32, byte], wasSquare: bool, r: array[32, byte]]

    let zero32: array[32, byte] = default(array[32, byte])

    var one32: array[32, byte] = default(array[32, byte])
    one32[0] = 1

    var two32: array[32, byte] = default(array[32, byte])
    two32[0] = 2

    var four32: array[32, byte] = default(array[32, byte])
    four32[0] = 4

    let r4 = [
      0x3c'u8, 0x5f, 0xf1, 0xb5, 0xd8, 0xe4, 0x11, 0x3b,
      0x87, 0x1b, 0xd0, 0x52, 0xf9, 0xe7, 0xbc, 0xd0,
      0x58, 0x28, 0x04, 0xc2, 0x66, 0xff, 0xb2, 0xd4,
      0xf4, 0x20, 0x3e, 0xb0, 0x7f, 0xdb, 0x7c, 0x54
    ]
    let r6 = [
      0xf6'u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f
    ]

    let vectors: seq[Vec] = @[
      (zero32, zero32, true, zero32),
      (zero32, one32, true, zero32),
      (one32, zero32, false, zero32),
      (two32, one32, false, r4),
      (four32, one32, true, two32),
      (one32, four32, true, r6),
    ]

    for vec in vectors:
      let (wasSquare, root) = feSqrtRatioM1(feFromBytes(vec.u), feFromBytes(vec.v))
      check wasSquare == vec.wasSquare
      check feToBytes(root) == vec.r

  test "false-branch root's defining equation: root^2 == SQRT_M1*u/v for known non-square u/v":
    # p = 2^255-19 == 5 (mod 8), and 2 is a quadratic non-residue for every
    # such prime. u = 2*x^2 for arbitrary nonzero x is therefore also a
    # non-residue (nonsquare * square = nonsquare), with v = 1, so this
    # exercises the general false-branch case (not merely v = 0/u = 0
    # degeneracies, nor the single already-KAT-pinned u=2,v=1 case above).
    var x: Fe
    x.limbs = [11'i32, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    var xsq, u: Fe
    feSq(xsq, x)
    var two: Fe
    two.limbs = [2'i32, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    feMul(u, two, xsq)

    let (wasSquare, root) = feSqrtRatioM1(u, FeOne)
    check wasSquare == false

    # root^2 == SQRT_M1 * u / v == SQRT_M1 * u (since v = 1 here).
    var rootSq, expected: Fe
    feSq(rootSq, root)
    feMul(expected, FeSqrtM1, u)
    check feToBytes(rootSq) == feToBytes(expected)

suite "feFromLimbs (RFC-003 slice 1 item 2)":
  test "feFromLimbs(limbs) is byte-identical to hand-assigning .limbs":
    let rawLimbs = [2'i32, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    var handAssigned: Fe
    handAssigned.limbs = rawLimbs
    let viaConstructor = feFromLimbs(rawLimbs)
    check feToBytes(viaConstructor) == feToBytes(handAssigned)
    check viaConstructor.limbs == handAssigned.limbs

  test "feFromLimbs round-trips into arithmetic identically to hand-assignment":
    # (2)^2 == 4, computed both ways -- confirms the constructor's result
    # is not just field-equal but usable by every fe* primitive the same
    # way a hand-assigned Fe is.
    let rawLimbs = [2'i32, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    var handAssigned: Fe
    handAssigned.limbs = rawLimbs
    let viaConstructor = feFromLimbs(rawLimbs)
    var r1, r2: Fe
    feSq(r1, handAssigned)
    feSq(r2, viaConstructor)
    check feToBytes(r1) == feToBytes(r2)