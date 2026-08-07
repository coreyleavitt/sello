import std/[unittest, options]
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

suite "feSqrtRatioVartime (RFC-003 slice 1 item 3, extracted from ed25519.pointDecode)":
  test "returns a root x with x^2 * v == u when u/v is a square":
    # Construct u = v * x0^2 for arbitrary nonzero v, x0, so u/v is square
    # by construction; feSqrtRatioVartime need not recover x0 itself
    # (ed25519's field has two square roots, x0 and -x0) -- only that the
    # returned root actually squares (times v) back to u.
    var v: Fe
    v.limbs = [7'i32, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    var x0: Fe
    x0.limbs = [11'i32, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    var x0sq, u: Fe
    feSq(x0sq, x0)
    feMul(u, v, x0sq)

    let xOpt = feSqrtRatioVartime(u, v)
    check xOpt.isSome
    var vxx: Fe
    feSq(vxx, xOpt.get)
    feMul(vxx, vxx, v)
    check feToBytes(vxx) == feToBytes(u)

  test "returns none when u/v is not a square":
    # p = 2^255 - 19 == 5 (mod 8), and 2 is a quadratic non-residue for
    # every prime p == 5 (mod 8) -- so u=2, v=1 is a clean,
    # curve-constant-free non-square case (independent of Ed25519D_Raw,
    # unlike ed25519.pointDecode's own non-residue backstop test, which
    # goes through the full y-coordinate recovery formula).
    var u: Fe
    u.limbs = [2'i32, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    check feSqrtRatioVartime(u, FeOne).isNone

  test "u = 0 returns some(0), the trivial square root":
    check feSqrtRatioVartime(FeZero, FeOne).isSome
    let x = feSqrtRatioVartime(FeZero, FeOne).get
    check feToBytes(x) == feToBytes(FeZero)