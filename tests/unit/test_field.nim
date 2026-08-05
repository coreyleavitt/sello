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