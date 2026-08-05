import std/strutils
import sello/field
import sello/scalar

proc bytesHex(a: array[32, byte]): string =
  result = ""
  for b in a:
    result.add b.toHex(2).toLowerAscii

# Basepoint
var B: GeP3
B.x.limbs = Ed25519Gx_Raw
B.y.limbs = Ed25519Gy_Raw
B.z = FeOne
B.t = FeZero
feMul(B.t, B.x, B.y)

# Encode basepoint manually
var zInv, bx, by: Fe
feInvert(zInv, B.z)
feMul(bx, B.x, zInv)
feMul(by, B.y, zInv)
var enc = feToBytes(by)
if feIsNegative(bx):
  enc[31] = enc[31] or 0x80'u8
echo "Basepoint: ", enc.bytesHex
echo "Expected:  5866666666666666666666666666666666666666666666666666666666666666"

# Test [2]B via geAdd
var BCached: GeCached
geP3ToCached(BCached, B)
var twoB_p1p1: GeP1P1
geAdd(twoB_p1p1, B, BCached)
var twoB: GeP3
geP1P1ToP3(twoB, twoB_p1p1)

# Encode [2]B
feInvert(zInv, twoB.z)
feMul(bx, twoB.x, zInv)
feMul(by, twoB.y, zInv)
var enc2 = feToBytes(by)
if feIsNegative(bx):
  enc2[31] = enc2[31] or 0x80'u8
echo "[2]B (add): ", enc2.bytesHex
echo "Expected:   c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022"

# Test [2]B via geP2Dbl
var Bp2: GeP2
geP3ToP2(Bp2, B)
var dbl_p1p1: GeP1P1
geP2Dbl(dbl_p1p1, Bp2)
var twoB_dbl: GeP3
geP1P1ToP3(twoB_dbl, dbl_p1p1)

# Encode [2]B_dbl
feInvert(zInv, twoB_dbl.z)
feMul(bx, twoB_dbl.x, zInv)
feMul(by, twoB_dbl.y, zInv)
var enc3 = feToBytes(by)
if feIsNegative(bx):
  enc3[31] = enc3[31] or 0x80'u8
echo "[2]B (dbl): ", enc3.bytesHex
echo "Expected:   c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022"
