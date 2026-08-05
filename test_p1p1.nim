import std/strutils
import sello/field
import sello/curve/scalar

proc bytesHex(a: openArray[byte]): string =
  var s = ""
  for b in a: s.add b.toHex(2).toLowerAscii
  s

# Compute [2]B using geAdd and check affine coordinates
var B: GeP3
B.x.limbs = Ed25519Gx_Raw
B.y.limbs = Ed25519Gy_Raw
B.z = feFromBytes([1'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
feMul(B.t, B.x, B.y)

var Bc: GeCached
geP3ToCached(Bc, B)

var p1p1: GeP1P1
geAdd(p1p1, B, Bc)

echo "P1P1 limbs:"
echo "X: ", p1p1.x.limbs
echo "Y: ", p1p1.y.limbs
echo "Z: ", p1p1.z.limbs
echo "T: ", p1p1.t.limbs

# Compute affine: x = X/Z, y = Y/Z
var x_aff, y_aff: Fe
feDiv(x_aff, p1p1.x, p1p1.z)
feDiv(y_aff, p1p1.y, p1p1.z)

var enc: array[32, byte]
feToBytes(enc, x_aff)
echo "\nAffine x = ", bytesHex(enc)
feToBytes(enc, y_aff)
echo "Affine y = ", bytesHex(enc)

# Also check: x = X/T, y = Y/T
var x_aff2, y_aff2: Fe
feDiv(x_aff2, p1p1.x, p1p1.t)
feDiv(y_aff2, p1p1.y, p1p1.t)
feToBytes(enc, x_aff2)
echo "\nAffine x (X/T) = ", bytesHex(enc)
feToBytes(enc, y_aff2)
echo "Affine y (Y/T) = ", bytesHex(enc)

# Expected [2]B
echo "\nExpected [2]B = 7e004a879a4cd3b68d3707516756e1d627b8da140ff421599230db4cce9e6d33"
