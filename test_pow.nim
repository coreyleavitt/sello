import src/sello/field

# Test fePow22523 with known values
var a: Fe
a = FeOne

var result: Fe
fePow22523(result, a)

echo "1^((p-5)/8) = ", feToBytes(result)
echo "Expected: all zeros except first byte = 1"

var b: Fe
# b = 2
b.limbs[0] = 2

var result2: Fe
fePow22523(result2, b)

var bBytes = feToBytes(result2)
echo "2^((p-5)/8) first few bytes: ", bBytes[0], " ", bBytes[1], " ", bBytes[2]

# Now test the actual formula: x = (u*v^7)^((p-5)/8) * u * v^3
# For the basepoint, we know y and can compute what x should be

var y: Fe
# Basepoint y = 4/5 mod p (from RFC)
# We need to decode this properly
var yBytes: array[32, byte]
# The basepoint y-coordinate in hex (little-endian):
# 5866666666666666666666666666666666666666666666666666666666666666
for i in 0..31:
  if i == 0:
    yBytes[i] = 0x58
  else:
    yBytes[i] = 0x66

y = feFromBytes(yBytes)

# Compute u = y^2 - 1
var y2: Fe
feSq(y2, y)
var u: Fe
feSub(u, y2, FeOne)

# Compute v = d*y^2 + 1
var d: Fe
# d = -121665/121666 mod p
d.limbs[0] = -10913610
d.limbs[1] = 13857413
d.limbs[2] = -15372611
d.limbs[3] = 6949391
d.limbs[4] = 114729
d.limbs[5] = -8797816
d.limbs[6] = -6277180
d.limbs[7] = -3248513
d.limbs[8] = -1231616
d.limbs[9] = 7682783

var dy2: Fe
feMul(dy2, d, y2)
var v: Fe
feAdd(v, dy2, FeOne)

# Compute v^7
var v2, v3, v4, v5, v6, v7: Fe
feSq(v2, v)
feMul(v3, v2, v)
feSq(v4, v2)
feMul(v5, v4, v)
feMul(v6, v5, v)
feMul(v7, v6, v)

# Compute u*v^7
var uv7: Fe
feMul(uv7, u, v7)

# Compute (u*v^7)^((p-5)/8)
var pow: Fe
fePow22523(pow, uv7)

# Compute x = pow * u * v^3
var vu3: Fe
feMul(vu3, v3, u)
var x: Fe
feMul(x, pow, vu3)

echo "Recovered x first few bytes: "
var xBytes = feToBytes(x)
for i in 0..3:
  stdout.write($xBytes[i] & " ")
echo ""

# Verify: x^2 should equal u/v or (u/v)*(-1)
var x2: Fe
feSq(x2, x)
var vInv: Fe
feInvert(vInv, v)
var uvInv: Fe
feMul(uvInv, u, vInv)

var diff: Fe
feSub(diff, x2, uvInv)
echo "x^2 - u/v is zero? ", not feIsNonZero(diff)

var negUvInv: Fe
feNeg(negUvInv, uvInv)
feSub(diff, x2, negUvInv)
echo "x^2 - (-u/v) is zero? ", not feIsNonZero(diff)
