import src/sello/field

# Test: is u/v a perfect square?
# If x^2 = u/v, then for non-square u/v, we need x^2 = sqrt(-1) * u/v

var y: Fe
var yBytes: array[32, byte]
for i in 0..31:
  if i == 0:
    yBytes[i] = 0x58
  else:
    yBytes[i] = 0x66
y = feFromBytes(yBytes)

var y2: Fe
feSq(y2, y)
var u: Fe
feSub(u, y2, FeOne)

var d: Fe
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

var vInv: Fe
feInvert(vInv, v)
var uvInv: Fe
feMul(uvInv, u, vInv)

# Check legendre symbol: (u/v)^((p-1)/2)
# For p = 2^255-19, (p-1)/2 = 2^254 - 10
var legendre: Fe
fePow22523(legendre, uvInv)
feSq(legendre, legendre)
feSq(legendre, legendre)  # Now legendre = (u/v)^(2 * ((p-5)/8) * 4) = (u/v)^((p-5)/8 * 2)
# Actually let's compute it properly

# Simpler: compute legendre = (u/v)^((p-1)/2)
# (p-1)/2 = (2^255-20)/2 = 2^254 - 10
# fePow22523 gives a^((p-5)/8) = a^(2^252-3)
# So (a^((p-5)/8))^4 = a^(4 * 2^252 - 12) = a^(2^254 - 12) = a^((p-1)/2 - 2)
# So legendre(a) = (a^((p-5)/8))^4 * a^2

var pow: Fe
fePow22523(pow, uvInv)
var pow2: Fe
feSq(pow2, pow)
var pow4: Fe
feSq(pow4, pow2)
var result: Fe
feMul(result, pow4, uvInv)
feMul(result, result, uvInv)
# result = pow^4 * a^2 = a^((p-5)/8 * 4 + 2) = a^(2^254 - 12 + 2) = a^(2^254 - 10) = a^((p-1)/2)

echo "Legendre symbol bytes: ", feToBytes(result)
# Legendre should be 1 (square) or -1 (non-square) or 0 (zero)

# If non-square, multiply by sqrt(-1)
var sqrtM1: Fe
sqrtM1.limbs = [-32595792'i32, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686, 11406482]

# Check: sqrtM1^((p-1)/2) should be -1
var sm1Legendre: Fe
fePow22523(sm1Legendre, sqrtM1)
feSq(sm1Legendre, sm1Legendre)
feSq(sm1Legendre, sm1Legendre)
feMul(sm1Legendre, sm1Legendre, sqrtM1)
feMul(sm1Legendre, sm1Legendre, sqrtM1)
echo "sqtM1 Legendre bytes: ", feToBytes(sm1Legendre)

