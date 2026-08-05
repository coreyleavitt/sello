import std/options
import sello/field, sello/scalar

# Test the square root function with a known value
# Let's compute x^2 for a known x, then try to recover x using fePow22523

let xBytes: array[32, byte] = [
  0x05'u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
]

let x = feFromBytes(xBytes)
echo "Original x: ", feToBytes(x)

# Compute x^2
var x2: Fe
feSq(x2, x)
echo "x^2: ", feToBytes(x2)

# Now try to recover x using the formula from pointDecode
# For p ≡ 5 (mod 8), if x^2 is a quadratic residue, then:
# x = (x^2)^((p+3)/8) mod p

# (p+3)/8 = (2^255 - 19 + 3)/8 = (2^255 - 16)/8 = 2^252 - 2
var exp: Fe
exp = x2
echo "Testing fePow22523 on x^2:"
var root: Fe
fePow22523(root, x2)
echo "Recovered root: ", feToBytes(root)

# Check if root^2 == x^2
var recoveredX2: Fe
feSq(recoveredX2, root)
echo "root^2: ", feToBytes(recoveredX2)

# Actually, fePow22523 computes a^((p-5)/8), not a^((p+3)/8)
# (p-5)/8 = (2^255 - 24)/8 = 2^252 - 3
# For quadratic residues, (x^2)^((p-5)/8) = x^(p-5)/4 = x^((p-1)/2 - 1) = x^(-1) = 1/x
# So we need to multiply by the original value to get x

echo ""
echo "Trying the correct formula from pointDecode:"
# From pointDecode: x = u*v^3 * (u*v^7)^((p-5)/8)
# Let's trace through a simple case where u=1, v=1 (so we're just computing 1^((p-5)/8))
var u_simple: Fe
u_simple = FeOne
var v_simple: Fe
v_simple = FeOne

var v3_simple: Fe
feSq(v3_simple, v_simple)
feMul(v3_simple, v3_simple, v_simple)
echo "v^3: ", feToBytes(v3_simple)

var uv3_simple: Fe
feMul(uv3_simple, v3_simple, u_simple)
var uv7_simple: Fe
feMul(uv7_simple, uv3_simple, v3_simple)
feMul(uv7_simple, uv7_simple, v_simple)
echo "u*v^7: ", feToBytes(uv7_simple)

var pow_simple: Fe
fePow22523(pow_simple, uv7_simple)
echo "(u*v^7)^((p-5)/8): ", feToBytes(pow_simple)

var x_simple: Fe
feMul(x_simple, pow_simple, uv3_simple)
echo "x = uv^3 * (uv^7)^((p-5)/8): ", feToBytes(x_simple)

# Now let's test with the basepoint
echo ""
echo "=== Testing with basepoint ==="
let basepointY: array[32, byte] = [0x58'u8, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                                    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                                    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                                    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66]
let y = feFromBytes(basepointY)
var D: Fe
D.limbs = [
    -10913610'i32, 13857413, -15372611, 6949391, 114729,
    -8797816, -6277180, -3248513, -1231616, 7682783
]

# u = y^2 - 1
var u: Fe
feSq(u, y)
feSub(u, u, FeOne)
echo "u = y^2-1: ", feToBytes(u)

# v = d*y^2 + 1
var dy2: Fe
feMul(dy2, D, y)
feMul(dy2, dy2, y)
var v: Fe
feAdd(v, dy2, FeOne)
echo "v = dy^2+1: ", feToBytes(v)

# v^3
var v3: Fe
feSq(v3, v)
feMul(v3, v3, v)
echo "v^3: ", feToBytes(v3)

# u*v^3
var uv3: Fe
feMul(uv3, v3, u)

# u*v^7
var uv7: Fe
feMul(uv7, uv3, v3)
feMul(uv7, uv7, v)
echo "uv^7: ", feToBytes(uv7)

# (uv^7)^((p-5)/8)
var pow: Fe
fePow22523(pow, uv7)
echo "(uv^7)^((p-5)/8): ", feToBytes(pow)

# x = u*v^3 * (uv^7)^((p-5)/8)
var bx: Fe
feMul(bx, pow, uv3)
echo "x = uv^3 * (uv^7)^((p-5)/8): ", feToBytes(bx)

# Check: v*x^2 should equal u (or -u)
var vxx2: Fe
feSq(vxx2, bx)
feMul(vxx2, vxx2, v)
var check1: Fe
feSub(check1, vxx2, u)
echo "v*x^2 - u: ", feToBytes(check1)
let isZero1 = not feIsNonZero(check1)
echo "Is zero? ", isZero1

# If not zero, try multiplying x by sqrt(-1)
var sqrtM1: Fe
sqrtM1.limbs = [
    -32595792'i32, -7943725, 9377950, 3500415, 12389472,
    -272473, -25146209, -2005654, 326686, 11406482
]
if feIsNonZero(check1):
  echo ""
  echo "v*x^2 != u, trying x * sqrt(-1)"
  var bx2: Fe
  feMul(bx2, bx, sqrtM1)
  var vxx3: Fe
  feSq(vxx3, bx2)
  feMul(vxx3, vxx3, v)
  var check2: Fe
  feSub(check2, vxx3, u)
  echo "v*(x*sqrt(-1))^2 - u: ", feToBytes(check2)
  echo "Is zero? ", not feIsNonZero(check2)