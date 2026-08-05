import std/strutils
import sello/field

proc bytesHex(a: openArray[byte]): string =
  var s = ""
  for b in a: s.add b.toHex(2).toLowerAscii
  s

proc printFe(name: string; f: Fe) =
  echo name, " = ", bytesHex(feToBytes(f))
  echo name, " limbs: ", f.limbs

# These are the exact E and F values from the successful Python computation.
# E (LE bytes) = c576df96ce2a7ab7d54b45dd017ec283f48daf92393aa99b95d92d5e3f7c1d1e
# F (LE bytes) = ff945fc8143d7361bdcabf153afbbc0042f5faab88a2e354ad1ec46d9944f44f
let eBytes: array[32, byte] = [
  0xc5'u8, 0x76, 0xdf, 0x96, 0xce, 0x2a, 0x7a, 0xb7,
  0xd5, 0x4b, 0x45, 0xdd, 0x01, 0x7e, 0xc2, 0x83,
  0xf4, 0x8d, 0xaf, 0x92, 0x39, 0x3a, 0xa9, 0x9b,
  0x95, 0xd9, 0x2d, 0x5e, 0x3f, 0x7c, 0x1d, 0x1e
]
let fBytes: array[32, byte] = [
  0xff'u8, 0x94, 0x5f, 0xc8, 0x14, 0x3d, 0x73, 0x61,
  0xbd, 0xca, 0xbf, 0x15, 0x3a, 0xfb, 0xbc, 0x00,
  0x42, 0xf5, 0xfa, 0xab, 0x88, 0xa2, 0xe3, 0x54,
  0xad, 0x1e, 0xc4, 0x6d, 0x99, 0x44, 0xf4, 0x4f
]

var E = feFromBytes(eBytes)
var F = feFromBytes(fBytes)

echo "E roundtrip: ", bytesHex(feToBytes(E)) == bytesHex(eBytes)
echo "F roundtrip: ", bytesHex(feToBytes(F)) == bytesHex(fBytes)

var X3: Fe
feMul(X3, E, F)
printFe("E*F (Nim)", X3)

# Python says E*F mod p should be:
# X3 = 0x3b6f8891960f6ad45776d1e1213c1bd9de44f888163a76921515e6cf9f3fd67e
# LE bytes:
let expectedX3: array[32, byte] = [
  0x7e'u8, 0xd6, 0x3f, 0x9f, 0xcf, 0xe6, 0x15, 0x15,
  0x92, 0x76, 0x3a, 0x16, 0x88, 0xf8, 0x44, 0xde,
  0xd9, 0x1b, 0x3c, 0x21, 0xe1, 0xd1, 0x76, 0x57,
  0xd4, 0x6a, 0x0f, 0x96, 0x91, 0x88, 0x6f, 0x3b
]
echo "\nExpected E*F = ", bytesHex(expectedX3)
echo "Nim E*F      = ", bytesHex(feToBytes(X3))
echo "Match: ", bytesHex(expectedX3) == bytesHex(feToBytes(X3))

# Also test with simpler known values
var two: Fe; two.limbs[0] = 2
var three: Fe; three.limbs[0] = 3
var six: Fe
feMul(six, two, three)
echo "\n2*3 = ", feToBytes(six)[0]  # should be 6

# Test with larger values
var a: Fe; a.limbs = [1000000'i32, 2000000, 3000000, 4000000, 5000000,
                       6000000, 7000000, 8000000, 9000000, 10000000]
var b: Fe; b.limbs = [1100000'i32, 2100000, 3100000, 4100000, 5100000,
                       6100000, 7100000, 8100000, 9100000, 11100000]
var ab: Fe
feMul(ab, a, b)
var ba: Fe
feMul(ba, b, a)
echo "Commutative: ", bytesHex(feToBytes(ab)) == bytesHex(feToBytes(ba))

# Compare with Python result
# Python: a_val * b_val mod p
# a_val = sum(a_limbs[i] * 2^shift[i])
# ... let's just verify the roundtrip
