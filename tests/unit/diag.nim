import std/options
import sello/ed25519, sello/field, sello/scalar

# --- Test 1: pointDecode round-trip for the known public key
let pk: array[32, byte] = [
  0xd7'u8, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
  0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
  0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
  0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
]
let decoded = pointDecode(pk)
if not decoded.isSome:
  echo "FAIL: pointDecode(pk) returned None"
  quit(1)
let reEncoded = pointEncode(decoded.get)
if reEncoded != pk:
  echo "FAIL: pointEncode(pointDecode(pk)) != pk"
  for i in 0..<32: echo "  byte ", i, ": got ", reEncoded[i], " expected ", pk[i]
  quit(1)
echo "OK: pointDecode/pointEncode round-trip"

# --- Test 2: scalar mul 1*B == B
var basepoint: GeP3
basepoint.x.limbs = Ed25519Gx_Raw
basepoint.y.limbs = Ed25519Gy_Raw
basepoint.z = FeOne
feMul(basepoint.t, basepoint.x, basepoint.y)

let bpEncoded = pointEncode(basepoint)
echo "basepoint encoded: ", bpEncoded

var oneScalar: array[32, byte]
oneScalar[0] = 1
var result: GeP3
scalarmult(result, oneScalar, basepoint)
let resEncoded = pointEncode(result)
echo "1*B encoded:       ", resEncoded

if bpEncoded != resEncoded:
  echo "FAIL: 1*B != B"
  for i in 0..<32: echo "  byte ", i, ": got ", resEncoded[i], " expected ", bpEncoded[i]
  quit(1)
echo "OK: 1*B == B"

# --- Test 3: scalar mul 2*B
var twoScalar: array[32, byte]
twoScalar[0] = 2
var res2: GeP3
scalarmult(res2, twoScalar, basepoint)
let res2Encoded = pointEncode(res2)
echo "2*B encoded:       ", res2Encoded

# Check 2*B == B+B via group addition
var cachedB: GeCached
geP3ToCached(cachedB, basepoint)
var sumP: GeP1P1
geAdd(sumP, basepoint, cachedB)
var res2add: GeP3
geP1P1ToP3(res2add, sumP)
let res2addEncoded = pointEncode(res2add)
echo "B+B encoded:       ", res2addEncoded

if res2Encoded != res2addEncoded:
  echo "FAIL: 2*B != B+B"
  for i in 0..<32: echo "  byte ", i, ": got ", res2Encoded[i], " expected ", res2addEncoded[i]
  quit(1)
echo "OK: 2*B == B+B"

# --- Test 4: SHA-512 check
import nimcrypto/sha2
var sha: sha512
sha.init()
var k64: array[64, byte]
sha.finish(k64)
echo "SHA-512(empty):    ", k64

# Expected SHA-512 of empty string:
# cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce
# 47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
let expected: array[64, byte] = [
  0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
  0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
  0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
  0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
  0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
  0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
  0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
  0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e
]
if k64 != expected:
  echo "FAIL: SHA-512 of empty string is wrong"
  for i in 0..<64: echo "  byte ", i, ": got ", k64[i], " expected ", expected[i]
  quit(1)
echo "OK: SHA-512 of empty string correct"

# --- Test 5: scReduce basic check
# Reduce the SHA-512(empty) modulo L, check result < L
var hRed: array[32, byte]
scReduce(hRed, k64)
echo "scReduce(SHA512(empty)) = ", hRed
echo "  top byte: ", hRed[31], " (< 16 = 0x10)"

# scIsCanonical
echo "scIsCanonical = ", scIsCanonical(hRed)

# Now let's manually step through verify for test vector 1
echo ""
echo "=== Full verify trace for test vector 1 ==="

let tv1_sig: array[64, byte] = [
  0xe5'u8, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72,
  0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
  0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
  0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
  0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac,
  0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
  0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
  0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b
]

# Decode R
var rArr: array[32, byte]
for i in 0..<32: rArr[i] = tv1_sig[i]
let Ropt = pointDecode(rArr)
if not Ropt.isSome:
  echo "FAIL: R cannot be decoded"
  quit(1)
let R = Ropt.get
echo "R decoded OK"
echo "  re-encoded: ", pointEncode(R)

# Decode A
let Aopt = pointDecode(pk)
if not Aopt.isSome:
  echo "FAIL: A cannot be decoded"
  quit(1)
let A = Aopt.get
echo "A decoded OK"

# S
var sArr: array[32, byte]
for i in 0..<32: sArr[i] = tv1_sig[32 + i]
echo "S = ", sArr
echo "S canonical = ", scIsCanonical(sArr)

# k = SHA-512(R || PK || empty_msg) mod L
var sha2ctx: sha512
sha2ctx.init()
sha2ctx.update(cast[ptr byte](unsafeAddr rArr[0]), 32'u)
sha2ctx.update(cast[ptr byte](unsafeAddr pk[0]), 32'u)
var k64b: array[64, byte]
sha2ctx.finish(k64b)
echo "k_full = SHA-512(R||PK) = ", k64b

var kRed2: array[32, byte]
scReduce(kRed2, k64b)
echo "k = k_full mod L = ", kRed2

# [S]B
var SB: GeP3
scalarmult(SB, sArr, basepoint)
let sbEnc = pointEncode(SB)
echo "[S]B = ", sbEnc

# [k]A
var kA: GeP3
scalarmult(kA, kRed2, A)
let kaEnc = pointEncode(kA)
echo "[k]A = ", kaEnc

# R + [k]A
var cachedR2: GeCached
geP3ToCached(cachedR2, R)
var sum2: GeP1P1
geAdd(sum2, kA, cachedR2)
var rhs: GeP3
geP1P1ToP3(rhs, sum2)
let rhsEnc = pointEncode(rhs)
echo "R+[k]A = ", rhsEnc

if sbEnc == rhsEnc:
  echo "PASS: signature verifies!"
else:
  echo "FAIL: [S]B != R+[k]A"
  echo "  [S]B   = ", sbEnc
  echo "  R+[k]A = ", rhsEnc
  echo ""
  echo "  Verifying B encodes correctly:"
  echo "  B = ", bpEncoded