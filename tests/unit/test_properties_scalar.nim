## Property-based coverage for sello/scalar (RFC-001 finding 10).
##
## See test_properties_field.nim's module doc comment for the proptest
## wiring notes (optional milpa dep, z3-avoidance, canonical-encoding
## comparison discipline) -- not repeated here.
##
## recodeScalarRadix16 reconstruction is checked with a tiny, purpose-built
## unsigned bignum (see `BigNum`/`addShifted`/`toBigNum` below) built from
## nothing but `uint32` limb addition with carry propagation -- deliberately
## NOT reusing any of sello's own field/scalar arithmetic, so this property
## is a genuine EC-independent oracle rather than the recoding checking
## itself against its own codebase.

import std/unittest
import proptest
import sello/field
import sello/scalar

proc randByte(): Strategy[byte] =
  integers(0, 255).map(proc(x: int): byte = byte(x))

proc scalar32(): Strategy[array[32, byte]] =
  arrays[32, byte](randByte())

proc scalar64(): Strategy[array[64, byte]] =
  arrays[64, byte](randByte())

proc bit255Clear(): Strategy[array[32, byte]] =
  scalar32().map(proc(s: array[32, byte]): array[32, byte] =
    result = s
    result[31] = result[31] and 0x7F'u8)

proc reducedScalar(): Strategy[array[32, byte]] =
  ## A scReduce-shaped value: draw 64 random bytes and reduce, so the
  ## distribution matches what a real nonce r = scReduce(SHA-512(...))
  ## looks like (always < L).
  scalar64().map(proc(wide: array[64, byte]): array[32, byte] =
    scReduce(result, wide))

proc covSettings(): Settings =
  ## RFC-002 slice 3 item 3: `Settings.coverageGuided` enabled for the
  ## property suites -- see test_properties_field.nim's `covSettings`
  ## doc comment for the full rationale (not repeated here).
  result = defaultSettings()
  result.coverageGuided = true

# ---------------------------------------------------------------------------
# scReduce: idempotence, boundary inputs, output always canonical (< L).
# ---------------------------------------------------------------------------

suite "scalar property: scReduce":
  property "scReduce output is always canonical (< L)":
    with covSettings()
    given wide in scalar64()
    var reduced: array[32, byte]
    scReduce(reduced, wide)
    ensure scIsCanonical(reduced)

  property "scReduce is idempotent: reduce(zero-extend(reduce(x))) == reduce(x)":
    with covSettings()
    given wide in scalar64()
    var r1: array[32, byte]
    scReduce(r1, wide)
    var extended: array[64, byte]
    for i in 0 ..< 32: extended[i] = r1[i]
    var r2: array[32, byte]
    scReduce(r2, extended)
    ensure r1 == r2

  test "boundary: scReduce(0) == 0":
    var input: array[64, byte]
    var output: array[32, byte]
    scReduce(output, input)
    var zero: array[32, byte]
    check output == zero

  test "boundary: scReduce(zero-extend(L-1)) == L-1 (already canonical, no-op)":
    var input: array[64, byte]
    for i in 0 ..< 32: input[i] = L[i]
    input[0] -= 1  # L - 1
    var expected: array[32, byte]
    for i in 0 ..< 32: expected[i] = input[i]
    var output: array[32, byte]
    scReduce(output, input)
    check output == expected

  test "boundary: scReduce(zero-extend(L)) == 0":
    var input: array[64, byte]
    for i in 0 ..< 32: input[i] = L[i]
    var output: array[32, byte]
    scReduce(output, input)
    var zero: array[32, byte]
    check output == zero

  test "boundary: scReduce(zero-extend(L+1)) == 1":
    var input: array[64, byte]
    for i in 0 ..< 32: input[i] = L[i]
    input[0] += 1  # L + 1 (no carry: L's low byte is 0xED)
    var output: array[32, byte]
    scReduce(output, input)
    var one: array[32, byte]
    one[0] = 1
    check output == one

  test "boundary: scReduce(2^512-1) is canonical":
    var input: array[64, byte]
    for i in 0 ..< 64: input[i] = 0xFF'u8
    var output: array[32, byte]
    scReduce(output, input)
    check scIsCanonical(output)

suite "scIsCanonical (pinned)":
  test "L-1 is canonical":
    var lMinus1: array[32, byte] = L
    lMinus1[0] -= 1
    check scIsCanonical(lMinus1)

  test "L itself is not canonical":
    check not scIsCanonical(L)

# ---------------------------------------------------------------------------
# recodeScalarRadix16 reconstruction: sum(digits[i] * 16^i) == s, checked
# with an independent tiny bignum (unsigned uint32 limbs, carry-propagating
# add only -- no subtraction, so no borrow logic to get wrong). Positive and
# negative digit contributions are accumulated into separate unsigned
# accumulators `pos`/`neg` and compared via `pos == neg + s`, avoiding
# signed bignum subtraction entirely.
# ---------------------------------------------------------------------------

type BigNum = array[10, uint32]  # 320 bits -- comfortable headroom over the
                                 # ~2^255-ish magnitudes this file adds.

proc addShifted(acc: var BigNum; digit: uint32; bitOffset: int) =
  ## acc += digit << bitOffset, ripple-carried across 32-bit limbs.
  if digit == 0: return
  var limbIdx = bitOffset div 32
  let bitInLimb = bitOffset mod 32
  var carry: uint64 = uint64(digit) shl bitInLimb
  while carry != 0:
    doAssert limbIdx < acc.len, "BigNum overflow -- widen BigNum"
    let s = uint64(acc[limbIdx]) + (carry and 0xFFFFFFFF'u64)
    acc[limbIdx] = uint32(s and 0xFFFFFFFF'u64)
    carry = (carry shr 32) + (s shr 32)
    inc limbIdx

proc bigAdd(acc: var BigNum; other: BigNum) =
  var carry: uint64 = 0
  for i in 0 ..< acc.len:
    let s = uint64(acc[i]) + uint64(other[i]) + carry
    acc[i] = uint32(s and 0xFFFFFFFF'u64)
    carry = s shr 32
  doAssert carry == 0, "BigNum overflow in bigAdd -- widen BigNum"

proc toBigNum(s: array[32, byte]): BigNum =
  for i in 0 ..< 8:
    result[i] = uint32(s[4 * i]) or (uint32(s[4 * i + 1]) shl 8) or
                (uint32(s[4 * i + 2]) shl 16) or (uint32(s[4 * i + 3]) shl 24)

proc reconstructsTo(s: array[32, byte]): bool =
  let digits = recodeScalarRadix16(s)
  var pos, neg: BigNum
  for i in 0 ..< 64:
    let d = digits[i]
    if d >= 0:
      addShifted(pos, uint32(d), 4 * i)
    else:
      addShifted(neg, uint32(-d), 4 * i)
  bigAdd(neg, toBigNum(s))
  pos == neg

suite "scalar property: recodeScalarRadix16 reconstruction":
  property "sum(digits[i] * 16^i) == s, for random bit-255-clear scalars":
    with covSettings()
    given s in bit255Clear()
    ensure reconstructsTo(s)

  property "sum(digits[i] * 16^i) == s, for random reduced-mod-L scalars":
    with covSettings()
    given s in reducedScalar()
    ensure reconstructsTo(s)

# ---------------------------------------------------------------------------
# Group-law identity properties. Generalizes the fixed-sample standing
# guard in test_scalar.nim's "geScalarmultBase" suite from a counter-mode
# PRNG to a shrinking proptest strategy, over both scalar domains
# geScalarmultBase actually serves (clamped and reduced-mod-L).
# ---------------------------------------------------------------------------

proc clampedScalar(): Strategy[array[32, byte]] =
  scalar32().map(proc(s: array[32, byte]): array[32, byte] =
    result = s
    clampScalar(result))

proc refBaseMultEncoded(s: array[32, byte]): array[32, byte] =
  var p: GeP3
  scalarmultVartime(p, s, geBasePoint())
  pointEncode(p)

proc settingsWithExamples(n: int): Settings =
  ## `defaultSettings()` (fixed seed 0x1234567890abcdef, so runs stay
  ## reproducible without a committed example DB) with `maxExamples`
  ## dialed down for the costlier elliptic-curve properties in this
  ## suite -- keeps the added wall time bounded without disabling the
  ## engine's other defaults (shrinking, autoLabels, etc.). Also flips
  ## `coverageGuided` on (RFC-002 slice 3 item 3 -- see `covSettings`'s
  ## doc comment above).
  result = defaultSettings()
  result.maxExamples = n
  result.coverageGuided = true

let propertySettings50 = settingsWithExamples(50)

suite "scalar property: geScalarmultBase vs scalarmultVartime agreement":
  property "clamped domain: geScalarmultBase(s) == [s]B (scalarmultVartime)":
    with propertySettings50
    given s in clampedScalar()
    ensure pointEncode(geScalarmultBase(s)) == refBaseMultEncoded(s)

  property "reduced-mod-L domain: geScalarmultBase(s) == [s]B (scalarmultVartime)":
    with propertySettings50
    given s in reducedScalar()
    ensure pointEncode(geScalarmultBase(s)) == refBaseMultEncoded(s)

suite "scalar property: geScalarmultBase is additive over scMulAdd":
  # a + b mod L is computed via the already-audited scMulAdd(a, 1, b) =
  # a*1 + b mod L -- reusing one audited primitive instead of hand-rolling
  # a second scalar-add. Point addition on the right-hand side goes
  # through geAdd/geP3ToCached (the same group-addition core
  # geScalarmultBase itself is built from), compared via canonical
  # pointEncode. NOTE: a `##` doc comment as the first line of a
  # `property` body confuses the DSL macro's `with`/`given` detection (it
  # becomes body[0] instead of the `with` statement) -- this note lives
  # above the property instead, as a plain `#` comment on the suite.
  property "geScalarmultBase(a + b mod L) == geScalarmultBase(a) + geScalarmultBase(b)":
    with propertySettings50
    given a in reducedScalar(), b in reducedScalar()
    var one: array[32, byte]
    one[0] = 1
    let aPlusB = scMulAdd(a, one, b)
    let lhs = geScalarmultBase(aPlusB)
    let pa = geScalarmultBase(a)
    let pb = geScalarmultBase(b)
    var cachedPb: GeCached
    geP3ToCached(cachedPb, pb)
    var sum: GeP1P1
    geAdd(sum, pa, cachedPb)
    var rhs: GeP3
    geP1P1ToP3(rhs, sum)
    ensure pointEncode(lhs) == pointEncode(rhs)
