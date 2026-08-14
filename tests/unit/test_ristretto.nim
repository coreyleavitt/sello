import std/[unittest, options, strutils, os, osproc]
import sello/ristretto
import sello/scalar
import sello/field

proc hexToArray32(s: string): array[32, byte] =
  doAssert s.len == 64
  for i in 0 ..< 32:
    result[i] = byte(parseHexInt(s[2 * i .. 2 * i + 1]))

proc scalarFromSmallInt(i: int): array[32, byte] =
  ## Little-endian 32-byte scalar for i in 0..15 -- fits in the low byte,
  ## bit 255 clear (recodeScalarRadix16's precondition) trivially.
  doAssert i >= 0 and i <= 255
  result[0] = byte(i)

# ---------------------------------------------------------------------------
# RFC 9496 Appendix A.1 -- encodings of the multiples 0..15 of the canonical
# generator. A1Encodings[i] decodes to i*B.
# ---------------------------------------------------------------------------

const A1Encodings: array[16, string] = [
  "0000000000000000000000000000000000000000000000000000000000000000",
  "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
  "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
  "94741f5d5d52755ece4f23f044ee27d5d1ea1e2bd196b462166b16152a9d0259",
  "da80862773358b466ffadfe0b3293ab3d9fd53c5ea6c955358f568322daf6a57",
  "e882b131016b52c1d3337080187cf768423efccbb517bb495ab812c4160ff44e",
  "f64746d3c92b13050ed8d80236a7f0007c3b3f962f5ba793d19a601ebb1df403",
  "44f53520926ec81fbd5a387845beb7df85a96a24ece18738bdcfa6a7822a176d",
  "903293d8f2287ebe10e2374dc1a53e0bc887e592699f02d077d5263cdd55601c",
  "02622ace8f7303a31cafc63f8fc48fdc16e1c8c8d234b2f0d6685282a9076031",
  "20706fd788b2720a1ed2a5dad4952b01f413bcf0e7564de8cdc816689e2db95f",
  "bce83f8ba5dd2fa572864c24ba1810f9522bc6004afe95877ac73241cafdab42",
  "e4549ee16b9aa03099ca208c67adafcafa4c3f3e4e5303de6026e3ca8ff84460",
  "aa52e000df2e16f55fb1032fc33bc42742dad6bd5a8fc0be0167436c5948501f",
  "46376b80f409b29dc2b5f6f0c52591990896e5716f41477cd30085ab7f10301e",
  "e0c418f7c8d9c4cdd7395b93ea124f3ad99021bb681dfc3302a9d99a2e53e64e",
]

# ---------------------------------------------------------------------------
# RFC 9496 Appendix A.2 -- invalid encodings that MUST be rejected by
# ristrettoDecode. Every category listed in the spec, transcribed verbatim.
# ---------------------------------------------------------------------------

const A2NonCanonical: array[4, string] = [
  "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
]

const A2NegativeFieldElements: array[8, string] = [
  "0100000000000000000000000000000000000000000000000000000000000000",
  "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "ed57ffd8c914fb201471d1c3d245ce3c746fcbe63a3679d51b6a516ebebe0e20",
  "c34c4e1826e5d403b78e246e88aa051c36ccf0aafebffe137d148a2bf9104562",
  "c940e5a4404157cfb1628b108db051a8d439e1a421394ec4ebccb9ec92a8ac78",
  "47cfc5497c53dc8e61c91d17fd626ffb1c49e2bca94eed052281b510b1117a24",
  "f1c6165d33367351b0da8f6e4511010c68174a03b6581212c71c0e1d026c3c72",
  "87260f7a2f12495118360f02c26a470f450dadf34a413d21042b43b9d93e1309",
]

const A2NonSquareXSq: array[8, string] = [
  "26948d35ca62e643e26a83177332e6b6afeb9d08e4268b650f1f5bbd8d81d371",
  "4eac077a713c57b4f4397629a4145982c661f48044dd3f96427d40b147d9742f",
  "de6a7b00deadc788eb6b6c8d20c0ae96c2f2019078fa604fee5b87d6e989ad7b",
  "bcab477be20861e01e4a0e295284146a510150d9817763caf1a6f4b422d67042",
  "2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08",
  "f4a9e534fc0d216c44b218fa0c42d99635a0127ee2e53c712f70609649fdff22",
  "8268436f8c4126196cf64b3c7ddbda90746a378625f9813dd9b8457077256731",
  "2810e5cbc2cc4d4eece54f61c6f69758e289aa7ab440b3cbeaa21995c2f4232b",
]

const A2NegativeXY: array[8, string] = [
  "3eb858e78f5a7254d8c9731174a94f76755fd3941c0ac93735c07ba14579630e",
  "a45fdc55c76448c049a1ab33f17023edfb2be3581e9c7aade8a6125215e04220",
  "d483fe813c6ba647ebbfd3ec41adca1c6130c2beeee9d9bf065c8d151c5f396e",
  "8a2e1d30050198c65a54483123960ccc38aef6848e1ec8f5f780e8523769ba32",
  "32888462f8b486c68ad7dd9610be5192bbeaf3b443951ac1a8118419d9fa097b",
  "227142501b9d4355ccba290404bde41575b037693cef1f438c47f8fbf35d1165",
  "5c37cc491da847cfeb9281d407efc41e15144c876e0170b499a96a22ed31e01e",
  "445425117cb8c90edcbc7c1cc0e74f747f2c1efa5630a967c64f287792a48a4b",
]

const A2SMinusOneYZero: array[1, string] = [
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
]

suite "ristrettoDecode -- RFC 9496 Appendix A.1 (valid encodings, correctness)":
  test "each A.1 encoding decodes successfully and equals the independently-computed i*B":
    for i in 0 ..< A1Encodings.len:
      let encoded = toRistrettoEncoded(hexToArray32(A1Encodings[i]))
      let decoded = ristrettoDecode(encoded)
      check decoded.isSome
      # Independent oracle: i*B via scalar.geScalarmultBase, wrapped through
      # the ristrettoUnchecked door -- not decode's own machinery, so a
      # self-consistent-but-wrong decoder would be caught here.
      let expected = ristrettoUnchecked(geScalarmultBase(toSecretScalar(scalarFromSmallInt(i))))
      check decoded.get() == expected

suite "ristrettoDecode -- RFC 9496 Appendix A.2 (invalid encodings, all categories)":
  test "non-canonical field encodings reject":
    for s in A2NonCanonical:
      check ristrettoDecode(toRistrettoEncoded(hexToArray32(s))).isNone

  test "negative field elements reject":
    for s in A2NegativeFieldElements:
      check ristrettoDecode(toRistrettoEncoded(hexToArray32(s))).isNone

  test "non-square x^2 rejects":
    for s in A2NonSquareXSq:
      check ristrettoDecode(toRistrettoEncoded(hexToArray32(s))).isNone

  test "negative x*y value rejects":
    for s in A2NegativeXY:
      check ristrettoDecode(toRistrettoEncoded(hexToArray32(s))).isNone

  test "s = -1 (causes y = 0) rejects":
    for s in A2SMinusOneYZero:
      check ristrettoDecode(toRistrettoEncoded(hexToArray32(s))).isNone

suite "RistrettoPoint -- quotient equality (RFC 9496 SS4.3.3)":
  test "reflexive: a decoded point equals itself":
    let p = ristrettoDecode(toRistrettoEncoded(hexToArray32(A1Encodings[7]))).get()
    check p == p

  test "distinct A.1 points are unequal":
    let p3 = ristrettoDecode(toRistrettoEncoded(hexToArray32(A1Encodings[3]))).get()
    let p5 = ristrettoDecode(toRistrettoEncoded(hexToArray32(A1Encodings[5]))).get()
    check not (p3 == p5)

  test "the same element, derived two different ways, compares equal":
    # decode(A1[9]) and geScalarmultBase(9) reach the same group element via
    # entirely different code paths (field-level decode dance vs. the
    # radix-16 fixed-base ladder) -- exactly the "two representations of one
    # element" case quotient equality exists for.
    let viaDecode = ristrettoDecode(toRistrettoEncoded(hexToArray32(A1Encodings[9]))).get()
    let viaScalarmult = ristrettoUnchecked(geScalarmultBase(toSecretScalar(scalarFromSmallInt(9))))
    check viaDecode == viaScalarmult

  test "identity equals identity, derived two different ways":
    let viaDecode = ristrettoDecode(toRistrettoEncoded(hexToArray32(A1Encodings[0]))).get()
    let viaScalarmult = ristrettoUnchecked(geScalarmultBase(toSecretScalar(scalarFromSmallInt(0))))
    check viaDecode == viaScalarmult

suite "ristrettoEncode -- RFC 9496 Appendix A.1 (encode direction)":
  test "encode(i*B) == A.1 encoding, for i in 0..15, incl. i=0 (identity -- exercises SQRT_RATIO_M1(1, 0)'s degenerate branch)":
    for i in 0 ..< A1Encodings.len:
      let point = ristrettoUnchecked(geScalarmultBase(toSecretScalar(scalarFromSmallInt(i))))
      let encoded = ristrettoEncode(point)
      check toBytes(encoded) == hexToArray32(A1Encodings[i])

suite "ristrettoEncode / ristrettoDecode -- round-trips over the A.1 set":
  test "decode(A.1[i]) |> encode == A.1[i]":
    for i in 0 ..< A1Encodings.len:
      let encoded = toRistrettoEncoded(hexToArray32(A1Encodings[i]))
      let decoded = ristrettoDecode(encoded)
      check decoded.isSome
      check ristrettoEncode(decoded.get()) == encoded

  test "encode(i*B) |> decode == i*B":
    for i in 0 ..< A1Encodings.len:
      let point = ristrettoUnchecked(geScalarmultBase(toSecretScalar(scalarFromSmallInt(i))))
      let decoded = ristrettoDecode(ristrettoEncode(point))
      check decoded.isSome
      check decoded.get() == point

suite "InvSqrtAMinusD -- defining equation (RFC 9496 SS4.1)":
  test "InvSqrtAMinusD^2 * (a - d) == 1, where a = -1 and d is the Edwards d parameter":
    # a = -1 (the twisted Edwards curve parameter for Curve25519/ristretto255)
    var a, d, aMinusD, invSq, product: Fe
    feNeg(a, FeOne)
    d = feFromLimbs(Ed25519D_Raw)
    feSub(aMinusD, a, d)
    feSq(invSq, InvSqrtAMinusD)
    feMul(product, invSq, aMinusD)
    check feEqualCT(product, FeOne)

suite "RistrettoIdentity / RistrettoBasePoint -- fixed compile-time consts":
  test "RistrettoIdentity encodes to the all-zero A.1[0] encoding":
    check toBytes(ristrettoEncode(RistrettoIdentity)) == hexToArray32(A1Encodings[0])

  test "RistrettoBasePoint encodes to the A.1[1] encoding (the canonical generator)":
    check toBytes(ristrettoEncode(RistrettoBasePoint)) == hexToArray32(A1Encodings[1])

  test "RistrettoIdentity equals the identity reached via geScalarmultBase(0)":
    let viaScalarmult = ristrettoUnchecked(geScalarmultBase(toSecretScalar(scalarFromSmallInt(0))))
    check RistrettoIdentity == viaScalarmult

  test "RistrettoBasePoint equals the generator reached via geScalarmultBase(1)":
    let viaScalarmult = ristrettoUnchecked(geScalarmultBase(toSecretScalar(scalarFromSmallInt(1))))
    check RistrettoBasePoint == viaScalarmult

suite "RistrettoPoint -- group operator + (RFC 9496 group ops, slice 4)":
  test "B + identity == B":
    let b = ristrettoDecode(toRistrettoEncoded(hexToArray32(A1Encodings[1]))).get()
    check (b + RistrettoIdentity) == b

  test "B + 2B == 3B":
    let b1 = ristrettoDecode(toRistrettoEncoded(hexToArray32(A1Encodings[1]))).get()
    let b2 = ristrettoDecode(toRistrettoEncoded(hexToArray32(A1Encodings[2]))).get()
    let b3 = ristrettoDecode(toRistrettoEncoded(hexToArray32(A1Encodings[3]))).get()
    check (b1 + b2) == b3

  test "associativity spot check over A.1 points: (1B + 2B) + 3B == 1B + (2B + 3B)":
    let b1 = ristrettoDecode(toRistrettoEncoded(hexToArray32(A1Encodings[1]))).get()
    let b2 = ristrettoDecode(toRistrettoEncoded(hexToArray32(A1Encodings[2]))).get()
    let b3 = ristrettoDecode(toRistrettoEncoded(hexToArray32(A1Encodings[3]))).get()
    check ((b1 + b2) + b3) == (b1 + (b2 + b3))

  test "associativity spot check over geScalarmultBase multiples: (5B + 7B) + 9B == 5B + (7B + 9B)":
    let b5 = ristrettoUnchecked(geScalarmultBase(toSecretScalar(scalarFromSmallInt(5))))
    let b7 = ristrettoUnchecked(geScalarmultBase(toSecretScalar(scalarFromSmallInt(7))))
    let b9 = ristrettoUnchecked(geScalarmultBase(toSecretScalar(scalarFromSmallInt(9))))
    check ((b5 + b7) + b9) == (b5 + (b7 + b9))

suite "RistrettoPoint -- unary/binary - (RFC 9496 group ops, slice 4)":
  test "P + (-P) == RistrettoIdentity":
    let b5 = ristrettoUnchecked(geScalarmultBase(toSecretScalar(scalarFromSmallInt(5))))
    check (b5 + (-b5)) == RistrettoIdentity

  test "-identity == identity":
    check (-RistrettoIdentity) == RistrettoIdentity

  test "binary minus consistent: a - b == a + (-b)":
    let b3 = ristrettoDecode(toRistrettoEncoded(hexToArray32(A1Encodings[3]))).get()
    let b5 = ristrettoDecode(toRistrettoEncoded(hexToArray32(A1Encodings[5]))).get()
    check (b3 - b5) == (b3 + (-b5))

  test "a - a == identity":
    let b7 = ristrettoUnchecked(geScalarmultBase(toSecretScalar(scalarFromSmallInt(7))))
    check (b7 - b7) == RistrettoIdentity

suite "RistrettoPoint -- E[4] torsion invariance (Stage-3 amendment: [2]E/E[4], not E/E[8])":
  # RFC 9496 amendment (docs/rfc-004-ristretto255.md "Stage-3 amendment
  # (2026-08-14)"): ristretto255 is the quotient [2]E/E[4] -- the four E[4]
  # points below (identity, (0,-1), (+-FeSqrtM1, 0)) are the ONLY Edwards
  # translates that preserve a RistrettoPoint's encoding. All four are
  # trivially/FeSqrtM1-expressible -- no offline derivation needed. This
  # suite is the deterministic plain-unittest torsion spot-check the RFC
  # calls for (quotient coverage that survives a proptest-less build); the
  # random-P analog lives in test_properties_ristretto.nim.
  var negOne, negSqrtM1: Fe
  feNeg(negOne, FeOne)
  feNeg(negSqrtM1, FeSqrtM1)

  # Built as raw GeP3 first (RistrettoPoint's underlying `p` field is
  # private to sello/ristretto, so the curve-equation cross-check below has
  # to run on these raw values before they are wrapped through the door).
  let rawZeroMinusOne = GeP3(x: FeZero, y: negOne, z: FeOne, t: FeZero)
  let rawPlusSqrtM1 = GeP3(x: FeSqrtM1, y: FeZero, z: FeOne, t: FeZero)
  let rawMinusSqrtM1 = GeP3(x: negSqrtM1, y: FeZero, z: FeOne, t: FeZero)

  template checkOnCurve(p: GeP3) =
    ## The extended-coordinate twisted Edwards curve equation,
    ## Y^2 - X^2 == Z^2 + d*T^2 -- the same equation `ristrettoUnchecked`'s
    ## own debug-only assert checks internally (see that proc's doc
    ## comment); pinned explicitly here too, in-test, per the task's
    ## defining-equation cross-check requirement.
    ##
    ## A TEMPLATE, deliberately, not a `proc`: `std/unittest`'s `check`
    ## resolves failures through `testStatusIMPL`, a symbol `{.inject.}`ed
    ## into a `test:` block's own lexical scope by the `test` template --
    ## a symbol that does NOT propagate into an ordinary `proc` called from
    ## within that block (procs do not inherit a caller's injected
    ## symbols the way nested templates do). A `proc` version of this
    ## helper was the first RED pass here: every `check` inside it still
    ## *ran*, but a failing one fell through `fail()`'s
    ## `when declared(testStatusIMPL): ... else: setProgramResult 1`
    ## fallback -- printing `[OK]` on the suite line regardless of the
    ## outcome, with the failure surfacing only as an unattributed nonzero
    ## process exit ("execution of an external program failed") rather
    ## than a `[FAILED]` line pointing at this check. Confirmed directly
    ## (deliberately-inverted `feEqualCT` call, `proc` form): all three
    ## call sites below kept printing `[OK]` while the process still
    ## exited 1 -- exactly the silent-misattribution failure mode this
    ## comment exists to prevent a future edit from reintroducing. As a
    ## `template`, the check's `testStatusIMPL` reference resolves in the
    ## CALLING test's own scope instead, and failures report correctly.
    var y2, x2, z2, dt2, lhs, rhs: Fe
    feSq(y2, p.y)
    feSq(x2, p.x)
    feSq(z2, p.z)
    feSq(dt2, p.t)
    feMul(dt2, dt2, feFromLimbs(Ed25519D_Raw))
    feSub(lhs, y2, x2)
    feAdd(rhs, z2, dt2)
    check feEqualCT(lhs, rhs)

  test "(0,-1) satisfies the twisted Edwards curve equation":
    checkOnCurve(rawZeroMinusOne)

  test "(+FeSqrtM1, 0) satisfies the twisted Edwards curve equation":
    checkOnCurve(rawPlusSqrtM1)

  test "(-FeSqrtM1, 0) satisfies the twisted Edwards curve equation":
    checkOnCurve(rawMinusSqrtM1)

  let e4ZeroMinusOne = ristrettoUnchecked(rawZeroMinusOne)
  let e4PlusSqrtM1 = ristrettoUnchecked(rawPlusSqrtM1)
  let e4MinusSqrtM1 = ristrettoUnchecked(rawMinusSqrtM1)
  let e4NonIdentityPoints = [e4ZeroMinusOne, e4PlusSqrtM1, e4MinusSqrtM1]
  let e4Points = [RistrettoIdentity, e4ZeroMinusOne, e4PlusSqrtM1, e4MinusSqrtM1]

  test "each non-identity E[4] point is annihilated by 4 (4T == RistrettoIdentity, via the module's own + and ==)":
    for t in e4NonIdentityPoints:
      let doubled = t + t
      let quadrupled = doubled + doubled
      check quadrupled == RistrettoIdentity

  test "P + T encodes equal to P, for two fixed points and all four E[4] T's":
    # The two fixed spot-check points named in the RFC: the canonical
    # generator and one other fixed decoded point (A1Encodings[7], already
    # used as a fixed fixture elsewhere in this file).
    let p1 = RistrettoBasePoint
    let p2 = ristrettoDecode(toRistrettoEncoded(hexToArray32(A1Encodings[7]))).get()
    for p in [p1, p2]:
      for t in e4Points:
        check toBytes(ristrettoEncode(p + t)) == toBytes(ristrettoEncode(p))

suite "RistrettoPoint -- order-8 NEGATIVE companion ([2]E/E[4] boundary, Stage-3 amendment)":
  # The [2]E/E[4] boundary pinned as documented behavior: a genuine order-8
  # Edwards point does NOT preserve a RistrettoPoint's encoding (unlike the
  # four E[4] points above). Coordinates below are one order-8 point,
  # computed offline (Python, plain integer arithmetic mod 2^255-19): find a
  # curve point G whose order is the full curve-group order 8*L (checked via
  # 4*L*G != O and 8*G != O, i.e. G survives both maximality tests for the
  # two primes -- 2 and L -- dividing 8*L), then T8 = L*G has order exactly
  # 8 (order(G) = 8L => order(L*G) = 8L / gcd(L, 8L) = 8L / L = 8). Verified
  # in Python: T8 is on-curve, 2*T8 and 4*T8 are the expected order-4/order-2
  # points ((-sqrt(-1), 0) and (0,-1) respectively) and 8*T8 == the curve
  # identity (0,1) -- i.e. order exactly 8, not a proper divisor of 8.
  const Order8XHex = "4ad145c54646a1de38e2e513703c195cbb4ade38329933e9284a3906a0b9d51f"
  const Order8YHex = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"

  let x8 = feFromBytes(hexToArray32(Order8XHex))
  let y8 = feFromBytes(hexToArray32(Order8YHex))
  var t8: Fe
  feMul(t8, x8, y8) # z = 1, so t = x*y/z = x*y
  let rawOrder8 = GeP3(x: x8, y: y8, z: FeOne, t: t8)

  test "the order-8 point satisfies the twisted Edwards curve equation":
    var y2, x2, z2, dt2, lhs, rhs: Fe
    feSq(y2, rawOrder8.y)
    feSq(x2, rawOrder8.x)
    feSq(z2, rawOrder8.z)
    feSq(dt2, rawOrder8.t)
    feMul(dt2, dt2, feFromLimbs(Ed25519D_Raw))
    feSub(lhs, y2, x2)
    feAdd(rhs, z2, dt2)
    check feEqualCT(lhs, rhs)

  proc doubleRaw(p: GeP3): GeP3 =
    ## Literal Edwards-point doubling on a raw `GeP3`, via the same
    ## `geP3ToCached` -> `geAdd` -> `geP1P1ToP3` chain `RistrettoPoint`'s own
    ## `+` operator uses -- but staying at the raw-`GeP3` level rather than
    ## going through `RistrettoPoint`'s `+`/`==`. This distinction is
    ## load-bearing, not stylistic: `RistrettoPoint`'s `==` is QUOTIENT
    ## equality by design (E[4]-invariant -- that is the entire point of
    ## ristretto255), so it cannot distinguish the literal identity `(0,1)`
    ## from any other E[4] member such as `(0,-1)`: both collapse to the
    ## SAME ristretto element. `4*T8` for this order-8 `T8` is literally
    ## `(0,-1)` (T8's order is exactly 8, so `4*T8` has order exactly 2) --
    ## a first RED pass of this very test wrote the check against
    ## `RistrettoPoint`'s `==` and it FALSELY reported "annihilated", which
    ## is what caught this distinction before it reached GREEN. "4*T8 !=
    ## identity as points" (the task's own wording) means literal Edwards
    ## point equality, checked here directly on `X`/`Y`/`Z` rather than
    ## through the quotient.
    var pCached: GeCached
    geP3ToCached(pCached, p)
    var sum: GeP1P1
    geAdd(sum, p, pCached)
    geP1P1ToP3(result, sum)

  proc isLiteralIdentity(p: GeP3): bool =
    ## `p` represents the literal Edwards identity `(0, 1)` iff its affine
    ## `x = X/Z` is 0 (i.e. `X == 0`) and its affine `y = Y/Z` is 1 (i.e.
    ## `Y == Z`) -- checked directly on the extended coordinates, with no
    ## detour through `RistrettoPoint`'s quotient `==` (see `doubleRaw`'s
    ## doc comment above for why that would be the wrong tool here).
    feIsZeroCT(p.x) and feEqualCT(p.y, p.z)

  let t8Point = ristrettoUnchecked(rawOrder8)

  test "the order-8 point is NOT annihilated by 4, checked literally (4*T8 != (0,1) as an exact Edwards point)":
    let twiceRaw = doubleRaw(rawOrder8)
    let fourRaw = doubleRaw(twiceRaw)
    check not isLiteralIdentity(fourRaw)

  test "P + T8 does NOT encode equal to P, for the same two fixed points (the [2]E boundary)":
    let p1 = RistrettoBasePoint
    let p2 = ristrettoDecode(toRistrettoEncoded(hexToArray32(A1Encodings[7]))).get()
    for p in [p1, p2]:
      check toBytes(ristrettoEncode(p + t8Point)) != toBytes(ristrettoEncode(p))

suite "RistrettoEncoded -- wire.nim-style borrows":
  test "toRistrettoEncoded / toBytes round-trip":
    let bytes = hexToArray32(A1Encodings[2])
    let encoded = toRistrettoEncoded(bytes)
    check toBytes(encoded) == bytes

  test "== compares underlying bytes":
    let a = toRistrettoEncoded(hexToArray32(A1Encodings[4]))
    let b = toRistrettoEncoded(hexToArray32(A1Encodings[4]))
    let c = toRistrettoEncoded(hexToArray32(A1Encodings[6]))
    check a == b
    check not (a == c)

  test "$ produces a nonempty string":
    let encoded = toRistrettoEncoded(hexToArray32(A1Encodings[1]))
    check ($encoded).len > 0

  test "hash agrees with ==": # equal encodings must hash equal
    let a = toRistrettoEncoded(hexToArray32(A1Encodings[8]))
    let b = toRistrettoEncoded(hexToArray32(A1Encodings[8]))
    check hash(a) == hash(b)

# ---------------------------------------------------------------------------
# RFC-004 slice 5a -- RistrettoStaticSecret + ristrettoScalarmultBase/Vartime
# ---------------------------------------------------------------------------

proc lMinus1Bytes(): array[32, byte] =
  ## The largest valid canonical scalar (L - 1). L's low byte (0xED) has no
  ## borrow to propagate when decremented by 1.
  result = L
  result[0] = result[0] - 1

proc wideLBytes(): array[64, byte] =
  ## L represented as a 64-byte little-endian integer (L in the low 32
  ## bytes, zero in the high 32) -- the exact integer L, so
  ## `toRistrettoStaticSecretWide`'s reduction mod L lands on 0.
  for i in 0 ..< 32: result[i] = L[i]

suite "RistrettoStaticSecret -- constructors and the canonical-residue invariant (RFC-004 slice 5a)":
  test "toRistrettoStaticSecret accepts a canonical scalar and round-trips via toBytes":
    let bytes = scalarFromSmallInt(7)
    let secretOpt = toRistrettoStaticSecret(bytes)
    check secretOpt.isSome
    check toBytes(secretOpt.get()) == bytes

  test "toRistrettoStaticSecret accepts s = L - 1 (the largest valid canonical scalar)":
    let bytes = lMinus1Bytes()
    let secretOpt = toRistrettoStaticSecret(bytes)
    check secretOpt.isSome
    check toBytes(secretOpt.get()) == bytes

  test "toRistrettoStaticSecret rejects s = L (non-canonical -- the 32-byte import's whole point)":
    check toRistrettoStaticSecret(L).isNone

  test "toRistrettoStaticSecretWide totally accepts s = L, reducing it to the zero scalar":
    let secret = toRistrettoStaticSecretWide(wideLBytes())
    check toBytes(secret) == default(array[32, byte])

  test "toRistrettoStaticSecretWide reduces an all-zero 64-byte input to the zero scalar":
    let secret = toRistrettoStaticSecretWide(default(array[64, byte]))
    check toBytes(secret) == default(array[32, byte])

  test "ristrettoStaticSecret() generates a canonical scalar (< L)":
    let secret = ristrettoStaticSecret()
    check scIsCanonical(toBytes(secret))

  test "ristrettoStaticPair() generates a canonical secret whose public element matches ristrettoScalarmultBase":
    let (secret, public) = ristrettoStaticPair()
    check scIsCanonical(toBytes(secret))
    check ristrettoScalarmultBase(secret) == public

suite "RistrettoStaticSecret -- secret hygiene (=destroy / wipe, the X25519StaticSecret probe-pattern precedent)":
  ## Same methodology as test_x25519.nim's "X25519 - secret hygiene" suite:
  ## a raw pointer captured before the wipe, memory re-read after.
  ## RistrettoStaticSecret is a one-field object (same representation as
  ## X25519StaticSecret/Seed, and for the same reason), so a pointer to the
  ## object aliases its sole `bytes` field.
  test "=destroy wipes RistrettoStaticSecret's memory at scope exit":
    var probe: ptr array[32, byte]
    let bytes = scalarFromSmallInt(7)
    block:
      var s = toRistrettoStaticSecret(bytes).get()
      probe = cast[ptr array[32, byte]](addr s)
      check probe[] == bytes # sanity: the probe aliases the real bytes
    check probe[] == default(array[32, byte])

  test "a COPIED RistrettoStaticSecret also wipes independently at its own scope exit":
    let bytes = scalarFromSmallInt(9)
    let original = toRistrettoStaticSecret(bytes).get()
    var probeCopy: ptr array[32, byte]
    block:
      var copy = original
      probeCopy = cast[ptr array[32, byte]](addr copy)
      check probeCopy[] == bytes # sanity: the copy holds the same bytes
    check probeCopy[] == default(array[32, byte])
    check toBytes(original) == bytes # original unaffected by the copy's wipe

  test "wipe(var RistrettoStaticSecret) zeroes the underlying bytes in place":
    var s = toRistrettoStaticSecret(scalarFromSmallInt(11)).get()
    let probe = cast[ptr array[32, byte]](addr s)
    doAssert probe[] != default(array[32, byte]) # sanity: nonzero before wipe
    wipe(s)
    check probe[] == default(array[32, byte])

suite "ristrettoScalarmultBase / ristrettoScalarmultVartime -- deterministic boundary scalars (RFC-004 slice 5a)":
  ## s=0 and s=L -> identity, s=1 -> RistrettoBasePoint, s=L-1 -> -RistrettoBasePoint
  ## (the additive-inverse axiom checked a second way, matching scReduce's
  ## own boundary-scalar discipline). s=L reaches these operations only via
  ## the wide constructor (fixed-base) and the bare-array vartime path
  ## (variable-base) -- the 32-byte import rejects L by design, pinned in
  ## the constructor suite above.
  test "s = 0 -> identity (fixed-base)":
    let secret = toRistrettoStaticSecret(default(array[32, byte])).get()
    check ristrettoScalarmultBase(secret) == RistrettoIdentity

  test "s = 1 -> RistrettoBasePoint (fixed-base)":
    let secret = toRistrettoStaticSecret(scalarFromSmallInt(1)).get()
    check ristrettoScalarmultBase(secret) == RistrettoBasePoint

  test "s = L - 1 -> -RistrettoBasePoint (fixed-base, additive-inverse check)":
    let secret = toRistrettoStaticSecret(lMinus1Bytes()).get()
    check ristrettoScalarmultBase(secret) == (-RistrettoBasePoint)

  test "s = L -> identity (wide constructor, fixed-base)":
    let secret = toRistrettoStaticSecretWide(wideLBytes())
    check ristrettoScalarmultBase(secret) == RistrettoIdentity

  test "s = 0 -> identity (vartime)":
    check ristrettoScalarmultVartime(default(array[32, byte]), RistrettoBasePoint) == RistrettoIdentity

  test "s = 1 -> RistrettoBasePoint (vartime)":
    check ristrettoScalarmultVartime(scalarFromSmallInt(1), RistrettoBasePoint) == RistrettoBasePoint

  test "s = L - 1 -> -RistrettoBasePoint (vartime, additive-inverse check)":
    check ristrettoScalarmultVartime(lMinus1Bytes(), RistrettoBasePoint) == (-RistrettoBasePoint)

  test "s = L -> identity (bare-array vartime path, deliberately unreduced input)":
    ## scalarmultVartime performs no reduction -- it computes the literal
    ## 256-bit multiple, so L*RistrettoBasePoint lands on the identity
    ## because RistrettoBasePoint has order exactly L.
    check ristrettoScalarmultVartime(L, RistrettoBasePoint) == RistrettoIdentity

suite "RistrettoStaticSecret -- ristrettoScalarmultVartime type boundary (compile-time)":
  test "RistrettoStaticSecret has no implicit converter to array[32, byte]":
    ## `compiles()` CAN see this one (an ordinary type mismatch) -- pinned
    ## directly first, cheaply, before the subprocess fixture below
    ## re-confirms it as a literal compiler diagnostic, matching
    ## test_scalar.nim's SecretScalar-vs-scalarmultVartime suite.
    check(not compiles(block:
      let secretOpt = toRistrettoStaticSecret(default(array[32, byte]))
      let secret = secretOpt.get()
      discard ristrettoScalarmultVartime(secret, RistrettoBasePoint)
    ))

  test "ristrettoScalarmultVartime(secret, p) is rejected (subprocess compile)":
    ## Same subprocess-`nim c` methodology as test_scalar.nim's
    ## `reject_secretscalar_vartime.nim` check --
    ## `reject_secretscalar_ristretto_vartime.nim`'s own doc comment
    ## explains why this error class is ALSO visible to `compiles()` above.
    let fixture = currentSourcePath().parentDir / "fixtures" / "reject_secretscalar_ristretto_vartime.nim"
    let repoRoot = currentSourcePath().parentDir.parentDir.parentDir
    let cmd = "nim c --hints:off --nimcache:" &
      (repoRoot / "build" / "nimcache_reject_secretscalar_ristretto_vartime") & " " & fixture
    let (output, exitCode) = execCmdEx(cmd, workingDir = repoRoot)
    check exitCode != 0
    check "type mismatch" in output

# ---------------------------------------------------------------------------
# RFC-004 slice 5b -- RistrettoEphemeralSecret (move-only, fresh-only)
# ---------------------------------------------------------------------------

suite "RistrettoEphemeralSecret -- fresh-only constructors and borrow-only base-mult (RFC-004 slice 5b)":
  test "ristrettoEphemeralPair() generates a secret whose public element matches ristrettoScalarmultBase":
    let (secret, public) = ristrettoEphemeralPair()
    check ristrettoScalarmultBase(secret) == public

  test "ristrettoEphemeralSecret() then ristrettoScalarmultBase produces a valid, non-identity point":
    let secret = ristrettoEphemeralSecret()
    let public = ristrettoScalarmultBase(secret)
    check not (public == RistrettoIdentity)

suite "RistrettoEphemeralSecret -- secret hygiene (probe pattern, the X25519EphemeralSecret precedent)":
  ## Same probe-pattern methodology as `RistrettoStaticSecret`'s hygiene
  ## suite above and `test_x25519.nim`'s "ephemeral secret hygiene (probe
  ## pattern)" suite: a raw pointer captured before scope exit, memory
  ## re-read after. `RistrettoEphemeralSecret` is a one-field object, so a
  ## pointer to the object aliases its sole `bytes` field. Only the
  ## unused-at-scope-exit case is exercised this slice -- there is no
  ## consuming operation yet (`ristrettoScalarmult(sink ...)` arrives in
  ## slice 7a alongside its own dedicated hygiene coverage).
  test "=destroy wipes an unused RistrettoEphemeralSecret at scope exit":
    var probe: ptr array[32, byte]
    block:
      var secret = ristrettoEphemeralSecret()
      probe = cast[ptr array[32, byte]](addr secret)
      doAssert probe[] != default(array[32, byte]) # sanity: nonzero before scope exit
    check probe[] == default(array[32, byte])

suite "RistrettoEphemeralSecret -- move-only copy rejection (compile-time, subprocess-verified, RFC-004 slice 5b)":
  ## Neither `compiles()` nor `nim check` can see this violation -- it is
  ## raised by the `injectdestructors` pass, which runs later in the
  ## pipeline than either reaches (`x25519.X25519EphemeralSecret`'s own
  ## `reject_ephemeral_copy.nim` precedent, reused verbatim here for this
  ## module's ephemeral role).
  test "copying a RistrettoEphemeralSecret is a compile error (subprocess compile)":
    let fixture = currentSourcePath().parentDir / "fixtures" / "reject_ristretto_ephemeral_copy.nim"
    let repoRoot = currentSourcePath().parentDir.parentDir.parentDir
    let cmd = "nim c --hints:off --nimcache:" &
      (repoRoot / "build" / "nimcache_reject_ristretto_ephemeral_copy") & " " & fixture
    let (output, exitCode) = execCmdEx(cmd, workingDir = repoRoot)
    check exitCode != 0
    check "=copy" in output

# ---------------------------------------------------------------------------
# RFC-004 slice 6 -- hash-to-group (ristrettoFromUniformBytes / the MAP
# function) and the three remaining SS4.1 implementation constants
# ---------------------------------------------------------------------------

proc hexToArray64(s: string): array[64, byte] =
  doAssert s.len == 128
  for i in 0 ..< 64:
    result[i] = byte(parseHexInt(s[2 * i .. 2 * i + 1]))

# RFC 9496 Appendix A.3 -- direct element-derivation-function input/output
# pairs, transcribed from the published RFC (fetched directly, not from
# memory -- see the task's own admonition re: summarizer-mangled hex).
const A3DirectInputs: array[7, string] = [
  "5d1be09e3d0c82fc538112490e35701979d99e06ca3e2b5b54bffe8b4dc772c14d98b696a1bbfb5ca32c436cc61c16563790306c79eaca7705668b47dffe5bb6",
  "f116b34b8f17ceb56e8732a60d913dd10cce47a6d53bee9204be8b44f6678b270102a56902e2488c46120e9276cfe54638286b9e4b3cdb470b542d46c2068d38",
  "8422e1bbdaab52938b81fd602effb6f89110e1e57208ad12d9ad767e2e25510c27140775f9337088b982d83d7fcf0b2fa1edffe51952cbe7365e95c86eaf325c",
  "ac22415129b61427bf464e17baee8db65940c233b98afce8d17c57beeb7876c2150d15af1cb1fb824bbd14955f2b57d08d388aab431a391cfc33d5bafb5dbbaf",
  "165d697a1ef3d5cf3c38565beefcf88c0f282b8e7dbd28544c483432f1cec7675debea8ebb4e5fe7d6f6e5db15f15587ac4d4d4a1de7191e0c1ca6664abcc413",
  "a836e6c9a9ca9f1e8d486273ad56a78c70cf18f0ce10abb1c7172ddd605d7fd2979854f47ae1ccf204a33102095b4200e5befc0465accc263175485f0e17ea5c",
  "2cdc11eaeb95daf01189417cdddbf95952993aa9cb9c640eb5058d09702c74622c9965a697a3b345ec24ee56335b556e677b30e6f90ac77d781064f866a3c982",
]

const A3DirectOutputs: array[7, string] = [
  "3066f82a1a747d45120d1740f14358531a8f04bbffe6a819f86dfe50f44a0a46",
  "f26e5b6f7d362d2d2a94c5d0e7602cb4773c95a2e5c31a64f133189fa76ed61b",
  "006ccd2a9e6867e6a2c5cea83d3302cc9de128dd2a9a57dd8ee7b9d7ffe02826",
  "f8f0c87cf237953c5890aec3998169005dae3eca1fbb04548c635953c817f92a",
  "ae81e7dedf20a497e10c304a765c1767a42d6e06029758d2d7e8ef7cc4c41179",
  "e2705652ff9f5e44d3e841bf1c251cf7dddb77d140870d1ab2ed64f1a9ce8628",
  "80bd07262511cdde4863f8a7434cef696750681cb9510eea557088f76d9e5065",
]

# RFC 9496 Appendix A.3 -- the closing four-inputs-one-output convergence
# set (exercises the map's many-to-one property directly -- round 3's own
# undercount fix, see the RFC's Validation battery).
const A3ConvergenceInputs: array[4, string] = [
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1200000000000000000000000000000000000000000000000000000000000000",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "0000000000000000000000000000000000000000000000000000000000000080ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "00000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000080",
]

const A3ConvergenceOutput = "304282791023b73128d277bdcb5c7746ef2eac08dde9f2983379cb8e5ef0517f"

suite "ristrettoFromUniformBytes -- RFC 9496 Appendix A.3 direct pairs (RFC-004 slice 6)":
  test "each direct input maps to its labeled output":
    for i in 0 ..< A3DirectInputs.len:
      let point = ristrettoFromUniformBytes(hexToArray64(A3DirectInputs[i]))
      check toBytes(ristrettoEncode(point)) == hexToArray32(A3DirectOutputs[i])

suite "ristrettoFromUniformBytes -- RFC 9496 Appendix A.3 convergence set (RFC-004 slice 6)":
  test "all four convergence-set inputs map to the same labeled output":
    let expected = hexToArray32(A3ConvergenceOutput)
    for i in 0 ..< A3ConvergenceInputs.len:
      let point = ristrettoFromUniformBytes(hexToArray64(A3ConvergenceInputs[i]))
      check toBytes(ristrettoEncode(point)) == expected

  test "the four convergence-set points are pairwise equal via quotient ==, not just equal encodings":
    var points: array[4, RistrettoPoint]
    for i in 0 ..< A3ConvergenceInputs.len:
      points[i] = ristrettoFromUniformBytes(hexToArray64(A3ConvergenceInputs[i]))
    for i in 1 ..< points.len:
      check points[i] == points[0]

suite "ristrettoFromUniformBytes -- determinism and deterministic edge inputs (RFC-004 slice 6)":
  test "same input twice yields equal points (determinism)":
    let point1 = ristrettoFromUniformBytes(hexToArray64(A3DirectInputs[0]))
    let point2 = ristrettoFromUniformBytes(hexToArray64(A3DirectInputs[0]))
    check point1 == point2

  test "all-zero 64-byte input maps to a valid element (re-decodes cleanly)":
    let point = ristrettoFromUniformBytes(default(array[64, byte]))
    let decoded = ristrettoDecode(ristrettoEncode(point))
    check decoded.isSome
    check decoded.get() == point

  test "all-0xFF 64-byte input maps to a valid element (re-decodes cleanly)":
    var allFF: array[64, byte]
    for i in 0 ..< 64: allFF[i] = 0xFF'u8
    let point = ristrettoFromUniformBytes(allFF)
    let decoded = ristrettoDecode(ristrettoEncode(point))
    check decoded.isSome
    check decoded.get() == point

suite "OneMinusDSq / DMinusOneSq / SqrtAdMinusOne -- defining equations (RFC 9496 SS4.1, RFC-004 slice 6)":
  test "OneMinusDSq == 1 - d^2":
    let d = feFromLimbs(Ed25519D_Raw)
    var dSq, expected: Fe
    feSq(dSq, d)
    feSub(expected, FeOne, dSq)
    check feEqualCT(OneMinusDSq, expected)

  test "DMinusOneSq == (d - 1)^2":
    let d = feFromLimbs(Ed25519D_Raw)
    var dMinus1, expected: Fe
    feSub(dMinus1, d, FeOne)
    feSq(expected, dMinus1)
    check feEqualCT(DMinusOneSq, expected)

  test "SqrtAdMinusOne^2 == a*d - 1, where a = -1":
    let d = feFromLimbs(Ed25519D_Raw)
    var a, ad, expected, sq: Fe
    feNeg(a, FeOne)
    feMul(ad, a, d)
    feSub(expected, ad, FeOne)
    feSq(sq, SqrtAdMinusOne)
    check feEqualCT(sq, expected)

