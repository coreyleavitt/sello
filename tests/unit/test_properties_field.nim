## Property-based coverage for sello/field (RFC-001 finding 10).
##
## Uses proptest (Corey's Hypothesis-style choice-sequence engine for Nim,
## https://github.com/coreyleavitt/proptest), fetched as an optional milpa
## dev-dep -- see milpa.kdl (`optional=#true`) and
## docs/rfc-001-signing.handoff.md's B4a summary for the wiring decision.
##
## `import proptest` pulls in the whole library (strategy/engine/dsl plus
## the stateful/fuzz/mining/bisim/etc. surface), but NOT `proptest/symex`
## (the only module that imports `z3`) -- confirmed empirically by
## compiling this file in the base `ghcr.io/coreyleavitt/nim:2.2.10` image,
## which has no z3 shared library installed. `proptest/bmc` (also
## z3-adjacent by name) only imports `strategy`/`datasource`/`stateful`/
## `rng`, never `z3` or `symex` -- the whole z3/SMT stack lives behind an
## import boundary this file never crosses.
##
## Ring-axiom / roundtrip properties compare field elements via their
## CANONICAL byte encoding (`feToBytes`), never raw `Fe.limbs` -- two
## arithmetically-equal field elements can carry different (unreduced)
## limb representations, a lesson this repo already learned the hard way
## in slice 3 (see test_scalar.nim's GeBaseTable standing-guard comment).
##
## fePow22523 is deliberately NOT covered by an independent property here:
## the only cheap self-consistency check available without a modular
## big-int exponentiation oracle is circular (re-deriving the same
## addition-chain this function already IS), so it would pin the
## implementation against itself, not a spec. `pointDecode` already
## exercises `fePow22523` transitively against RFC 8032 + Wycheproof
## vectors; an independent oracle is exactly the differential-testing idea
## deferred to review finding 22 / the B4b fuzz+Z3 batch, not duplicated
## here.

import std/unittest
import proptest
import sello/field

proc randByte(): Strategy[byte] =
  integers(0, 255).map(proc(x: int): byte = byte(x))

proc fe32(): Strategy[array[32, byte]] =
  arrays[32, byte](randByte())

proc toFe(b: array[32, byte]): Fe = feFromBytes(b)

# ---------------------------------------------------------------------------
# Ring axioms (feAdd/feSub/feMul), compared via canonical encoding.
# ---------------------------------------------------------------------------

suite "field property: ring axioms":
  property "feAdd is commutative":
    given ab in fe32(), bb in fe32()
    let a = toFe(ab)
    let b = toFe(bb)
    var r1, r2: Fe
    feAdd(r1, a, b)
    feAdd(r2, b, a)
    ensure feToBytes(r1) == feToBytes(r2)

  property "feAdd is associative":
    given ab in fe32(), bb in fe32(), cb in fe32()
    let a = toFe(ab)
    let b = toFe(bb)
    let c = toFe(cb)
    var abSum: Fe
    feAdd(abSum, a, b)
    var lhs: Fe
    feAdd(lhs, abSum, c)
    var bc: Fe
    feAdd(bc, b, c)
    var rhs: Fe
    feAdd(rhs, a, bc)
    ensure feToBytes(lhs) == feToBytes(rhs)

  property "feMul is commutative":
    given ab in fe32(), bb in fe32()
    let a = toFe(ab)
    let b = toFe(bb)
    var r1, r2: Fe
    feMul(r1, a, b)
    feMul(r2, b, a)
    ensure feToBytes(r1) == feToBytes(r2)

  property "feMul is associative":
    given ab in fe32(), bb in fe32(), cb in fe32()
    let a = toFe(ab)
    let b = toFe(bb)
    let c = toFe(cb)
    var abSum: Fe
    feMul(abSum, a, b)
    var lhs: Fe
    feMul(lhs, abSum, c)
    var bc: Fe
    feMul(bc, b, c)
    var rhs: Fe
    feMul(rhs, a, bc)
    ensure feToBytes(lhs) == feToBytes(rhs)

  property "feMul distributes over feAdd":
    given ab in fe32(), bb in fe32(), cb in fe32()
    let a = toFe(ab)
    let b = toFe(bb)
    let c = toFe(cb)
    var bPlusC: Fe
    feAdd(bPlusC, b, c)
    var lhs: Fe
    feMul(lhs, a, bPlusC)
    var ab2, ac: Fe
    feMul(ab2, a, b)
    feMul(ac, a, c)
    var rhs: Fe
    feAdd(rhs, ab2, ac)
    ensure feToBytes(lhs) == feToBytes(rhs)

  property "feSub(a, a) == 0":
    given ab in fe32()
    let a = toFe(ab)
    var r: Fe
    feSub(r, a, a)
    ensure feToBytes(r) == feToBytes(FeZero)

  property "feMul(a, feInvert(a)) == 1 for nonzero a":
    given ab in fe32()
    let a = toFe(ab)
    assume feIsNonZero(a)
    var inv, r: Fe
    feInvert(inv, a)
    feMul(r, a, inv)
    ensure feToBytes(r) == feToBytes(FeOne)

  property "feNeg is involutive (double negation is the identity)":
    given ab in fe32()
    let a = toFe(ab)
    var neg, negneg: Fe
    feNeg(neg, a)
    feNeg(negneg, neg)
    ensure feToBytes(negneg) == feToBytes(a)

# ---------------------------------------------------------------------------
# feFromBytes / feToBytes roundtrips + near-p boundary stress.
#
# p = 2^255 - 19. Little-endian 32-byte canonical boundary values:
#   p-1   = ED-1=EC, FF*30, 7F
#   p     = ED,      FF*30, 7F   (non-canonical: feBytesCanonical says false
#                                 for v == p, per its own doc comment)
#   p+1..p+18 = EE..FF, FF*30, 7F  (all non-canonical: > p)
#   2^255-1   = FF,     FF*30, 7F  (== p+18; kept as its own named case per
#                                   the review finding's explicit list)
#   all-zeros = canonical zero
#   all-0xFF  = FF*32 (bit 255 SET -- exercises the "bit 255 ignored/masked"
#                       rule in both feBytesCanonical and feFromBytes)
# ---------------------------------------------------------------------------

proc pBoundary(delta: int): array[32, byte] =
  ## Little-endian bytes of (p + delta) for small |delta|, staying within
  ## one byte0 increment/decrement (delta in -1..18 covers every case this
  ## file needs; p's byte0 is 0xED with 18 headroom to 0xFF).
  doAssert delta >= -1 and delta <= 18
  result = [0xFF'u8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F]
  result[0] = byte(0xED + delta)

let boundaryVectors = @[
  ("p-1", pBoundary(-1), true),
  ("p", pBoundary(0), false),
  ("p+1", pBoundary(1), false),
  ("p+2", pBoundary(2), false),
  ("p+3", pBoundary(3), false),
  ("p+17", pBoundary(17), false),
  ("p+18 (== 2^255-1)", pBoundary(18), false),
  ("2^255-1 (explicit)", [0xFF'u8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                           0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                           0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                           0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F], false),
  ("all-zeros", [0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], true),
  ("all-0xFF (bit 255 set)", [0xFF'u8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                               0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                               0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                               0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], false),
]

suite "field property: near-p boundary stress (pinned)":
  test "feBytesCanonical matches the expected canonical/non-canonical verdict":
    for (name, bytes, expected) in boundaryVectors:
      check feBytesCanonical(bytes) == expected

  test "feFromBytes -> feToBytes always lands in canonical range, even on non-canonical input":
    ## The real final-carry-edge correctness property: regardless of
    ## whether the INPUT was canonical, the round-tripped OUTPUT must be
    ## the canonical representative of the same field element.
    for (name, bytes, _) in boundaryVectors:
      let roundtripped = feToBytes(feFromBytes(bytes))
      check feBytesCanonical(roundtripped)

suite "field property: encode/decode roundtrip":
  property "feFromBytes -> feToBytes is exact on canonical inputs":
    given b in fe32()
    let canon = feToBytes(feFromBytes(b))  # first pass always canonicalizes
    ensure feToBytes(feFromBytes(canon)) == canon

  property "feFromBytes -> feToBytes always yields a canonical encoding (random inputs)":
    given b in fe32()
    ensure feBytesCanonical(feToBytes(feFromBytes(b)))

# ---------------------------------------------------------------------------
# feCMove / feCSwap: both flag values on random pairs.
# ---------------------------------------------------------------------------

suite "field property: feCMove / feCSwap":
  property "feCMove(r, a, false) leaves r unchanged":
    given rb in fe32(), ab in fe32()
    var r = toFe(rb)
    let before = feToBytes(r)
    feCMove(r, toFe(ab), false)
    ensure feToBytes(r) == before

  property "feCMove(r, a, true) sets r := a":
    given rb in fe32(), ab in fe32()
    var r = toFe(rb)
    let a = toFe(ab)
    feCMove(r, a, true)
    ensure feToBytes(r) == feToBytes(a)

  property "feCSwap(a, b, false) leaves both unchanged":
    given ab in fe32(), bb in fe32()
    var a = toFe(ab)
    var b = toFe(bb)
    let beforeA = feToBytes(a)
    let beforeB = feToBytes(b)
    feCSwap(a, b, false)
    ensure feToBytes(a) == beforeA and feToBytes(b) == beforeB

  property "feCSwap(a, b, true) exchanges both":
    given ab in fe32(), bb in fe32()
    var a = toFe(ab)
    var b = toFe(bb)
    let beforeA = feToBytes(a)
    let beforeB = feToBytes(b)
    feCSwap(a, b, true)
    ensure feToBytes(a) == beforeB and feToBytes(b) == beforeA
