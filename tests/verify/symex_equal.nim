## Machine-checked (Z3-backed) proof of the or-accumulate lemma shared by
## `field.feEqualCT`/`field.feIsZeroCT`/`field.feBytesCanonicalCT` (RFC-004
## slice 1b), using COREY'S proptest library's symbolic-execution engine
## (`proptest/symex`) -- the same tooling and register `tests/verify/
## symex_mask.nim` and `tests/verify/symex_recode.nim` established. Read
## `symex_mask.nim`'s module doc comment first if this is your first time
## in `tests/verify/` -- it is the pattern library this harness follows
## (lemma extraction, tooling-compatible re-encoding when the walker
## demands it, exhaustive/meaningful cross-checks against the real
## implementation, honest scoping of what a `sxUnsat` verdict does and
## doesn't cover).
##
## Standalone, non-suite binary (mirrors `symex_recode.nim`'s,
## `symex_mask.nim`'s, and `symex_reduce.nim`'s pattern): NOT part of
## scripts/test.sh (needs z3-devel). Run via `scripts/bmc.sh`, alongside
## those three files' queries in one invocation (this slice's `scripts/
## bmc.sh` wiring).
##
## -----------------------------------------------------------------------
## THE PROPERTY UNDER PROOF, AND ITS SCOPE
## -----------------------------------------------------------------------
## `feEqualCT`, `feIsZeroCT` (defined in terms of `feEqualCT`), and
## `feBytesCanonicalCT` (field.nim, RFC-004 slice 1a) share one shape: two
## 32-byte arrays, or-accumulated byte-by-byte XOR into one word, no early
## exit, no short-circuit boolean, tested against zero at the end:
##   var diff: byte = 0
##   for i in 0..<32:
##     diff = diff or (x[i] xor y[i])
##   diff == 0
## (`feEqualCT` compares `feToBytes(a)`/`feToBytes(b)`; `feBytesCanonicalCT`
## compares `feToBytes(feFromBytes(bytes))`/`bytes` directly -- the two
## call sites differ only in WHICH byte arrays feed the loop, never in the
## loop's own shape, which is what this harness targets.)
##
## This harness proves the loop's own claim: the accumulated word is zero
## IFF every one of the 32 byte pairs is equal -- full-domain over
## symbolic bytes, for the FULL 32-pair composition in one query (not a
## per-step lemma standing in for an unattempted whole-chain proof, and
## not sampled).
##
## -----------------------------------------------------------------------
## WHY THE FREE-PARAMETER ENCODING IS USED FROM THE START (not discovered
## here by hitting a fresh resource wall)
## -----------------------------------------------------------------------
## `symex_recode.nim`'s RESOURCE WALL section (its module doc comment)
## already isolated, empirically, that symbolically decoding a fixed-size
## `array[N, byte]` PARAMETER (bit-shift/mask extraction reading a
## symbolic array into a mutated local) is the far more likely cause of
## that file's first-attempt timeout than the arithmetic chained after it
## -- confirmed by `wholeChainRecode` completing in ~84s once the array was
## dropped in favor of 64 independent free symbolic parameters carrying
## the identical per-step arithmetic. This harness's accumulate loop reads
## an `array[32, byte]` parameter at each iteration the same way that
## decode step did (`x[i]`/`y[i]`), so it sits squarely in the shape
## already identified as the likely trigger -- re-running that exact
## experiment a third time, cold, against this harness's own 300s slice of
## `scripts/bmc.sh`'s kill-timeout, would spend the budget re-confirming a
## lesson this project's own prior work already recorded, not discovering
## new information. Per that file's own instruction ("prove the strongest
## TRACTABLE statement... rather than... re-running the whole-loop attempt
## with an ever-larger timeout hoping it eventually lands"), the primary
## artifact below goes straight to the free-parameter re-encoding
## `symex_recode.nim` already validated as tractable for a structurally
## identical chain-of-32/64-independent-steps shape. This is still "the
## full chain" in the sense the mission asks for -- one `sxUnsat` query
## over the complete 32-pair composition, not a per-step lemma alone --
## just encoded the tooling-compatible way from the outset rather than
## after a first failed literal-array attempt.
##
## The re-encoding: `orAccumulateChain` below takes 64 free `int32`
## parameters (`x0..x31`, `y0..y31`), each `symexAssume`d into `[0, 255]`
## (byte range), and chains them through the IDENTICAL `diff = diff or
## (xI xor yI)` step 32 times -- no array, no nested proc call (unlike
## `wholeChainRecode`, which needed a nested `oneStepChain` callee to
## thread nibble/carry state through 63 nontrivial arithmetic steps; this
## loop's per-step state is a single accumulator word threaded through
## bitwise `or`/`xor` only, so it stays a single FLAT proc, matching
## `symex_mask.nim`'s `maskConstructStep`/`cmoveSelectStep`/`cswapSelectStep`
## shape and sidestepping both of `symex_recode.nim`'s documented
## nested-call limitations (int32-width binop crash, tuple-return gap) and
## `symex_mask.nim`'s branch-merged-local crash by construction: nothing
## in this proc is derived from an `if`/`else`, so no local is
## "branch-merged" in the sense that bug requires). `xI`/`yI` are ordinary
## free top-level parameters (like `symex_mask.nim`'s `cmoveSelectStep`'s
## `mask` parameter), not branch-derived, so they compose into `xor`/`or`
## binops exactly the way that file's own workaround requires for safety.
##
## The final assertion combines all 32 pairwise equalities with plain
## boolean `and` (`(x0 == y0) and (x1 == y1) and ... `) -- not a NEW
## pattern for this harness register: `symex_mask.nim`'s `cswapSelectStep`
## already asserts a 2-way `and` of two equalities
## (`aOut == bLimb and bOut == aLimb`) and `symex_recode.nim`'s `oneStep`
## asserts a 2-way `and` of two inequalities
## (`digit >= -8'i32 and digit <= 7'i32`) with no crash or blowup; this
## harness's 32-way chain is the same construct at larger, but still
## linear, size -- a boolean AND-of-comparisons formula, not a
## value-producing `if`/`else` branch of the kind that crashes the walker
## per `symex_mask.nim`'s "A THIRD EMPIRICAL SYMEX LIMITATION" section.
## RESULT (see "THE MACHINE-CHECKED ARTIFACT" below): this direct 32-pair
## attempt completed and reported `sxUnsat` -- no resource wall was hit,
## no per-step-lemma fallback was required, and no query split was needed
## (unlike `symex_mask.nim`'s three-way split) -- but one more empirical
## walker limitation, distinct from any already on record, HAD to be
## routed around first. See immediately below.
##
## -----------------------------------------------------------------------
## A FOURTH EMPIRICAL SYMEX LIMITATION (found while building this harness):
## seeding an accumulator from the LITERAL `0'i32` and then chaining it
## through two or more further bitwise binops crashes the walker -- even
## though ONE combination with that same literal is fine
## -----------------------------------------------------------------------
## The natural transliteration of field.nim's own source -- `var diff:
## int32 = 0'i32`, then `diff = diff or (xI xor yI)` for each of the 32
## pairs in turn -- crashes the walker with the SAME `l.kind == r.kind`
## / "binBV: width mismatch" `AssertionDefect` `symex_mask.nim`'s own
## "THIRD EMPIRICAL SYMEX LIMITATION" section documents, but on a
## DIFFERENT trigger: confirmed on isolated minimal probes (down to two
## `int32` parameters and two chained `or` steps, independent of this
## harness's specific 32-pair/64-parameter structure, so it is not an
## artifact of this file's own size) that:
##   * `var diff: int32 = 0` then ONE `diff = diff or (a0 xor b0)` then
##     `symexAssert(diff == 0'i32)` (or any other use of `diff` in a
##     further binop/comparison) works fine, `sxUnsat`, no crash.
##   * The SAME setup with a SECOND chained step --
##     `diff = diff or (a1 xor b1)` before the assert -- crashes,
##     `l.kind == r.kind` / "binBV: width mismatch", at `lower`/
##     `lowerInExpr`. Reproduced identically whether the accumulator is a
##     mutated `var` (matching field.nim's own shape) or a fresh `let` per
##     step (`let diff1 = 0'i32 or (...); let diff2 = diff1 or (...)`) --
##     so this is not specifically about mutation/reassignment (the
##     `symex_mask.nim` "branch-merged local" trigger does not apply here
##     either: nothing in this proc is derived from an `if`/`else`).
##   * By contrast, seeding the accumulator from a SYMBOLIC expression that
##     is not a bare literal -- even one that is provably, but not
##     syntactically, always zero (`a0 xor a0`) -- does NOT crash for any
##     number of further chained steps tested (confirmed through 4 chained
##     pairs on an isolated probe before landing on the real 32-pair
##     harness below).
## The apparent root cause (not diagnosed further -- out of scope for this
## slice, matching the standing "report the empirical finding and its
## workaround, do not chase the tooling's internals" register this
## project's other symex harnesses already hold themselves to): a local
## seeded directly from an integer literal appears to carry a different
## internal representation than one seeded from a genuine (if
## staticaly-foldable) symbolic expression, and that representation
## survives exactly one further bitwise combination before a width
## bookkeeping mismatch surfaces on the next one.
##
## WORKAROUND, matching this project's established register (a different
## concrete encoding, checked against the original rather than merely
## assumed equivalent): `orAccumulateChain` below never introduces a bare
## literal `0'i32` into the accumulator at all -- since `0 or v == v` for
## any `v`, the accumulator is simply SEEDED with the first pair's own
## `xI xor yI` (itself an ordinary symbolic expression, not a literal) and
## the chain runs the remaining 31 pairs through the same `or`-accumulate
## step from there. This is not a generalization or an approximation of
## field.nim's loop -- it is the exact same arithmetic value at every step
## (the literal-seeded and expression-seeded forms compute identical
## results for identical inputs, by the `or`-identity `0 or v == v`), only
## the SOURCE-LEVEL encoding of the seed differs, exactly parallel to how
## `symex_mask.nim`'s `maskConstructStep` re-encodes `-int32(b)` as
## `if bFlag: -1'i32 else: 0'i32` for a tooling reason, not a semantic one.
## `crossCheckRealFunctionsAgreeWithAccumulateShape` below confirms this
## encoding's real-function counterpart (`orAccumulateLoop`, the literal
## `var diff: byte = 0` transliteration used ONLY for the concrete
## cross-check, never handed to `symexFind`) still matches the real,
## imported `feEqualCT`/`feIsZeroCT`/`feBytesCanonicalCT` on concrete
## vectors -- so the workaround changes how the proof is encoded, not what
## is proved.
import proptest/symex
import sello/field

# -----------------------------------------------------------------------
# The machine-checked artifact: one flat proc, 64 free int32 parameters
# (32 byte pairs), the full 32-step or-accumulate composition, asserting
# the iff directly.
# -----------------------------------------------------------------------

proc orAccumulateChain(
    x0, x1, x2, x3, x4, x5, x6, x7, x8, x9,
    x10, x11, x12, x13, x14, x15, x16, x17, x18, x19,
    x20, x21, x22, x23, x24, x25, x26, x27, x28, x29,
    x30, x31: int32;
    y0, y1, y2, y3, y4, y5, y6, y7, y8, y9,
    y10, y11, y12, y13, y14, y15, y16, y17, y18, y19,
    y20, y21, y22, y23, y24, y25, y26, y27, y28, y29,
    y30, y31: int32) =
  ## 64 INDEPENDENT free symbolic parameters, each standing for one byte
  ## of a hypothetical 32-byte array pair -- no array anywhere in this
  ## proc's own body (see module doc comment for why). Each parameter is
  ## constrained to `[0, 255]` (a byte's range); the `diff = diff or (xI
  ## xor yI)` chain is field.nim's shared loop body, applied 32 times with
  ## plain scalar locals instead of array reads/writes -- SEEDED from the
  ## first pair's own `x0 xor y0` rather than a literal `0'i32` (see "A
  ## FOURTH EMPIRICAL SYMEX LIMITATION" in the module doc comment above
  ## for why: `0 or v == v`, so this is the identical arithmetic value,
  ## re-encoded only at the source level to route around a walker crash).
  symexAssume(x0 >= 0'i32 and x0 <= 255'i32)
  symexAssume(x1 >= 0'i32 and x1 <= 255'i32)
  symexAssume(x2 >= 0'i32 and x2 <= 255'i32)
  symexAssume(x3 >= 0'i32 and x3 <= 255'i32)
  symexAssume(x4 >= 0'i32 and x4 <= 255'i32)
  symexAssume(x5 >= 0'i32 and x5 <= 255'i32)
  symexAssume(x6 >= 0'i32 and x6 <= 255'i32)
  symexAssume(x7 >= 0'i32 and x7 <= 255'i32)
  symexAssume(x8 >= 0'i32 and x8 <= 255'i32)
  symexAssume(x9 >= 0'i32 and x9 <= 255'i32)
  symexAssume(x10 >= 0'i32 and x10 <= 255'i32)
  symexAssume(x11 >= 0'i32 and x11 <= 255'i32)
  symexAssume(x12 >= 0'i32 and x12 <= 255'i32)
  symexAssume(x13 >= 0'i32 and x13 <= 255'i32)
  symexAssume(x14 >= 0'i32 and x14 <= 255'i32)
  symexAssume(x15 >= 0'i32 and x15 <= 255'i32)
  symexAssume(x16 >= 0'i32 and x16 <= 255'i32)
  symexAssume(x17 >= 0'i32 and x17 <= 255'i32)
  symexAssume(x18 >= 0'i32 and x18 <= 255'i32)
  symexAssume(x19 >= 0'i32 and x19 <= 255'i32)
  symexAssume(x20 >= 0'i32 and x20 <= 255'i32)
  symexAssume(x21 >= 0'i32 and x21 <= 255'i32)
  symexAssume(x22 >= 0'i32 and x22 <= 255'i32)
  symexAssume(x23 >= 0'i32 and x23 <= 255'i32)
  symexAssume(x24 >= 0'i32 and x24 <= 255'i32)
  symexAssume(x25 >= 0'i32 and x25 <= 255'i32)
  symexAssume(x26 >= 0'i32 and x26 <= 255'i32)
  symexAssume(x27 >= 0'i32 and x27 <= 255'i32)
  symexAssume(x28 >= 0'i32 and x28 <= 255'i32)
  symexAssume(x29 >= 0'i32 and x29 <= 255'i32)
  symexAssume(x30 >= 0'i32 and x30 <= 255'i32)
  symexAssume(x31 >= 0'i32 and x31 <= 255'i32)
  symexAssume(y0 >= 0'i32 and y0 <= 255'i32)
  symexAssume(y1 >= 0'i32 and y1 <= 255'i32)
  symexAssume(y2 >= 0'i32 and y2 <= 255'i32)
  symexAssume(y3 >= 0'i32 and y3 <= 255'i32)
  symexAssume(y4 >= 0'i32 and y4 <= 255'i32)
  symexAssume(y5 >= 0'i32 and y5 <= 255'i32)
  symexAssume(y6 >= 0'i32 and y6 <= 255'i32)
  symexAssume(y7 >= 0'i32 and y7 <= 255'i32)
  symexAssume(y8 >= 0'i32 and y8 <= 255'i32)
  symexAssume(y9 >= 0'i32 and y9 <= 255'i32)
  symexAssume(y10 >= 0'i32 and y10 <= 255'i32)
  symexAssume(y11 >= 0'i32 and y11 <= 255'i32)
  symexAssume(y12 >= 0'i32 and y12 <= 255'i32)
  symexAssume(y13 >= 0'i32 and y13 <= 255'i32)
  symexAssume(y14 >= 0'i32 and y14 <= 255'i32)
  symexAssume(y15 >= 0'i32 and y15 <= 255'i32)
  symexAssume(y16 >= 0'i32 and y16 <= 255'i32)
  symexAssume(y17 >= 0'i32 and y17 <= 255'i32)
  symexAssume(y18 >= 0'i32 and y18 <= 255'i32)
  symexAssume(y19 >= 0'i32 and y19 <= 255'i32)
  symexAssume(y20 >= 0'i32 and y20 <= 255'i32)
  symexAssume(y21 >= 0'i32 and y21 <= 255'i32)
  symexAssume(y22 >= 0'i32 and y22 <= 255'i32)
  symexAssume(y23 >= 0'i32 and y23 <= 255'i32)
  symexAssume(y24 >= 0'i32 and y24 <= 255'i32)
  symexAssume(y25 >= 0'i32 and y25 <= 255'i32)
  symexAssume(y26 >= 0'i32 and y26 <= 255'i32)
  symexAssume(y27 >= 0'i32 and y27 <= 255'i32)
  symexAssume(y28 >= 0'i32 and y28 <= 255'i32)
  symexAssume(y29 >= 0'i32 and y29 <= 255'i32)
  symexAssume(y30 >= 0'i32 and y30 <= 255'i32)
  symexAssume(y31 >= 0'i32 and y31 <= 255'i32)

  var diff: int32 = x0 xor y0
  diff = diff or (x1 xor y1)
  diff = diff or (x2 xor y2)
  diff = diff or (x3 xor y3)
  diff = diff or (x4 xor y4)
  diff = diff or (x5 xor y5)
  diff = diff or (x6 xor y6)
  diff = diff or (x7 xor y7)
  diff = diff or (x8 xor y8)
  diff = diff or (x9 xor y9)
  diff = diff or (x10 xor y10)
  diff = diff or (x11 xor y11)
  diff = diff or (x12 xor y12)
  diff = diff or (x13 xor y13)
  diff = diff or (x14 xor y14)
  diff = diff or (x15 xor y15)
  diff = diff or (x16 xor y16)
  diff = diff or (x17 xor y17)
  diff = diff or (x18 xor y18)
  diff = diff or (x19 xor y19)
  diff = diff or (x20 xor y20)
  diff = diff or (x21 xor y21)
  diff = diff or (x22 xor y22)
  diff = diff or (x23 xor y23)
  diff = diff or (x24 xor y24)
  diff = diff or (x25 xor y25)
  diff = diff or (x26 xor y26)
  diff = diff or (x27 xor y27)
  diff = diff or (x28 xor y28)
  diff = diff or (x29 xor y29)
  diff = diff or (x30 xor y30)
  diff = diff or (x31 xor y31)

  let allEqual =
    x0 == y0 and x1 == y1 and x2 == y2 and x3 == y3 and
    x4 == y4 and x5 == y5 and x6 == y6 and x7 == y7 and
    x8 == y8 and x9 == y9 and x10 == y10 and x11 == y11 and
    x12 == y12 and x13 == y13 and x14 == y14 and x15 == y15 and
    x16 == y16 and x17 == y17 and x18 == y18 and x19 == y19 and
    x20 == y20 and x21 == y21 and x22 == y22 and x23 == y23 and
    x24 == y24 and x25 == y25 and x26 == y26 and x27 == y27 and
    x28 == y28 and x29 == y29 and x30 == y30 and x31 == y31

  symexAssert((diff == 0'i32) == allEqual)

# -----------------------------------------------------------------------
# Empirical evidence (not the machine-checked artifact itself): the real,
# imported `feEqualCT`/`feIsZeroCT`/`feBytesCanonicalCT` -- called on
# whole `Fe`/`array[32, byte]` values -- agree with a byte-exact
# transliteration of `orAccumulateChain`'s own shape (the shared loop
# quoted directly out of field.nim, not a lookalike) on a boundary-plus-
# random set of concrete vectors. Ordinary testing, not symbolic
# execution; it confirms the FREE-PARAMETER re-encoding is faithful to
# what the real functions actually do -- Z3 already decides the
# accumulate-shape property itself, in full, below (round-2 finding 31's
# lesson: never compare only against a third transcription).
# -----------------------------------------------------------------------

proc orAccumulateLoop(x, y: array[32, byte]): byte =
  ## Verbatim transliteration of field.nim's shared loop body (the tail of
  ## `feEqualCT` and `feBytesCanonicalCT`), operating directly on
  ## `array[32, byte]` -- used only by the concrete cross-check below,
  ## never handed to `symexFind` (array-parameter symbolic execution is
  ## the shape `symex_recode.nim`'s RESOURCE WALL section already flags as
  ## the likely-costly one; see module doc comment above for why this
  ## harness's actual artifact avoids it).
  result = 0
  for i in 0 ..< 32:
    result = result or (x[i] xor y[i])

proc crossCheckRealFunctionsAgreeWithAccumulateShape() =
  proc mkFeFromByte(b: byte): Fe =
    var raw: array[32, byte]
    raw[0] = b
    feFromBytes(raw)

  let boundaryBytes = [0'u8, 1'u8, 2'u8, 0x7F'u8, 0x80'u8, 0xFE'u8, 0xFF'u8]

  var rng = 0xDEADBEEFCAFE1234'u64
  proc nextByte(): byte =
    rng = rng * 6364136223846793005'u64 + 1442695040888963407'u64
    byte(rng shr 40)

  var caseCount = 0

  # `feEqualCT`/`feIsZeroCT`: compare two Fe values (via their canonical
  # feToBytes encodings), boundary cross-product plus random pairs, plus
  # explicit equal-operand cases (the TRUE side of the iff, which a
  # not-equal-biased sampler could otherwise under-exercise).
  for bx in boundaryBytes:
    for by in boundaryBytes:
      let a = mkFeFromByte(bx)
      let b = mkFeFromByte(by)
      let wantEqual = feToBytes(a) == feToBytes(b)
      let gotEqual = feEqualCT(a, b)
      let gotLoop = orAccumulateLoop(feToBytes(a), feToBytes(b)) == 0
      doAssert gotEqual == wantEqual,
        "feEqualCT disagrees with plain feToBytes array equality at bx=" &
        $bx & " by=" & $by
      doAssert gotLoop == wantEqual,
        "orAccumulateLoop disagrees with plain feToBytes array equality " &
        "at bx=" & $bx & " by=" & $by
      doAssert gotEqual == gotLoop,
        "feEqualCT and orAccumulateLoop disagree at bx=" & $bx & " by=" & $by
      inc caseCount

  for _ in 0 ..< 300:
    var rawA, rawB: array[32, byte]
    for i in 0 ..< 32:
      rawA[i] = nextByte()
      rawB[i] = nextByte()
    let a = feFromBytes(rawA)
    let b = feFromBytes(rawB)
    let wantEqual = feToBytes(a) == feToBytes(b)
    let gotEqual = feEqualCT(a, b)
    let gotLoop = orAccumulateLoop(feToBytes(a), feToBytes(b)) == 0
    doAssert gotEqual == wantEqual,
      "feEqualCT disagrees with plain feToBytes array equality on a " &
      "random pair"
    doAssert gotLoop == wantEqual,
      "orAccumulateLoop disagrees with plain feToBytes array equality " &
      "on a random pair"
    doAssert gotEqual == gotLoop,
      "feEqualCT and orAccumulateLoop disagree on a random pair"
    inc caseCount

    # feIsZeroCT: same accumulate shape against FeZero specifically.
    let wantZero = feToBytes(a) == feToBytes(FeZero)
    doAssert feIsZeroCT(a) == wantZero,
      "feIsZeroCT disagrees with plain feToBytes-against-FeZero equality"
    inc caseCount

  # Equal-operand cases explicitly (the TRUE side of the iff): a == a for
  # every boundary Fe and several random ones.
  for bx in boundaryBytes:
    let a = mkFeFromByte(bx)
    doAssert feEqualCT(a, a), "feEqualCT(a, a) must be true (bx=" & $bx & ")"
    doAssert orAccumulateLoop(feToBytes(a), feToBytes(a)) == 0,
      "orAccumulateLoop(a, a) must be zero (bx=" & $bx & ")"
    inc caseCount

  # `feBytesCanonicalCT`: compares feToBytes(feFromBytes(bytes)) against
  # bytes directly -- canonical inputs round-trip equal, non-canonical
  # inputs (>= p) round-trip to different bytes. p = 2^255 - 19.
  var pBytes: array[32, byte]
  pBytes[0] = 0xED'u8
  for i in 1 ..< 31: pBytes[i] = 0xFF'u8
  pBytes[31] = 0x7F'u8
  var pMinus1Bytes = pBytes
  pMinus1Bytes[0] = 0xEC'u8
  var pPlus1Bytes = pBytes
  pPlus1Bytes[0] = 0xEE'u8
  var allZero: array[32, byte]
  var allFF: array[32, byte]
  for i in 0 ..< 32: allFF[i] = 0xFF'u8

  let canonicityVectors = [
    (allZero, true),      # 0 -- canonical
    (pMinus1Bytes, true), # p-1 -- canonical (largest canonical value)
    (pBytes, false),      # p itself -- non-canonical
    (pPlus1Bytes, false), # p+1 -- non-canonical
    (allFF, false),       # 2^255-1 with bit 255 set -- non-canonical
  ]
  for (vec, wantCanonical) in canonicityVectors:
    let roundTrip = feToBytes(feFromBytes(vec))
    let wantEqual = roundTrip == vec
    doAssert wantEqual == wantCanonical,
      "canonicity test vector's own expectation is inconsistent with " &
      "round-trip equality -- fixture bug, not a field.nim bug"
    let gotCanonical = feBytesCanonicalCT(vec)
    let gotLoop = orAccumulateLoop(roundTrip, vec) == 0
    doAssert gotCanonical == wantEqual,
      "feBytesCanonicalCT disagrees with plain round-trip array equality"
    doAssert gotLoop == wantEqual,
      "orAccumulateLoop disagrees with plain round-trip array equality " &
      "(feBytesCanonicalCT shape)"
    doAssert gotCanonical == gotLoop,
      "feBytesCanonicalCT and orAccumulateLoop disagree"
    inc caseCount

  echo "cross-check OK: feEqualCT/feIsZeroCT/feBytesCanonicalCT (the real, " &
       "imported field.nim functions) and orAccumulateLoop (field.nim's " &
       "shared loop body, transliterated for this cross-check only) all " &
       "agree with plain array/byte equality -- and with each other -- on ",
       caseCount, " concrete cases (boundary cross-product, random pairs, " &
       "explicit equal-operand cases, and the canonicity boundary vectors " &
       "p-1/p/p+1/0/2^255-1)"

crossCheckRealFunctionsAgreeWithAccumulateShape()

# -----------------------------------------------------------------------
# The sxUnsat query.
# -----------------------------------------------------------------------
let equalResult = symexFind(orAccumulateChain, tAssertionViolation())

proc report(name: string; r: auto) =
  case r.status
  of sxUnsat:
    echo "PROVED sxUnsat: ", name
  of sxSat:
    echo "COUNTEREXAMPLE FOUND in ", name, " -- witness: ", r.witness
    quit(1)
  of sxUnknown:
    echo "INCONCLUSIVE (sxUnknown) in ", name, ":"
    for e in r.errors: echo "  [", e.severity, "/", e.kind, "] ", e.msg
    quit(1)
  of sxRaised:
    echo "UNEXPECTED RAISE in ", name, " (", r.raisedTypeId, ") -- witness: ",
         r.raisedWitness
    quit(1)

report("orAccumulateChain (the full 32-byte-pair or-accumulate " &
       "composition, chained through 64 free int32 parameters each " &
       "constrained to [0,255]: the accumulated word is zero IFF every " &
       "byte pair is equal, over the FULL domain, not sampled)", equalResult)

echo ""
echo "The or-accumulate shape shared by feEqualCT/feIsZeroCT/" &
     "feBytesCanonicalCT holds for its full domain (Z3 bitvector theory " &
     "decides the whole 64-free-parameter composition exactly, not a " &
     "sampled subset), and crossCheckRealFunctionsAgreeWithAccumulateShape " &
     "confirms the real functions (called directly on Fe/array[32, byte] " &
     "values) agree with this shape -- so together they cover the " &
     "property this file's mission describes: one machine-checked lemma " &
     "for all three consumers, no per-consumer duplication."
