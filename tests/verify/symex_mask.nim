## Machine-checked (Z3-backed) proof of the arithmetic-masking algebra
## behind `field.feCMove`/`field.feCSwap` (round-3 fix batch Z, item Z1),
## using COREY'S proptest library's symbolic-execution engine
## (`proptest/symex`) -- the same tooling and register `tests/verify/
## symex_recode.nim` established for `scalar.recodeScalarRadix16`'s
## digit-range invariant. Read that file's module doc comment first if
## this is your first time in `tests/verify/` -- it is the pattern
## library this harness follows (lemma extraction, exhaustive per-domain
## cross-check against the real implementation, honest scoping of what a
## `sxUnsat` verdict does and doesn't cover).
##
## Standalone, non-suite binary (mirrors `symex_recode.nim`'s and
## `tests/ct/ct_main.nim`'s pattern): NOT part of scripts/test.sh (needs
## z3-devel). Run via `scripts/bmc.sh`, alongside `symex_recode.nim`'s and
## `symex_reduce.nim`'s queries in one invocation (round-3 batch Z's
## bmc.sh wiring).
##
## -----------------------------------------------------------------------
## THE PROPERTY UNDER PROOF, AND ITS SCOPE
## -----------------------------------------------------------------------
## `feCMove`/`feCSwap` (field.nim) are the constant-time selection
## primitives every secret-dependent choice in this codebase routes
## through -- `x25519.nim`'s Montgomery ladder and `scalar.cmovCached`
## (itself feeding `geScalarmultBase`, the signer's fixed-base scalarmult)
## both select between secret-derived field elements ONLY through these
## two functions. Their whole correctness case rests on one small piece
## of bit-twiddling per limb:
##   feCMove:  mask := -int32(b);  r := r xor ((r xor a) and mask)
##   feCSwap:  mask := -int32(swap);  x := (a xor b) and mask;
##             a := a xor x;  b := b xor x
## This harness proves, per limb (a symbolic `int32`, matching `Fe.limbs`'
## element type exactly -- no generalization to a wider int width is
## needed here, unlike `symex_recode.nim`'s `oneStepChain`):
##   (1) MASK CONSTRUCTION: `-int32(b)` is exactly `0'i32` when `b` is
##       false and exactly `-1'i32` (all 32 bits set) when `b` is true --
##       for BOTH boolean values, not sampled.
##   (2) SELECTION CORRECTNESS: GIVEN a mask already known to be `0` or
##       `-1`, the masked-XOR select `r xor ((r xor a) and mask)`
##       (feCMove) yields exactly `r` when `mask = 0` and exactly `a` when
##       `mask = -1`, FOR EVERY possible `int32` value of `r` and `a` --
##       the full domain, not a sampled subset of it.
##   (3) The feCSwap analog: `(a xor b) and mask` then `a xor= x; b xor= x`
##       leaves `(a, b)` unchanged when `mask = 0` and exchanges them when
##       `mask = -1`, again for every `int32` pair.
## (1) and (2)/(3) are proved as SEPARATE lemmas below (`maskConstructStep`
## and `cmoveSelectStep`/`cswapSelectStep`), each a standalone
## `symexFind` target -- not composed into one combined "bool in, select
## out" proc the way the property's own English statement above might
## suggest. See "A THIRD EMPIRICAL SYMEX LIMITATION" below for why: this
## split is tooling-forced, not a stylistic choice, and
## `crossCheckMaskConstructThenSelect` (after both lemmas) chains them
## back together concretely to confirm the split loses nothing.
##
## Because `feCMove`/`feCSwap` themselves are plain `for i in 0..<10` loops
## applying this EXACT one-limb formula independently to each of `Fe`'s 10
## limbs (no cross-limb interaction, no carry propagation of any kind --
## unlike `recodeScalarRadix16`'s loop or `scReduce`'s carry chain, this
## loop has no data dependency between iterations at all), proving the
## one-limb property for ALL `int32` inputs is already the STRONGEST
## possible statement about the whole 10-limb function: the 10-limb
## claim is 10 independent instances of the exact one-limb claim, so
## Z3's per-limb `sxUnsat` verdicts (full-domain proofs, not a
## generalization the way `wholeChainRecode`'s free-nibble domain was a
## generalization of the real byte-decoded nibbles) cover it without
## needing a further "whole-loop" composition query at all -- there is no
## analogous RESOURCE WALL question here, because there is no
## inter-iteration state to compose through.
##
## -----------------------------------------------------------------------
## WHY NO NESTED-CALL WORKAROUND IS NEEDED (contrast with symex_recode.nim)
## -----------------------------------------------------------------------
## `symex_recode.nim`'s module doc comment records two empirical symex
## tooling limitations: (1) an `int32`-typed proc called as a NESTED
## callee that does checked `+`/`shr` arithmetic on its `int32` parameters
## crashes the walker; (2) a tuple-returning proc called as a nested
## callee is unsupported. Both limitations are specifically about NESTED
## calls -- every lemma below is a SINGLE FLAT proc (no nested call to any
## other proc) handed DIRECTLY to `symexFind`, so neither limitation
## applies here, and no `int`-widening or `var`-out-param workaround is
## needed on THAT account. A third, DIFFERENT limitation was found while
## building this harness -- see immediately below.
##
## -----------------------------------------------------------------------
## A THIRD EMPIRICAL SYMEX LIMITATION (found while building this harness):
## a branch-merged int32 local crashes the walker when fed into a binop
## alongside another symbolic value
## -----------------------------------------------------------------------
## The natural one-proc encoding -- compute `mask` from `bFlag` via an
## `if`/`else` (needed anyway, see the mask-construction sub-limitation
## below), THEN use that local `mask` as an operand to `and` (feCMove/
## feCSwap) or `+` (tried during development) alongside another symbolic
## `int32` parameter (`rLimb`) -- crashes the walker, confirmed on
## isolated minimal probes (a 2-3 line proc, nothing else in the file) so
## it is not an artifact of this harness's specific structure:
##   * `result = rLimb and mask` (mask branch-derived, rLimb a free
##     parameter) raises `AssertionDefect: l.kind == r.kind` ("binBV:
##     width mismatch") inside `lowerInExpr`/`lower`.
##   * `result = rLimb + mask` (same shape, `+` instead of `and`) raises
##     `FieldDefect: field 'bv32' is not accessible for type 'SymVal'
##     using 'kind = svBV64'` inside `lowerArith`/`overflowCond` -- the
##     SAME crash signature `symex_recode.nim`'s limitation 1 describes
##     for NESTED int32 calls, but reproduced here on a DIRECT `symexFind`
##     target with no nested call at all, so it is evidently a broader
##     trigger than "nested callee" alone: a branch-merged local's
##     internal representation, whatever it is, does not present as a
##     clean `int32` bitvector to at least two different binop-lowering
##     code paths.
##   * By contrast, a branch-merged local returned BARE (no binop) works
##     fine (`sxUnsat`), and a branch-merged local compared for EQUALITY
##     against literal constants also works fine (`mask == 0'i32 or
##     mask == -1'i32` proves `sxUnsat` with no crash) -- the crash is
##     specific to feeding it into an arithmetic/bitwise BINOP together
##     with another symbolic operand.
##   * Crucially, a FREE TOP-LEVEL PARAMETER (not a branch-derived local)
##     used the same way does NOT crash: `proc probe(rLimb, aLimb,
##     mask: int32)` with `symexAssume(mask == 0'i32 or mask == -1'i32)`
##     then `rLimb xor ((rLimb xor aLimb) and mask)` proves `sxUnsat`
##     cleanly.
##
## WORKAROUND, matching this project's established register (a different
## concrete encoding, checked against the original rather than merely
## assumed equivalent): split "construct the mask from a bool" and "use
## an already-known-binary mask in a binop" into two SEPARATE lemmas, with
## the second treating `mask` as a free `int32` PARAMETER constrained by
## `symexAssume(mask == 0'i32 or mask == -1'i32)` rather than computing it
## from a bool inside the same proc. `crossCheckMaskConstructThenSelect`
## below calls `maskConstructStep` and then `cmoveSelectStep`/
## `cswapSelectStep` in the SAME chained order the real `feCMove`/
## `feCSwap` do (mask constructed, then consumed), on concrete vectors, to
## confirm the two-lemma split, chained together, still reproduces the
## real functions' behavior -- the split changes HOW the proof is
## structured, not WHAT is proved.
import proptest/symex
import sello/field

# -----------------------------------------------------------------------
# Lemma 1: mask construction. A single flat proc, the exact expression
# feCMove/feCSwap both use.
# -----------------------------------------------------------------------

proc maskConstructStep(bFlag: bool): int32 =
  ## Mirrors `let mask = -int32(b)` (feCMove/feCSwap's own literal
  ## source) via `if bFlag: -1'i32 else: 0'i32` -- NOT literally
  ## `-int32(bFlag)`: handing that exact expression to `symexFind`
  ## (confirmed on an isolated probe, independent of whether the cast
  ## result is first bound to a `let` before negating it) produces
  ## `sxUnknown` with `weInternalWalkerFault: ValueError: negBV on
  ## non-BV SymVal` -- a bool-to-int32 conversion's result apparently
  ## does not reach the negation operator's BV code path as a proper
  ## bitvector value. The `if`/`else` form is a tooling-forced
  ## re-encoding, proved (not assumed) equivalent to `-int32(b)` for both
  ## boolean values by `crossCheckMaskConstructReencoding` below.
  result = if bFlag: -1'i32 else: 0'i32
  symexAssert(result == 0'i32 or result == -1'i32)

proc crossCheckMaskConstructReencoding() =
  ## `maskConstructStep`'s `if`/`else` body vs. the real source's literal
  ## `-int32(b)`, for both boolean values -- exhaustive, not sampled
  ## (only 2 cases exist).
  for b in [false, true]:
    let reencoded = maskConstructStep(b)
    let original = -int32(b)
    doAssert reencoded == original,
      "maskConstructStep disagrees with -int32(b) (feCMove/feCSwap's " &
      "literal source expression) at b=" & $b
  echo "cross-check OK: maskConstructStep matches -int32(b) on both " &
       "boolean values"

crossCheckMaskConstructReencoding()

# -----------------------------------------------------------------------
# Lemma 2/3: masked select, given an ALREADY-CONSTRUCTED mask (a free
# int32 parameter, assumed via symexAssume to be 0 or -1 -- see "A THIRD
# EMPIRICAL SYMEX LIMITATION" above for why the mask cannot instead be
# computed from a bool inside these same procs).
# -----------------------------------------------------------------------

proc cmoveSelectStep(rLimb, aLimb, mask: int32): int32 =
  ## Verbatim one-limb select body of `feCMove`'s loop (field.nim):
  ##   r.limbs[i] := r.limbs[i] xor ((r.limbs[i] xor a.limbs[i]) and mask)
  ## GIVEN `mask` already known to be `0` or `-1` (the postcondition
  ## `maskConstructStep` establishes for it).
  symexAssume(mask == 0'i32 or mask == -1'i32)
  result = rLimb xor ((rLimb xor aLimb) and mask)
  if mask == -1'i32:
    symexAssert(result == aLimb)
  else:
    symexAssert(result == rLimb)

proc cswapSelectStep(aLimb, bLimb, mask: int32): tuple[aOut, bOut: int32] =
  ## Verbatim one-limb select body of `feCSwap`'s loop (field.nim):
  ##   x := (a.limbs[i] xor b.limbs[i]) and mask
  ##   a.limbs[i] := a.limbs[i] xor x; b.limbs[i] := b.limbs[i] xor x
  ## GIVEN `mask` already known to be `0` or `-1`.
  symexAssume(mask == 0'i32 or mask == -1'i32)
  let x = (aLimb xor bLimb) and mask
  let aOut = aLimb xor x
  let bOut = bLimb xor x
  if mask == -1'i32:
    symexAssert(aOut == bLimb and bOut == aLimb)
  else:
    symexAssert(aOut == aLimb and bOut == bLimb)
  (aOut, bOut)

# -----------------------------------------------------------------------
# Empirical evidence (not the machine-checked artifact itself): the real,
# imported `feCMove`/`feCSwap` -- called on whole `Fe` values -- agree
# with `maskConstructStep` CHAINED INTO `cmoveSelectStep`/`cswapSelectStep`
# (the same order the real functions use: construct the mask, then
# consume it), applied per limb. Ordinary testing, not symbolic
# execution; it exercises the exact functions `symexFind` proves below
# (round-2 finding 31's lesson: never compare against a third
# transcription), over a boundary-plus-random `int32` domain -- the full
## 2^32 x 2^32 x 2 domain is enumerable by Z3 (bitvector theory decides it
## exactly, see the module doc comment above) but far too large to check
## concretely here, so this cross-check's job is only to confirm the
## EXTRACTION (and the two-lemma split) is faithful to the real per-limb
## loop body, not to re-establish the property Z3 already decides in full.
# -----------------------------------------------------------------------
proc crossCheckMaskConstructThenSelect() =
  proc mkFe(limbs: array[10, int32]): Fe =
    ## Bypasses `feFromLimbs`'s debug-only magnitude assert (this
    ## cross-check deliberately includes out-of-normal-range boundary
    ## limbs like `int32.low`/`int32.high` -- feCMove/feCSwap's own
    ## algebra places no requirement on the limb's magnitude, only
    ## `feFromLimbs`'s stricter field-element precondition does, and that
    ## precondition is irrelevant to the bitwise mask property this file
    ## proves).
    Fe(limbs: limbs)

  let boundaryLimbs = [
    0'i32, 1'i32, -1'i32, int32.high, int32.low,
    12345'i32, -98765'i32, 67108863'i32, -67108864'i32
  ]

  var rng = 0x1234567890ABCDEF'u64
  proc nextLimb(): int32 =
    rng = rng * 6364136223846793005'u64 + 1442695040888963407'u64
    int32(rng shr 33)

  var caseCount = 0
  for bFlag in [false, true]:
    let mask = maskConstructStep(bFlag)

    # Boundary x boundary limb pairs (feCMove/feCSwap, cross product).
    for ra in boundaryLimbs:
      for aa in boundaryLimbs:
        var r = mkFe([ra, ra, ra, ra, ra, ra, ra, ra, ra, ra])
        let a = mkFe([aa, aa, aa, aa, aa, aa, aa, aa, aa, aa])
        let rBefore = r
        feCMove(r, a, bFlag)
        for i in 0 ..< 10:
          let want = cmoveSelectStep(rBefore.limbs[i], a.limbs[i], mask)
          doAssert r.limbs[i] == want,
            "maskConstructStep+cmoveSelectStep has drifted from feCMove " &
            "at limb value ra=" & $ra & " aa=" & $aa & " b=" & $bFlag
        inc caseCount

        var x = mkFe([ra, ra, ra, ra, ra, ra, ra, ra, ra, ra])
        var y = mkFe([aa, aa, aa, aa, aa, aa, aa, aa, aa, aa])
        let xBefore = x
        let yBefore = y
        feCSwap(x, y, bFlag)
        for i in 0 ..< 10:
          let (wantA, wantB) = cswapSelectStep(xBefore.limbs[i], yBefore.limbs[i], mask)
          doAssert x.limbs[i] == wantA and y.limbs[i] == wantB,
            "maskConstructStep+cswapSelectStep has drifted from feCSwap " &
            "at limb value ra=" & $ra & " aa=" & $aa & " swap=" & $bFlag
        inc caseCount

    # Random limb pairs, same two checks, larger sample.
    for _ in 0 ..< 200:
      let ra = nextLimb()
      let aa = nextLimb()
      var r = mkFe([ra, nextLimb(), ra, nextLimb(), ra, nextLimb(), ra, nextLimb(), ra, nextLimb()])
      var a = mkFe([aa, nextLimb(), aa, nextLimb(), aa, nextLimb(), aa, nextLimb(), aa, nextLimb()])
      let rBefore = r
      let aBefore = a
      feCMove(r, a, bFlag)
      for i in 0 ..< 10:
        let want = cmoveSelectStep(rBefore.limbs[i], aBefore.limbs[i], mask)
        doAssert r.limbs[i] == want,
          "maskConstructStep+cmoveSelectStep has drifted from feCMove " &
          "on a random vector"
      inc caseCount

      var x = rBefore
      var y = aBefore
      let xBefore = x
      let yBefore = y
      feCSwap(x, y, bFlag)
      for i in 0 ..< 10:
        let (wantA, wantB) = cswapSelectStep(xBefore.limbs[i], yBefore.limbs[i], mask)
        doAssert x.limbs[i] == wantA and y.limbs[i] == wantB,
          "maskConstructStep+cswapSelectStep has drifted from feCSwap " &
          "on a random vector"
      inc caseCount

  echo "cross-check OK: maskConstructStep chained into cmoveSelectStep/" &
       "cswapSelectStep (the real functions' own construct-then-consume " &
       "order) matches feCMove/feCSwap (called on whole Fe values) on ",
       caseCount, " concrete (limb-pair, flag) cases (boundary " &
       "cross-product + random)"

crossCheckMaskConstructThenSelect()

# -----------------------------------------------------------------------
# The machine-checked artifact: three separate lemmas (see "A THIRD
# EMPIRICAL SYMEX LIMITATION" above for why mask-construction and
# masked-select could not be one combined query).
# -----------------------------------------------------------------------
let maskResult = symexFind(maskConstructStep, tAssertionViolation())
let cmoveResult = symexFind(cmoveSelectStep, tAssertionViolation())
let cswapResult = symexFind(cswapSelectStep, tAssertionViolation())

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

report("maskConstructStep (-int32(b), re-encoded: produces exactly 0 or " &
       "-1, for both boolean values)", maskResult)
report("cmoveSelectStep (feCMove's one-limb select, given mask in {0,-1}: " &
       "selects a iff mask=-1, else r -- over the FULL int32 x int32 " &
       "domain)", cmoveResult)
report("cswapSelectStep (feCSwap's one-limb select, given mask in {0,-1}: " &
       "(a,b) exchanged iff mask=-1, else unchanged -- over the FULL " &
       "int32 x int32 domain)", cswapResult)

echo ""
echo "All three mask-algebra lemmas hold for their full domains (Z3 " &
     "bitvector theory decides each exactly, not a sampled subset), and " &
     "crossCheckMaskConstructThenSelect confirms chaining " &
     "maskConstructStep into cmoveSelectStep/cswapSelectStep (the real " &
     "functions' own order) reproduces feCMove/feCSwap's concrete " &
     "behavior -- so together the three lemmas cover the same ground the " &
     "mission's single combined property describes, split only because " &
     "of the tooling limitation documented above. Because feCMove/" &
     "feCSwap apply this one-limb formula independently to each of Fe's " &
     "10 limbs with no inter-limb data dependency, these one-limb " &
     "verdicts already cover the full 10-limb function; no separate " &
     "whole-loop composition query is needed or attempted here (contrast " &
     "tests/verify/symex_recode.nim's wholeChainRecode, which composes a " &
     "genuinely data-dependent chain)."
