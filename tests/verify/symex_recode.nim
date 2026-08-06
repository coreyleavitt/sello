## Machine-checked (Z3-backed) proof of `scalar.recodeScalarRadix16`'s
## digit-range invariant (RFC-001 review finding 22), using COREY'S
## proptest library's symbolic-execution engine (`proptest/symex`).
##
## Standalone, non-suite binary (mirrors `tests/ct/ct_main.nim`'s and
## `tests/fuzz/fuzz_main.nim`'s pattern): NOT part of scripts/test.sh
## (needs z3-devel; the ordinary dev loop shouldn't pay for the solver).
## Run via `scripts/bmc.sh`, which wraps this in a hard kill-timeout the
## same way proptest's own `scripts/dt-bounded.sh` does -- symex/Z3 queries
## can hang or exhaust resources on some shapes (see the RESOURCE WALL
## note below -- this is not a hypothetical risk in this harness, it is
## what actually happened on the first attempt).
##
## -----------------------------------------------------------------------
## THE PROPERTY UNDER PROOF, AND ITS SCOPE (read this before the verdict)
## -----------------------------------------------------------------------
## `recodeScalarRadix16`'s own doc comment (scalar.nim) states the range
## invariant for any 32-byte scalar with bit 255 clear:
##   digits[0..62] in [-8, 7]
##   digits[63]    in [-8, 8]
## Previously this was only SAMPLED: `tests/unit/test_properties_scalar.nim`
## checks 200 scalars (100 clamped-domain, 100 reduced-mod-L) drawn from
## proptest's PBT generator, against 2^255 possible bit-255-clear inputs.
##
## THIS HARNESS DOES NOT MACHINE-CHECK THE WHOLE FUNCTION IN ONE SHOT. The
## natural approach -- symbolically execute all 32 input bytes through the
## function's own two `for` loops, fully unwound (32 then 63 iterations,
## both counts input-independent -- see the RESOURCE WALL note) -- was
## attempted first and did not complete: killed by `scripts/bmc.sh`'s hard
## timeout after 300s wall-clock, with no sat/unsat/unknown verdict ever
## produced. That is a resource-exhaustion result, not a proof of
## infeasibility -- it may well complete given a longer budget or more
## RAM/CPU than this environment provides -- but "ran for 5 minutes and
## was killed" is not a finding this harness gets to round up to "proved."
## The attempted code is preserved, inert, at the bottom of this file
## (behind `-d:selloBmcFullUnroll`) for exactly that reason: a future run
## with more resources can flip it on without reconstructing it from
## scratch.
##
## What DOES run, and complete, below: the **per-iteration inductive
## lemma** the mission's own fallback names as the strongest tractable
## statement when the whole-loop proof isn't tractable. `recodeScalarRadix16`'s
## carry-propagation loop is, line for line:
##   result[i] += carry
##   carry = (result[i] + 8) shr 4
##   result[i] -= carry shl 4
## `oneStep` below is exactly those three lines, extracted verbatim, as a
## tiny standalone function of two symbolic inputs (the pre-carry nibble,
## the incoming carry) instead of 63 iterations threaded through a 256-bit
## symbolic array. `finalStep` is the i==63 case (no post-carry
## truncation, but a tighter nibble bound from the bit-255-clear
## precondition). Both are exhaustively decidable by Z3 in well under a
## second (32 nibble values x 2 carry values = 64 concrete cases each, not
## an exponential path count) -- see the verdict output for actual timing.
##
## The gap this leaves, stated precisely: Z3 checks each step in
## isolation, not the 63-step CHAIN. The composition --  "carry starts at
## 0 in {0,1}; oneStep's postcondition (carryOut in {0,1}) is exactly its
## own next call's precondition; therefore by induction over i = 0..62
## every digit lands in range and every intermediate carry stays in
## {0,1}; finalStep then closes i = 63" -- is a standard, mechanical
## induction, but it is a MANUAL argument in this module's prose, not a
## single artifact Z3 verified end to end. That is real, bounded
## incompleteness relative to the ideal ("prove the whole function"), not
## swept under a broader claim: this harness proves the per-step lemma
## exhaustively and states the induction that closes the gap; it does not
## claim Z3 checked the induction itself.
import proptest/symex
import sello/scalar  # for the cross-check only, not entered by symex (see below)

# -----------------------------------------------------------------------
# RESOURCE WALL (empirical, this environment, this run)
# -----------------------------------------------------------------------
# Attempt: symbolically execute the real loop shape (32-byte input,
# `maxLoopUnwind = 64`, `arithChecks = {}` -- see the retired
# `whenFullUnrollAttempt` block at the end of this file for the exact
# settings and wrapper used) via `tAssertionViolation()`. `scripts/bmc.sh
# 300` killed the container with SIGKILL after the full 300s budget with
# no verdict printed -- not `sxUnknown` (which the walker prints itself
# when IT gives up), an external kill of a still-running solver/walker
# process. Plausible causes (not diagnosed further -- out of scope for
# this batch): the 256-bit symbolic input plus 63 sequentially-dependent
# carry forks may simply be a large-but-finite BV query that needs more
# than 300s, or the walker/solver may be hitting a genuine non-termination
# shape like the "F5 incident" this file's header already cites
# (docs/symex/... in the proptest repo: a mixed-theory
# int2bv(bv2int(x))-style query spun a full core for 24+ minutes on an
# unrelated SUT). Either way, "prove the strongest TRACTABLE statement"
# means backing off to the per-iteration lemma below rather than either
# (a) reporting a full blocker when a real, honestly-scoped result is
# available, or (b) re-running the whole-loop attempt with an ever-larger
# timeout hoping it eventually lands.

proc oneStep(nibble: int32, carryIn: int32): tuple[digit, carryOut: int32] =
  ## Verbatim body of one non-final loop iteration of
  ## `recodeScalarRadix16` (scalar.nim), with `result[i]` renamed
  ## `nibble` (the pre-carry value) and `carry`/`carryOut` made explicit
  ## parameter/local values instead of loop-carried state. Both
  ## postconditions (digit range AND carry-out range) are asserted here,
  ## in the same symbolic run, so a single `sxUnsat` verdict covers both
  ## halves of the inductive step at once. Returns BOTH `digit` and
  ## `carryOut` (a tuple, not just `digit`) so the cross-check below can
  ## call this exact function in a loop, threading `carryOut` into the
  ## next call's `carryIn` the same way `recodeScalarRadix16`'s own loop
  ## threads its `carry` local -- `symexFind` only inspects a proc's
  ## PARAMETERS to build its witness tuple (see `proptest/symex`'s
  ## `parseProc`/`emitTyAndReader`), so widening the return type from
  ## `int32` to this tuple changes nothing about what gets proved below.
  symexAssume(nibble >= 0'i32 and nibble <= 15'i32)   # a nibble from `s[i] and 0xF` / `(s[i] shr 4) and 0xF`
  symexAssume(carryIn == 0'i32 or carryIn == 1'i32)   # the loop's own invariant, established by induction (see module doc)
  var digit = nibble + carryIn
  let carryOut = (digit + 8'i32) shr 4'i32
  digit = digit - (carryOut shl 4'i32)
  symexAssert(digit >= -8'i32 and digit <= 7'i32)
  symexAssert(carryOut == 0'i32 or carryOut == 1'i32)
  (digit, carryOut)

proc finalStep(nibble: int32, carryIn: int32): int32 =
  ## The i == 63 case: `result[63] += carry` with NO subsequent
  ## truncation (the loop that shifts/masks only runs `for i in 0 ..< 63`;
  ## index 63 is folded in afterward as a single `+=`). The nibble bound
  ## is tighter than the general [0,15] case: `s[31] shr 4` is the TOP
  ## nibble of the scalar's last byte, and the bit-255-clear precondition
  ## is exactly "that nibble's own top bit is clear," i.e. the nibble is
  ## in [0,7], not [0,15]. Returns `digit` (previously a bare assertion
  ## with no return value) so the cross-check below can use this exact
  ## function to produce `result[63]`, the same way `oneStep` produces
  ## `result[0..62]`.
  symexAssume(nibble >= 0'i32 and nibble <= 7'i32)
  symexAssume(carryIn == 0'i32 or carryIn == 1'i32)
  let digit = nibble + carryIn
  symexAssert(digit >= -8'i32 and digit <= 8'i32)
  digit

# -----------------------------------------------------------------------
# Empirical evidence (not the machine-checked artifact itself): the real,
# imported `recodeScalarRadix16` and `oneStep`/`finalStep` -- called
# directly, in a loop, threading the carry exactly as the real loop does --
# agree on concrete vectors. This is ordinary testing, not symbolic
# execution -- it does not extend the proof to the full input domain
# (that's what the lemmas above are for) -- but it directly exercises the
# same functions `symexFind` proves below, so a future edit that breaks
# their agreement with `recodeScalarRadix16` cannot slip past unnoticed
# (round-2 finding 31: an earlier version of this cross-check compared
# against a separate `viaSteps` transcription instead of `oneStep`/
# `finalStep` themselves, so it could not have caught that class of drift).
proc crossCheckAgainstRealImplementation() =
  ## Calls `oneStep`/`finalStep` -- the EXACT functions `symexFind` proves
  ## below, not a third transcription of the same arithmetic -- directly,
  ## in a loop that threads the carry precisely the way
  ## `recodeScalarRadix16`'s own loop does (`carry` starts at 0, each
  ## `oneStep` call's `carryOut` becomes the next call's `carryIn`,
  ## `finalStep` closes out index 63). Round-2 finding 31: the previous
  ## version of this cross-check instead ran a separate `viaSteps` proc, a
  ## THIRD hand-transcribed copy of the loop body that happened to also
  ## match `recodeScalarRadix16` -- meaning this check could pass even if
  ## `oneStep`/`finalStep` themselves (the functions actually handed to
  ## `symexFind`) had silently drifted from the real function, since
  ## nothing here ever called them. Calling them directly closes that
  ## gap: this cross-check and the `symexFind` calls below now run the
  ## identical code, so a future edit to either lemma that breaks its
  ## agreement with `recodeScalarRadix16` fails loudly here before the
  ## solver ever runs.
  proc runOneStepFinalStep(s: array[32, byte]): array[64, int32] =
    for i in 0 ..< 32:
      result[2 * i] = int32(s[i] and 0xF)
      result[2 * i + 1] = int32((s[i] shr 4) and 0xF)
    var carry: int32 = 0
    for i in 0 ..< 63:
      let (digit, carryOut) = oneStep(result[i], carry)
      result[i] = digit
      carry = carryOut
    result[63] = finalStep(result[63], carry)

  var vectors: seq[array[32, byte]]
  var allZero: array[32, byte]
  vectors.add allZero
  var maxClear: array[32, byte]
  for i in 0 ..< 32: maxClear[i] = 0xFF'u8
  maxClear[31] = 0x7F'u8  # bit 255 clear, everything else set
  vectors.add maxClear
  var single: array[32, byte]
  single[0] = 1'u8
  vectors.add single
  var rng = 0x2A2A2A2A2A2A2A2A'u64
  for _ in 0 ..< 20:
    var v: array[32, byte]
    for i in 0 ..< 32:
      rng = rng * 6364136223846793005'u64 + 1442695040888963407'u64
      v[i] = byte((rng shr 33) and 0xFF)
    v[31] = v[31] and 0x7F'u8  # bit 255 clear precondition
    vectors.add v

  for v in vectors:
    let fromReal = recodeScalarRadix16(v)
    let fromSteps = runOneStepFinalStep(v)
    doAssert fromReal == fromSteps,
      "oneStep/finalStep's arithmetic has drifted from the real " &
      "recodeScalarRadix16 -- the lemmas below would be proving " &
      "something other than this function's actual loop body."
  echo "cross-check OK: oneStep/finalStep (called directly, carry threaded " &
       "exactly as the real loop does) match recodeScalarRadix16 on ",
       vectors.len, " concrete vectors"

crossCheckAgainstRealImplementation()

# -----------------------------------------------------------------------
# The machine-checked artifact: two small, fast symexFind calls.
# -----------------------------------------------------------------------
let stepResult = symexFind(oneStep, tAssertionViolation())
let finalResult = symexFind(finalStep, tAssertionViolation())

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

report("oneStep (non-final iteration: nibble in [0,15], carryIn in {0,1} " &
       "=> digit in [-8,7], carryOut in {0,1})", stepResult)
report("finalStep (i=63: nibble in [0,7] (bit-255-clear-bounded), " &
       "carryIn in {0,1} => digit in [-8,8])", finalResult)

echo ""
echo "Both per-iteration lemmas hold for ALL nibble/carry combinations " &
     "(exhaustively decided by Z3, not sampled)."
echo "The 63-step composition (carry starts at 0 in {0,1}; oneStep's " &
     "carryOut is exactly the next call's carryIn; by induction every " &
     "digit lands in range) is a manual argument in this file's module " &
     "doc comment, not itself a single Z3-checked artifact -- see the " &
     "HONEST SCOPE note at the top of this file. The whole-function, " &
     "whole-domain symbolic execution was attempted and did not complete " &
     "within this environment's resources (see RESOURCE WALL above)."

# -----------------------------------------------------------------------
# Retired: the full whole-loop, whole-domain attempt (RESOURCE WALL above).
# Preserved so a future run with more time/RAM can retry it without
# reconstructing it from scratch. NOT compiled by default -- opt in with
# `-d:selloBmcFullUnroll` (and expect it to need much more than 300s; see
# scripts/bmc.sh's usage comment for how to pass a larger timeout).
# -----------------------------------------------------------------------
when defined(selloBmcFullUnroll):
  proc recodeRangeCheckBody(s: array[32, byte]): array[64, int32] =
    ## Verbatim copy of `scalar.recodeScalarRadix16`'s body, declared as a
    ## plain `proc` (not `func`) because symex's parser could not resolve
    ## `getImpl` for a `func`-kind callee, in-module or cross-module (see
    ## the B4b summary in docs/rfc-001-signing.handoff.md for the fuller
    ## writeup of that finding -- trimmed here since this whole block is
    ## inert by default).
    for i in 0 ..< 32:
      result[2 * i] = int32(s[i] and 0xF)
      result[2 * i + 1] = int32((s[i] shr 4) and 0xF)
    var carry: int32 = 0
    for i in 0 ..< 63:
      result[i] += carry
      carry = (result[i] + 8) shr 4
      result[i] -= carry shl 4
    result[63] += carry

  proc recodeRangeCheck(s: array[32, byte]) =
    symexAssume((s[31] and 0x80'u8) == 0'u8)
    let digits = recodeRangeCheckBody(s)
    for i in 0 ..< 63:
      symexAssert(digits[i] >= -8'i32 and digits[i] <= 7'i32)
    symexAssert(digits[63] >= -8'i32 and digits[63] <= 8'i32)

  const fullSettings = static:
    var s = defaultSymexSettings()
    s.budget.maxLoopUnwind = 64
    s.arithChecks = {}
    s

  let fullResult = symexFind(recodeRangeCheck, tAssertionViolation(), fullSettings)
  report("recodeRangeCheck (full whole-loop, whole-domain attempt)", fullResult)
