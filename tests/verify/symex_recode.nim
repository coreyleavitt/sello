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
## THIS HARNESS DOES NOT MACHINE-CHECK THE LITERAL FUNCTION, BYTE ARRAY IN,
## DIGIT ARRAY OUT, IN ONE SHOT. The natural approach -- symbolically
## execute all 32 input bytes through the function's own two `for` loops,
## fully unwound (32 then 63 iterations, both counts input-independent --
## see the RESOURCE WALL note) -- was attempted first and did not
## complete: killed by `scripts/bmc.sh`'s hard timeout after 300s
## wall-clock, with no sat/unsat/unknown verdict ever produced. That is a
## resource-exhaustion result, not a proof of infeasibility -- it may well
## complete given a longer budget or more RAM/CPU than this environment
## provides -- but "ran for 5 minutes and was killed" is not a finding
## this harness gets to round up to "proved." The attempted code is
## preserved, inert, at the bottom of this file (behind
## `-d:selloBmcFullUnroll`) for exactly that reason: a future run with
## more resources can flip it on without reconstructing it from scratch.
##
## RFC-002 slice 4 item 3 (`wholeChainRecode`, see "Z3 WHOLE-CHAIN
## ATTEMPT" below) DOES machine-check the full 63-step composition, but
## over a STRICT GENERALIZATION of the real function's input shape --  64
## independent free symbolic nibbles rather than 32 symbolic input bytes
## decoded into nibbles -- not literally the byte-array-in-digit-array-out
## function above. Every real scalar's 64 nibbles are one instance of "64
## independent values, each in its own legal range" (real nibbles
## additionally come in same-byte pairs, a constraint the generalization
## does not impose), so proving the range invariant over the free-nibble
## superset implies it for every real bit-255-clear scalar too -- but it
## is worth stating precisely rather than blurring into "the whole
## function is now machine-checked in one shot," which would overclaim
## what was actually proved.
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
## The gap this used to leave (RFC-001 review finding 22, CLOSED by
## RFC-002 slice 4 item 3 -- see "Z3 WHOLE-CHAIN ATTEMPT" below): Z3
## checked each step in isolation, not the 63-step CHAIN, and the
## composition was a MANUAL argument in this module's prose rather than a
## single Z3-checked artifact. `wholeChainRecode` below now closes that
## gap: a single `sxUnsat` verdict over 64 independent free symbolic
## nibbles, chained through the same per-step arithmetic, machine-checks
## the full composition -- no manual induction step remains. See the "Z3
## WHOLE-CHAIN ATTEMPT" section below for the exact encoding and the
## empirical tooling limitations that shaped it.
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
#
# -----------------------------------------------------------------------
# Z3 WHOLE-CHAIN ATTEMPT (RFC-002 slice 4 item 3): 64 free symbolic
# nibbles, no byte array -- SUCCEEDED (sxUnsat)
# -----------------------------------------------------------------------
# RFC-002's hypothesis: the first attempt's resource exhaustion was caused
# by symbolically decoding a 32-byte array into 64 nibbles (bit-shift +
# mask extraction on a symbolic byte array, `s[i] and 0xF` /
# `(s[i] shr 4) and 0xF`, folded into a mutated `array[64, int32]` local)
# -- NOT by the 63-step carry-chain arithmetic itself, which has no
# branching (every step is straight-line arithmetic, no `if`). The fix: a
# strict generalization that drops the byte-array encoding entirely -- 64
# INDEPENDENT free symbolic parameters, each already constrained to its
# nibble's legal range, with NO array anywhere (state threaded between
# steps via plain scalar locals, not array reads/writes).
#
# TWO EMPIRICAL SYMEX LIMITATIONS, found by isolated scratch probes before
# landing on the working encoding below (same standard this project
# already holds itself to elsewhere -- e.g. `signing.Seed`'s distinct-
# array finding, RFC-002 slice 2's `checks: off`/`assertions` finding):
#
#   1. Calling an `int32`-typed proc as a NESTED callee (i.e. not the
#      direct `symexFind` SUT itself) and doing checked `+`/`shr`
#      arithmetic on its `int32` parameters inside that nested call
#      crashes the walker outright: `Error: unhandled exception: field
#      'bv32' is not accessible for type 'SymVal' using 'kind = svBV64'
#      [FieldDefect]`, deep in `proptest/smt/runtime.nim`'s
#      `lowerArith`/`overflowCond`. Reproduced on a minimal 1-call and
#      2-call harness with plain `int32` arithmetic, nothing scalar.nim-
#      specific about it. Neither `{.push overflowChecks: off.}` at the
#      Nim-pragma level NOR `SymexSettings.arithChecks = {}` (which the
#      retired `-d:selloBmcFullUnroll` attempt below already sets, for a
#      different reason) suppresses it -- the crash site is unconditional
#      `int32`-width bookkeeping in the interprocedural call path, not the
#      optional arithmetic-defect-fork feature `arithChecks` gates.
#   2. Independently, a proc that RETURNS A TUPLE and is called as a
#      nested callee hits a *different*, more gracefully-handled gap:
#      `sxUnknown` with `weInternalWalkerFault: ValueError: retBindEq:
#      composite-typed proc return not yet wired -- got svTuple`. This
#      reproduces even with plain `int` (once limitation 1's width crash
#      is out of the way), confirming it is a second, separate gap: this
#      symex version's interprocedural call-return binding does not yet
#      support composite (tuple) return types for callees, only for the
#      proc handed directly to `symexFind`. `oneStep` above returns a
#      tuple specifically so `symexFind(oneStep, ...)` and the cross-check
#      loop above can both use it as-is when `oneStep` IS the direct SUT
#      (or called from ordinary, non-symbolic Nim code) -- both of those
#      remain unaffected; only calling `oneStep` itself, unmodified, as a
#      NESTED callee from another SUT is the combination that doesn't
#      work in this version.
#
# WORKAROUND, confirmed correct by exhaustive cross-check below rather
# than assumed: `oneStepChain`/`finalStepChain`, defined after
# `crossCheckAgainstRealImplementation`, are tooling-compatible
# re-encodings of `oneStep`/`finalStep` -- byte-for-byte the same three
# lines of arithmetic and the same two `symexAssert` postconditions --
# using plain `int` (sidesteps limitation 1; the value ranges involved
# are tiny (nibble in [0,15], carry in {0,1}), so `int` vs `int32` changes
# no mathematical content, only the symbolic width symex models) and a
# `var` output parameter instead of a tuple return (sidesteps limitation
# 2). `wholeChainRecode` below chains 63 calls to `oneStepChain` plus one
# to `finalStepChain` this way. Both variants are checked EXHAUSTIVELY
# (not sampled) against `oneStep`/`finalStep` over their entire concrete
# domain (32 and 16 (nibble, carry) pairs respectively) immediately below
# `crossCheckAgainstRealImplementation`, closing the "two independently-
# typed-out implementations could silently drift" risk the same way round
# -2 finding 31 already closed it once for the sampled cross-check.
#
# VERDICT: `symexFind(wholeChainRecode, tAssertionViolation())` (default
# `SymexSettings`, no special budget) returned `sxUnsat` in this
# environment -- roughly 84s wall-clock for the full 64-step chain in a
# `nim c -r` run (compile + Z3 solve), well inside `scripts/bmc.sh`'s
# kill-timeout. The full 63-step composition is therefore now MACHINE-
# CHECKED, not manually argued -- see `chainResult`'s `report(...)` near
# the bottom of this file. The manual-induction caveat this section used
# to describe is RETIRED (also updated in CLAUDE.md's validation-bar
# entry and docs/rfc-001-signing.md; docs/rfc-002-audit-remediation.md's
# slice-4 text is left as-is per that RFC's own instruction, since it
# records the plan, not the outcome).

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
# RFC-002 slice 4 item 3: `oneStepChain`/`finalStepChain` -- tooling-
# compatible re-encodings of `oneStep`/`finalStep` (plain `int`, `var`
# output parameter instead of a tuple return) needed to work around the
# two empirical symex limitations documented in the "Z3 WHOLE-CHAIN
# ATTEMPT" module-doc section above. Byte-for-byte the same three lines
# of arithmetic and the same two postconditions as `oneStep`/`finalStep`;
# NOT a third hand-transcribed copy left to drift unnoticed (round-2
# finding 31's lesson) -- checked EXHAUSTIVELY against `oneStep`/
# `finalStep` immediately below, over every concrete (nibble, carry) pair
# in their domain (32 and 16 pairs respectively), not sampled.
# -----------------------------------------------------------------------

proc oneStepChain(nibble: int; carryIn: int; digitOut: var int): int =
  ## Same arithmetic as `oneStep`, `int`-typed with `digit` returned via
  ## `var` output parameter instead of a tuple (see module doc comment).
  symexAssume(nibble >= 0 and nibble <= 15)
  symexAssume(carryIn == 0 or carryIn == 1)
  var digit = nibble + carryIn
  let carryOut = (digit + 8) shr 4
  digit = digit - (carryOut shl 4)
  symexAssert(digit >= -8 and digit <= 7)
  symexAssert(carryOut == 0 or carryOut == 1)
  digitOut = digit
  result = carryOut

proc finalStepChain(nibble: int; carryIn: int): int =
  ## Same arithmetic as `finalStep`, `int`-typed (no tuple involved here
  ## to begin with, but kept `int` for consistency with `oneStepChain`
  ## along the same chain).
  symexAssume(nibble >= 0 and nibble <= 7)
  symexAssume(carryIn == 0 or carryIn == 1)
  let digit = nibble + carryIn
  symexAssert(digit >= -8 and digit <= 8)
  digit

proc crossCheckChainVariants() =
  ## EXHAUSTIVE (not sampled) agreement check, ordinary Nim runtime code:
  ## `oneStepChain`/`finalStepChain` must produce the identical `digit`
  ## and `carryOut` as `oneStep`/`finalStep` for every concrete input in
  ## their respective domains. `oneStep`'s domain is 16 nibble values x 2
  ## carry values = 32 pairs; `finalStep`'s is 8 x 2 = 16 pairs -- both
  ## small enough to check exhaustively rather than sample, closing the
  ## drift risk completely rather than probabilistically.
  for nibble in 0'i32 .. 15'i32:
    for carryIn in 0'i32 .. 1'i32:
      let (wantDigit, wantCarryOut) = oneStep(nibble, carryIn)
      var gotDigit: int
      let gotCarryOut = oneStepChain(int(nibble), int(carryIn), gotDigit)
      doAssert gotDigit == int(wantDigit) and gotCarryOut == int(wantCarryOut),
        "oneStepChain has drifted from oneStep at nibble=" & $nibble &
        " carryIn=" & $carryIn
  for nibble in 0'i32 .. 7'i32:
    for carryIn in 0'i32 .. 1'i32:
      let want = finalStep(nibble, carryIn)
      let got = finalStepChain(int(nibble), int(carryIn))
      doAssert got == int(want),
        "finalStepChain has drifted from finalStep at nibble=" & $nibble &
        " carryIn=" & $carryIn
  echo "cross-check OK: oneStepChain/finalStepChain match oneStep/finalStep " &
       "on all 32 + 16 = 48 concrete (nibble, carryIn) pairs (exhaustive, not sampled)"

crossCheckChainVariants()

# -----------------------------------------------------------------------
# The whole-chain attempt itself: 64 independent free symbolic nibbles
# chained through oneStepChain/finalStepChain in ONE symexFind -- see the
# "Z3 WHOLE-CHAIN ATTEMPT" module-doc section above for the full writeup,
# the two empirical symex limitations that shaped this encoding, and the
# outcome (sxUnsat).
# -----------------------------------------------------------------------
proc wholeChainRecode*(n0: int, n1: int, n2: int, n3: int, n4: int, n5: int, n6: int, n7: int, n8: int, n9: int, n10: int, n11: int, n12: int, n13: int, n14: int, n15: int, n16: int, n17: int, n18: int, n19: int, n20: int, n21: int, n22: int, n23: int, n24: int, n25: int, n26: int, n27: int, n28: int, n29: int, n30: int, n31: int, n32: int, n33: int, n34: int, n35: int, n36: int, n37: int, n38: int, n39: int, n40: int, n41: int, n42: int, n43: int, n44: int, n45: int, n46: int, n47: int, n48: int, n49: int, n50: int, n51: int, n52: int, n53: int, n54: int, n55: int, n56: int, n57: int, n58: int, n59: int, n60: int, n61: int, n62: int, n63: int) =
  ## 64 INDEPENDENT free symbolic parameters, each standing for one
  ## nibble of a hypothetical scalar -- no byte array, no bit-shift/mask
  ## extraction anywhere in this proc's own body (the extraction the
  ## RESOURCE WALL note above blames for the first attempt's OOM).
  ## `oneStepChain`/`finalStepChain` are called exactly as
  ## `recodeScalarRadix16`'s own loop calls its inline carry-propagation
  ## (carry threaded from each call's returned `carryOut` into the next
  ## call's `carryIn`, starting at 0), chaining all 63 non-final steps
  ## into the 64th (`finalStepChain`). Every real scalar's 64 nibbles are
  ## a SPECIAL CASE of "64 independent values, each within its own legal
  ## range" (real nibbles additionally come in same-byte pairs, a
  ## constraint this proof does not impose) -- so proving the range
  ## invariant here, over the fully free case, is a strict generalization:
  ## it implies the invariant for every real bit-255-clear scalar too.
  ## Neither this proc's parameters nor its body assume anything about the
  ## nibbles directly -- `oneStepChain`/`finalStepChain` each already
  ## `symexAssume` their own nibble/carry domain internally, and those
  ## assumes apply to whatever expression is bound to the parameter at
  ## each call site -- here, each `n_i` in turn. The two functions' own
  ## `symexAssert` postconditions are what `tAssertionViolation()` below
  ## checks, at all 64 call sites in this single symbolic run -- a single
  ## `sxUnsat` verdict therefore covers the FULL 63-step composition, not
  ## just one isolated step. No local array of any kind is used to thread
  ## state between steps (only scalar `int` locals), by design.
  var carry = 0
  var d: int
  carry = oneStepChain(n0, carry, d)
  carry = oneStepChain(n1, carry, d)
  carry = oneStepChain(n2, carry, d)
  carry = oneStepChain(n3, carry, d)
  carry = oneStepChain(n4, carry, d)
  carry = oneStepChain(n5, carry, d)
  carry = oneStepChain(n6, carry, d)
  carry = oneStepChain(n7, carry, d)
  carry = oneStepChain(n8, carry, d)
  carry = oneStepChain(n9, carry, d)
  carry = oneStepChain(n10, carry, d)
  carry = oneStepChain(n11, carry, d)
  carry = oneStepChain(n12, carry, d)
  carry = oneStepChain(n13, carry, d)
  carry = oneStepChain(n14, carry, d)
  carry = oneStepChain(n15, carry, d)
  carry = oneStepChain(n16, carry, d)
  carry = oneStepChain(n17, carry, d)
  carry = oneStepChain(n18, carry, d)
  carry = oneStepChain(n19, carry, d)
  carry = oneStepChain(n20, carry, d)
  carry = oneStepChain(n21, carry, d)
  carry = oneStepChain(n22, carry, d)
  carry = oneStepChain(n23, carry, d)
  carry = oneStepChain(n24, carry, d)
  carry = oneStepChain(n25, carry, d)
  carry = oneStepChain(n26, carry, d)
  carry = oneStepChain(n27, carry, d)
  carry = oneStepChain(n28, carry, d)
  carry = oneStepChain(n29, carry, d)
  carry = oneStepChain(n30, carry, d)
  carry = oneStepChain(n31, carry, d)
  carry = oneStepChain(n32, carry, d)
  carry = oneStepChain(n33, carry, d)
  carry = oneStepChain(n34, carry, d)
  carry = oneStepChain(n35, carry, d)
  carry = oneStepChain(n36, carry, d)
  carry = oneStepChain(n37, carry, d)
  carry = oneStepChain(n38, carry, d)
  carry = oneStepChain(n39, carry, d)
  carry = oneStepChain(n40, carry, d)
  carry = oneStepChain(n41, carry, d)
  carry = oneStepChain(n42, carry, d)
  carry = oneStepChain(n43, carry, d)
  carry = oneStepChain(n44, carry, d)
  carry = oneStepChain(n45, carry, d)
  carry = oneStepChain(n46, carry, d)
  carry = oneStepChain(n47, carry, d)
  carry = oneStepChain(n48, carry, d)
  carry = oneStepChain(n49, carry, d)
  carry = oneStepChain(n50, carry, d)
  carry = oneStepChain(n51, carry, d)
  carry = oneStepChain(n52, carry, d)
  carry = oneStepChain(n53, carry, d)
  carry = oneStepChain(n54, carry, d)
  carry = oneStepChain(n55, carry, d)
  carry = oneStepChain(n56, carry, d)
  carry = oneStepChain(n57, carry, d)
  carry = oneStepChain(n58, carry, d)
  carry = oneStepChain(n59, carry, d)
  carry = oneStepChain(n60, carry, d)
  carry = oneStepChain(n61, carry, d)
  carry = oneStepChain(n62, carry, d)
  discard finalStepChain(n63, carry)

# -----------------------------------------------------------------------
# The machine-checked artifact: two small, fast per-step symexFind calls,
# plus the whole-chain attempt above.
# -----------------------------------------------------------------------
let stepResult = symexFind(oneStep, tAssertionViolation())
let finalResult = symexFind(finalStep, tAssertionViolation())
let chainResult = symexFind(wholeChainRecode, tAssertionViolation())

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
report("wholeChainRecode (64 free nibbles chained through oneStepChain/" &
       "finalStepChain -- the full 63-step composition in one query)", chainResult)

echo ""
echo "Both per-iteration lemmas hold for ALL nibble/carry combinations " &
     "(exhaustively decided by Z3, not sampled)."
echo "wholeChainRecode PROVED sxUnsat: the full 63-step composition is " &
     "now machine-checked in one Z3 query, over 64 independent free " &
     "symbolic nibbles chained through oneStepChain/finalStepChain " &
     "(tooling-compatible re-encodings of oneStep/finalStep, exhaustively " &
     "cross-checked against them above). The manual-induction argument " &
     "this file's module doc comment used to require is RETIRED -- see " &
     "the \"Z3 WHOLE-CHAIN ATTEMPT\" section above for the full writeup."

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
