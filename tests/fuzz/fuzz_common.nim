## Shared strategies, byte-encoders, and the run/report loop for sello's
## coverage-guided fuzz harness (RFC-001 review finding 12, reworked by
## RFC-002 slice 3 into an EXTERNAL SanitizerCoverage target). Imported by
## `fuzz_main.nim`; not a test itself, mirroring `tests/ct/dudect.nim`'s
## role as the engine behind `tests/ct/ct_main.nim`.
##
## SCOPE -- attacker-controlled-input surface ONLY. The three oracles
## (pointDecode, verify, x25519's peer public u-coordinate) are exactly
## the boundary where sello parses bytes nobody had to prove well-formed
## before handing them to us. Deliberately NOT fuzzed: `backend.
## signDetached` and `scalar.geScalarmultBase` -- those hold the secret
## scalar and are branchless BY DESIGN (constant-time discipline,
## CLAUDE.md's verify/sign split); their risk is a TIMING side channel on
## secret data, which a mutation fuzzer cannot observe or usefully stress,
## and which `tests/ct/`'s dudect harness already owns.
##
## RFC-002 slice 3 rework: this file used to hold `{.cover.}`-instrumented
## in-process oracle wrappers driven by `fuzzWith` (IR mutation mode). That
## harness's coverage signal was "which outcome branch did the wrapper
## take" -- a 2-edge universe per target (decode ok/reject, verify accept/
## reject, x25519 some/none), saturated within the first few iterations,
## i.e. black-box random thereafter with no real guidance. It has been
## replaced by an EXTERNAL SanitizerCoverage target
## (`fuzz_external_target.nim`, compiled separately with
## `-fsanitize-coverage=trace-pc -fno-pie` and linked against proptest's
## vendored `proptest_cov.c` runtime -- see that file's module doc for the
## oracle logic and `scripts/fuzz.sh` for the two-stage build). This file
## now holds only the DRIVER side: strategies over the plain value types,
## byte-encoders that prepend the target binary's mode-selector byte, and
## the run/report loop over `proptest`'s `externalTarget`/`fuzz`. It has
## NO import of any `sello/*` module -- the driver process never touches
## sello source; only the separately-compiled, separately-instrumented
## `fuzz_external_target` binary does, one fresh subprocess per input
## (`[INV-fresh-exec]`, docs/fuzz/FUZZ_PLAN.md D2).
import std/[os, times]
import proptest

# ---------------------------------------------------------------------------
# Strategies (unchanged in shape from the pre-slice-3 harness)
# ---------------------------------------------------------------------------

proc randByte*(): Strategy[byte] =
  integers(0, 255).map(proc(x: int): byte = byte(x))

proc bytes32*(): Strategy[array[32, byte]] =
  arrays[32, byte](randByte())

proc bytes64*(): Strategy[array[64, byte]] =
  arrays[64, byte](randByte())

type
  VerifyInput* = object
    sig*: array[64, byte]
    msg*: seq[byte]
    pk*: array[32, byte]

proc verifyInputs*(): Strategy[VerifyInput] =
  ## Composite strategy over sig || msg || pk -- everything `verify` reads.
  ## `newStrategy` is proptest's documented escape hatch for a strategy over
  ## a type its combinators don't build directly (no built-in tuple/record
  ## zip combinator; see strategy.nim's `newStrategy` doc comment).
  let sigS = bytes64()
  let msgS = bytes(0, 512)
  let pkS = bytes32()
  newStrategy[VerifyInput](proc(src: var DataSource): VerifyInput =
    VerifyInput(sig: sigS.run(src), msg: msgS.run(src), pk: pkS.run(src)))

# ---------------------------------------------------------------------------
# Byte-encoders -- mode byte + payload, matching
# `fuzz_external_target.nim`'s documented wire format exactly.
# ---------------------------------------------------------------------------

const
  ModePointDecode = 0'u8
  ModeVerify = 1'u8
  ModeX25519 = 2'u8

proc encodePointDecode*(b: array[32, byte]): seq[byte] =
  result = newSeq[byte](33)
  result[0] = ModePointDecode
  for i in 0 ..< 32: result[i + 1] = b[i]

proc encodeVerify*(inp: VerifyInput): seq[byte] =
  result = newSeq[byte](1 + 64 + 32 + inp.msg.len)
  result[0] = ModeVerify
  for i in 0 ..< 64: result[i + 1] = inp.sig[i]
  for i in 0 ..< 32: result[i + 65] = inp.pk[i]
  for i in 0 ..< inp.msg.len: result[i + 97] = inp.msg[i]

proc encodeX25519*(b: array[32, byte]): seq[byte] =
  result = newSeq[byte](33)
  result[0] = ModeX25519
  for i in 0 ..< 32: result[i + 1] = b[i]

# ---------------------------------------------------------------------------
# Run + report
# ---------------------------------------------------------------------------

const
  MinEdgesGate* = 50
    ## RFC-002 slice 3 item 1's smoke gate: "an edge count an order of
    ## magnitude above the old 1-2". Calibrated against real 20s/target
    ## campaign runs of this exact harness during development: observed
    ## 291-350 edges per target (pointDecode/verify/x25519), ~150x the
    ## retired in-process harness's 2-edge ceiling. 50 is set well below
    ## that observed floor (comfortable headroom for run-to-run variance
    ## in a short smoke-sized campaign, e.g. `scripts/fuzz.sh 15`) while
    ## still being unambiguous evidence real SanitizerCoverage guidance
    ## is happening, not a saturated/black-box run.

proc runExternalTarget*[T](name: string; strat: Strategy[T];
                            encode: proc(x: T): seq[byte];
                            targetBin: string; seconds: int; seedVal: uint64) =
  echo "=== fuzzing ", name, " (", seconds, "s budget, external SanitizerCoverage target) ==="
  doAssert fileExists(targetBin),
    "external fuzz target binary not found: " & targetBin &
    " -- scripts/fuzz.sh must build it before running this driver"

  var frontier = newCoverageFrontier()
  let target = externalTarget[T](
    argv = @[targetBin],
    delivery = stdinDelivery(),
    oracle = signalOracle[T](),
    limits = ResourceLimits(perRunTimeout: initDuration(seconds = 2)),
    encode = encode)

  var settings = FuzzSettings(
    timeBudget: initDuration(seconds = seconds),
    seed: seedVal,
    mutationMode: fmIR)
  let report = fuzz(strat, target, frontier, settings)

  let corpusSize = case report.corpus.kind
                   of fckIR: report.corpus.irEntries.len
                   of fckBytes: report.corpus.byteEntries.len
  echo "  iterations:        ", report.iterations
  echo "  coverage edges hit: ", report.coverageHits
  echo "  corpus size:        ", corpusSize
  echo "  crashes found:      ", report.irCrashes.len
  echo "  time budget hit:    ", report.timedOut

  if report.irCrashes.len > 0:
    echo "  !!! CRASH FOUND in ", name, " !!!"
    for i, c in report.irCrashes:
      echo "    [", i, "] ", c.message
    quit(1)

  if report.coverageHits < MinEdgesGate:
    echo "  !!! COVERAGE GATE FAILED for ", name, ": ", report.coverageHits,
         " edges < required minimum ", MinEdgesGate, " !!!"
    quit(1)
