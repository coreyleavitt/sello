## tests/ct/dudect.nim — dudect-style constant-time statistical timing
## harness engine (RFC-001 slice 9).
##
## Methodology (RFC-001 "Timing harness" section, followed exactly):
## two input classes -- fixed secret vs. per-sample random secret --
## executed in a single randomly interleaved order. Interleaving is
## non-negotiable: it is what cancels drift (thermal, frequency scaling,
## cache/branch warmup from the repeated fixed input) that would
## otherwise fake or mask a secret-dependent signal if the two classes
## ran as separate back-to-back blocks.
##
## Welch's t-test on the two cycle-count populations, after upper-
## percentile cropping: a single threshold is computed once from the
## *pooled* sample (both classes together) and applied identically to
## both classes, discarding rare large outliers (OS preemption, page
## faults, interrupts, container scheduling noise) that inflate variance
## without carrying a secret-dependent signal. Using one pooled cutoff
## for both classes means cropping cannot itself introduce bias toward
## either class.
##
## Both dudect thresholds are reported, never silently passed: |t| > 10
## fails; 4.5 < |t| <= 10 is a soft warning that must be investigated and
## written up in docs/ct-results.md.
##
## Cycle source: rdtsc/rdtscp (verified working inside the build
## container -- see docs/ct-results.md), fenced per Intel's benchmarking
## guidance: `lfence; rdtsc` opens the measured region (drains
## in-flight instructions before starting the clock) and
## `rdtscp; lfence` closes it (rdtscp itself waits for prior instructions
## to retire before reading the counter; the trailing lfence stops later
## instructions from being reordered into the measured window).
## Deliberately not cpuid-based serialization (the textbook
## `cpuid;rdtsc` / `rdtscp;cpuid` pairing): cpuid clobbers %rbx, which is
## reserved for the GOT base under -fPIC on some toolchains, and the
## lfence/rdtscp pairing gives adequate serialization for this harness's
## purposes without that risk.
##
## This module is test infrastructure, not shipped library code, and is
## deliberately NOT held to sello/private/ct.nim's no-seq/no-std-random
## production secret-hygiene rules -- those bind the actual crypto paths
## under audit. The synthetic per-sample "random" class inputs generated
## here exist only to feed a timing measurement, are discarded after
## classification, and carry no security meaning of their own.

import std/[random, math, algorithm, strutils]

type
  Verdict* = enum
    vPass = "PASS"
    vWarn = "WARN"
    vFail = "FAIL"

  BatteryEntry* = object
    ## One crop threshold's Welch t-test result (round-3 fix batch B,
    ## finding B4). `percentile = 100.0` is "no crop": `percentileOf` at
    ## p=100 returns the pooled sample's maximum, so the `x <= cutoff`
    ## filter in `runDudect` keeps every sample -- no special-casing
    ## needed to fold "no crop" into the same battery loop as the real
    ## percentile cuts.
    percentile*: float64
    keptFixed*, keptRandom*: int
    tStat*: float64
    verdict*: Verdict

  DudectReport* = object
    name*: string
    samplesPerClass*: int
    battery*: seq[BatteryEntry]
      ## One entry per `BatteryPercentiles` threshold, same order.
    worst*: BatteryEntry
      ## The battery entry with the largest `abs(tStat)` -- PASS/WARN/FAIL
      ## for the whole target keys off THIS entry (B4: "worst-case |t|
      ## across the battery"), not any single fixed crop. A target that
      ## looks clean at the traditional 99.5th-percentile crop but leaks
      ## at, say, no-crop or the 90th percentile is a WARN/FAIL, not a
      ## false PASS.
    meanFixedCycles*, meanRandomCycles*: float64
      ## Reported at `worst.percentile`'s crop -- the same population the
      ## verdict itself was computed from, so the printed means and the
      ## printed verdict always describe the same kept samples.
    croppedTotal*: int
      ## Also at `worst.percentile`'s crop, for the same reason.
    tStat*: float64
      ## `worst.tStat`, kept as a top-level field so `report()`'s
      ## existing single-line shape (`t = ... verdict = ...`) needs no
      ## restructuring -- it already prints the worst-case figure.
    verdict*: Verdict
      ## `worst.verdict`.

const
  DefaultSamplesPerClass* = 1_000_000
  BatteryPercentiles*: array[6, float64] =
    [100.0, 99.9, 99.5, 99.0, 95.0, 90.0]
    ## dudect percentile battery (round-3 fix batch B, finding B4):
    ## no-crop plus the 90th/95th/99th/99.5th/99.9th percentiles, each a
    ## separate upper-percentile cropping cutoff computed from the SAME
    ## pooled (both-classes-together) sample the single-crop harness used
    ## -- see the module doc comment for why pooling (not a per-class
    ## cutoff) is what keeps cropping itself from introducing bias.
    ## Ordered loosest-crop (100.0, keeps every sample including extreme
    ## outliers) to tightest (90.0), so the report's battery line reads
    ## in a consistent, meaningful direction. 99.5 (the prior single-crop
    ## harness's fixed cutoff) is kept as one entry in this list, not
    ## dropped, so the new battery strictly generalizes the old behavior
    ## rather than replacing it outright.
  WarnThreshold* = 4.5
  FailThreshold* = 10.0

# ---------------------------------------------------------------------------
# Cycle counter
# ---------------------------------------------------------------------------

proc rdtscStart(): uint64 {.inline.} =
  var lo, hi: uint32
  {.emit: """
  __asm__ __volatile__ (
    "lfence\n\t"
    "rdtsc\n\t"
    : "=a"(`lo`), "=d"(`hi`)
    :
    : "memory");
  """.}
  result = (uint64(hi) shl 32) or uint64(lo)

proc rdtscEnd(): uint64 {.inline.} =
  var lo, hi, aux: uint32
  {.emit: """
  __asm__ __volatile__ (
    "rdtscp\n\t"
    "lfence\n\t"
    : "=a"(`lo`), "=d"(`hi`), "=c"(`aux`)
    :
    : "memory");
  """.}
  result = (uint64(hi) shl 32) or uint64(lo)

# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

proc percentileOf(sortedAsc: seq[float64]; p: float64): float64 =
  ## Linear-interpolation percentile; `sortedAsc` must already be sorted.
  if sortedAsc.len == 0: return 0.0
  if sortedAsc.len == 1: return sortedAsc[0]
  let rank = (p / 100.0) * float64(sortedAsc.len - 1)
  let lo = int(floor(rank))
  let hi = int(ceil(rank))
  if lo == hi: return sortedAsc[lo]
  let frac = rank - float64(lo)
  sortedAsc[lo] * (1.0 - frac) + sortedAsc[hi] * frac

proc meanOf(xs: seq[float64]): float64 =
  for x in xs: result += x
  result /= float64(xs.len)

proc welchT(a, b: seq[float64]): float64 =
  ## Welch's t-statistic for two samples of possibly-unequal size/variance.
  let na = float64(a.len)
  let nb = float64(b.len)
  let meanA = meanOf(a)
  let meanB = meanOf(b)
  var varA, varB: float64
  for x in a: varA += (x - meanA) * (x - meanA)
  varA /= (na - 1.0)
  for x in b: varB += (x - meanB) * (x - meanB)
  varB /= (nb - 1.0)
  let se = sqrt(varA / na + varB / nb)
  if se == 0.0: return 0.0
  (meanA - meanB) / se

proc classifyVerdict(t: float64): Verdict =
  let a = abs(t)
  if a > FailThreshold: vFail
  elif a > WarnThreshold: vWarn
  else: vPass

# ---------------------------------------------------------------------------
# Harness engine
# ---------------------------------------------------------------------------

var globalSink: uint64
  ## Accumulates every `operate` result via xor. Read (printed) by the
  ## driver at program exit so the compiler cannot prove the measured
  ## calls are dead and elide them -- the standard dudect
  ## "use-the-result" anti-DCE technique.

proc sinkValue*(): uint64 = globalSink

proc runDudect*[T](name: string;
                    samplesPerClass: int;
                    fixedInput: T;
                    makeRandomInput: proc(): T {.closure.};
                    operate: proc(x: T): uint64 {.closure.}): DudectReport =
  ## Runs one dudect trial for a single target. `operate` is expected to
  ## call the function under test and fold its output into a `uint64`
  ## checksum (see ct_main.nim's `opXxx` wrappers) -- the fold happens
  ## inside the measured region, deliberately, since that is what
  ## prevents the compiler from discarding the call as dead code; the
  ## fold itself is a fixed, secret-independent byte walk, so it adds
  ## symmetric overhead to both classes rather than a new signal.
  let total = samplesPerClass * 2

  # Phase 1 -- build inputs and the interleaved class order BEFORE any
  # timing starts, so RNG cost and the shuffle never land inside the
  # measured region.
  var randomInputs = newSeq[T](samplesPerClass)
  for i in 0 ..< samplesPerClass:
    randomInputs[i] = makeRandomInput()

  var order = newSeq[bool](total) # true = fixed class, false = random class
  for i in 0 ..< samplesPerClass:
    order[i] = true
    order[samplesPerClass + i] = false
  shuffle(order)

  # Phase 2 -- the measured region: nothing here allocates or branches on
  # which class we are in beyond selecting which pre-built input to feed;
  # that selection itself is not secret-dependent (it is the harness's
  # own randomness, chosen before either function ever runs) and is
  # symmetric in cost across classes.
  var timesFixed = newSeqOfCap[float64](samplesPerClass)
  var timesRandom = newSeqOfCap[float64](samplesPerClass)
  var randIdx = 0
  for i in 0 ..< total:
    let isFixed = order[i]
    let input = if isFixed: fixedInput else: randomInputs[randIdx]
    if not isFixed: inc randIdx

    let t0 = rdtscStart()
    let r = operate(input)
    let t1 = rdtscEnd()
    globalSink = globalSink xor r

    let delta = float64(t1 - t0)
    if isFixed: timesFixed.add(delta)
    else: timesRandom.add(delta)

  # Phase 3 -- upper-percentile cropping battery (B4): the pooled sample
  # is built once (as before); each `BatteryPercentiles` threshold then
  # crops it, computes its OWN Welch t-test, and the worst-case |t|
  # across the whole battery decides the verdict. This adds no extra
  # measurement passes (the expensive part -- Phase 2's timed calls --
  # already happened once, above) and each crop pass over the collected
  # samples is cheap relative to it.
  var pooled = newSeq[float64](timesFixed.len + timesRandom.len)
  for i, x in timesFixed: pooled[i] = x
  for i, x in timesRandom: pooled[timesFixed.len + i] = x
  sort(pooled)

  var battery = newSeq[BatteryEntry](BatteryPercentiles.len)
  for i, pct in BatteryPercentiles:
    let cutoff = percentileOf(pooled, pct)
    var keptFixed = newSeqOfCap[float64](timesFixed.len)
    for x in timesFixed:
      if x <= cutoff: keptFixed.add(x)
    var keptRandom = newSeqOfCap[float64](timesRandom.len)
    for x in timesRandom:
      if x <= cutoff: keptRandom.add(x)
    let t = welchT(keptFixed, keptRandom)
    battery[i] = BatteryEntry(
      percentile: pct,
      keptFixed: keptFixed.len,
      keptRandom: keptRandom.len,
      tStat: t,
      verdict: classifyVerdict(t),
    )

  var worstIdx = 0
  for i in 1 ..< battery.len:
    if abs(battery[i].tStat) > abs(battery[worstIdx].tStat): worstIdx = i
  let worst = battery[worstIdx]

  # Recompute the worst entry's kept populations (cheap; not carried out
  # of the loop above) purely to report means/croppedTotal for the SAME
  # population the verdict came from.
  let worstCutoff = percentileOf(pooled, worst.percentile)
  var worstKeptFixed = newSeqOfCap[float64](timesFixed.len)
  for x in timesFixed:
    if x <= worstCutoff: worstKeptFixed.add(x)
  var worstKeptRandom = newSeqOfCap[float64](timesRandom.len)
  for x in timesRandom:
    if x <= worstCutoff: worstKeptRandom.add(x)

  result = DudectReport(
    name: name,
    samplesPerClass: samplesPerClass,
    battery: battery,
    worst: worst,
    meanFixedCycles: meanOf(worstKeptFixed),
    meanRandomCycles: meanOf(worstKeptRandom),
    croppedTotal: total - worst.keptFixed - worst.keptRandom,
    tStat: worst.tStat,
    verdict: worst.verdict,
  )

proc report*(r: DudectReport) =
  echo "== ", r.name, " =="
  echo "  samples/class: ", r.samplesPerClass,
       "  kept(worst crop ", r.worst.percentile, "%): ", r.worst.keptFixed, "/", r.worst.keptRandom,
       "  cropped: ", r.croppedTotal
  echo "  mean cycles  fixed=", r.meanFixedCycles, "  random=", r.meanRandomCycles
  echo "  t = ", r.tStat, "  verdict = ", r.verdict, "  (worst-case across percentile battery)"
  var batteryLine = "  battery (crop%: t):"
  for e in r.battery:
    batteryLine.add "  " & $e.percentile & "%=" & formatFloat(e.tStat, ffDecimal, 3)
  echo batteryLine
