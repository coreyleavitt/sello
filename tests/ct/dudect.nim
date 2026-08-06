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

import std/[random, math, algorithm]

type
  Verdict* = enum
    vPass = "PASS"
    vWarn = "WARN"
    vFail = "FAIL"

  DudectReport* = object
    name*: string
    samplesPerClass*: int
    keptFixed*, keptRandom*: int
    croppedTotal*: int
    meanFixedCycles*, meanRandomCycles*: float64
    tStat*: float64
    verdict*: Verdict

const
  DefaultSamplesPerClass* = 1_000_000
  CropPercentile* = 99.5 ## dudect-style upper-percentile cropping cutoff,
                         ## applied once to the pooled sample (see module doc)
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

  # Phase 3 -- upper-percentile cropping from the pooled sample, then
  # Welch's t-test on the cropped populations.
  var pooled = newSeq[float64](timesFixed.len + timesRandom.len)
  for i, x in timesFixed: pooled[i] = x
  for i, x in timesRandom: pooled[timesFixed.len + i] = x
  sort(pooled)
  let cutoff = percentileOf(pooled, CropPercentile)

  var keptFixed = newSeqOfCap[float64](timesFixed.len)
  for x in timesFixed:
    if x <= cutoff: keptFixed.add(x)
  var keptRandom = newSeqOfCap[float64](timesRandom.len)
  for x in timesRandom:
    if x <= cutoff: keptRandom.add(x)

  let t = welchT(keptFixed, keptRandom)
  result = DudectReport(
    name: name,
    samplesPerClass: samplesPerClass,
    keptFixed: keptFixed.len,
    keptRandom: keptRandom.len,
    croppedTotal: total - keptFixed.len - keptRandom.len,
    meanFixedCycles: meanOf(keptFixed),
    meanRandomCycles: meanOf(keptRandom),
    tStat: t,
    verdict: classifyVerdict(t),
  )

proc report*(r: DudectReport) =
  echo "== ", r.name, " =="
  echo "  samples/class: ", r.samplesPerClass,
       "  kept: ", r.keptFixed, "/", r.keptRandom,
       "  cropped: ", r.croppedTotal
  echo "  mean cycles  fixed=", r.meanFixedCycles, "  random=", r.meanRandomCycles
  echo "  t = ", r.tStat, "  verdict = ", r.verdict
