# Constant-time timing evidence (RFC-001 slice 9)

Results of the `tests/ct/` dudect-style harness, run via `nimble ct`. This
document is the honest record the RFC requires: the harness measures, it
does not prove. It is evidence toward the constant-time discipline applied
in slices 1-8, not a substitute for an audit. Consumers who need an audited
constant-time implementation have the `-d:selloLibsodium` escape hatch
(RFC-001 slice 10).

## Measurement environment

- **Container image:** `ghcr.io/coreyleavitt/nim:2.2.10` (the same image
  `nimble test`/`nimble ct` run in per CLAUDE.md; no bare-metal run was
  performed).
- **Host CPU:** Intel(R) Pentium(R) Gold 8505, 6 logical CPUs.
- **CPU pinning:** the harness process was pinned to core 0 via
  `taskset -c 0` (available inside the container; `nimble ct` detects and
  uses it automatically, and warns if it is absent).
- **Frequency governor:** the host runs `powersave`. Switching to
  `performance` was attempted and requires root
  (`/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor`); this sandbox
  has no passwordless root, so the governor could not be changed. Results
  below carry the extra-variance caveat this implies (frequency scaling
  under `powersave` is a source of measurement noise that interleaving
  cancels on average but does not eliminate sample-by-sample).
- **Cycle source:** `rdtsc`/`rdtscp`, verified functional inside the
  container. The measured region opens with `lfence; rdtsc` (drains
  in-flight instructions before the clock starts) and closes with
  `rdtscp; lfence` (waits for prior instructions to retire before reading
  the counter, then blocks later instructions from being reordered into
  the window) -- see `tests/ct/dudect.nim`'s module doc for why this
  pairing was chosen over the textbook `cpuid`-based serialization (cpuid
  clobbers `%rbx`, which some `-fPIC` toolchains reserve for the GOT
  base).
- **No bare-metal comparison run** was performed; all numbers below are
  container-only.

## Harness design

- **Classes:** fixed secret vs. per-sample random secret, per RFC-001.
  Only the secret varies between classes for a given target; any public
  input (message, peer point) is identical across both classes, so a
  detected difference can only be attributed to the secret.
- **Interleaving:** all samples for a target are generated up front
  (inputs and a fixed/random class assignment for each trial slot), then
  the class order is randomly shuffled (`std/random.shuffle`) before the
  timed loop runs -- a single pass over both classes in randomized order,
  not two separate blocks. This is what cancels thermal/frequency-scaling
  drift and cache/branch warmup bias from the repeatedly-executed fixed
  input.
- **Samples:** 1,000,000 per class per target (2,000,000 timed calls per
  target; 8,000,000 total across the four targets in this run).
- **Cropping:** upper-percentile cropping at the 99.5th percentile,
  computed once from the *pooled* (both classes together) sample and
  applied identically to both classes, so the cropping step itself cannot
  bias the comparison toward either class. This discards rare large
  outliers (OS preemption, page faults, container scheduling jitter) that
  inflate variance without carrying a secret-dependent signal. Roughly
  0.5% of samples were cropped per target (see per-target counts below).
- **Statistic:** Welch's t-test on the cropped populations. Thresholds:
  `|t| > 10` fails; `4.5 < |t| <= 10` is a soft warning requiring writeup
  (none triggered in this run); `|t| <= 4.5` passes.
- **Anti-dead-code-elimination:** each target's output is folded into a
  `uint64` checksum inside the measured region (before the closing
  timestamp is taken) and every sample's checksum is XORed into a global
  sink that is read and printed at program exit, so the compiler cannot
  prove the measured calls are unobserved and elide them.

## Targets and results

| target | samples/class | kept (fixed/random) | cropped | mean cycles (fixed/random) | t | verdict |
|---|---|---|---|---|---|---|
| positive control (`leakyOp`, harness self-test) | 1,000,000 | 993,072 / 996,943 | 9,985 | 3,924.95 / 1,973.95 | **953.87** | FAIL (expected) |
| `sello/private/backend.signDetached` | 1,000,000 | 994,990 / 995,010 | 10,000 | 240,608.19 / 240,633.23 | **-0.27** | PASS |
| `sello/scalar.geScalarmultBase` | 1,000,000 | 995,003 / 994,997 | 10,000 | 118,143.62 / 118,099.61 | **0.92** | PASS |
| `sello/x25519.x25519Base` | 1,000,000 | 995,023 / 994,978 | 9,999 | 363,862.83 / 363,758.15 | **0.59** | PASS |

### Positive control (harness self-test)

`leakyOp` is not a sello function: it deliberately branches on
`secret[0]`'s parity, running a slow loop whenever the byte is even. The
fixed-class secret is chosen even (always the slow path); the random-class
secret is even roughly half the time. This is this slice's RED-equivalent
check -- before trusting a clean (low-|t|) result on a real target, the
harness must first be shown capable of detecting a real, deliberately
introduced leak. It is: **t = 953.87**, several orders of magnitude past
the fail threshold, confirming the measurement pipeline (interleaving,
rdtsc timing, cropping, Welch's t-test) is sensitive enough to catch a
secret-dependent branch of this size. A FAIL verdict on the positive
control is the correct, passing outcome for the harness sanity check
itself; `tests/ct/ct_main.nim` treats it as such (only a *pass* on the
positive control, or a *fail* on a real target, is treated as a harness
failure with a nonzero exit code).

### Real targets

All three sello targets pass comfortably inside the `|t| <= 4.5` band,
nowhere near the 4.5 warn threshold, let alone the 10 fail threshold:

- `backend.signDetached` (the full RFC 8032 sign operation: seed
  expansion, clamping, two fixed-base scalarmults, `scMulAdd`): t = -0.27.
- `scalar.geScalarmultBase` (the fixed-base scalarmult in isolation --
  this RFC's new secret-facing arithmetic: radix-16 recoding +
  `cmovCached` select): t = 0.92.
- `x25519.x25519Base` (the RFC 7748 Montgomery ladder over a secret
  scalar): t = 0.59.

A smaller pilot run (20,000 samples/class, same environment and pinning)
produced the same qualitative picture -- positive control t = 137.04
(FAIL), and all three real targets under |t| = 1 -- so the full run is a
confirmation, not a one-off.

## Interpretation

No target exceeded the warn threshold, so there is nothing in the
4.5-10 band requiring the investigation writeup the RFC calls for. The
clean pass on all three real targets, combined with the positive control
firmly failing, is the intended shape of evidence: the harness is
demonstrably capable of detecting a leak of this class and size, and does
not detect one in `signDetached`, `geScalarmultBase`, or `x25519Base`
under 2,000,000 interleaved, pinned, cropped samples each in this
container.

This is evidence, not proof, for three reasons stated plainly:

1. **Container, not bare metal.** Virtualization/container scheduling
   adds noise a bare-metal run would not have; the harness could not run
   outside the container in this environment.
2. **`powersave`, not `performance`.** Frequency scaling was not
   disabled; a low t-statistic under `powersave` is a stronger result
   (the noise floor is higher, and the signal still isn't there) than the
   same result would be, but it also means a *very* subtle leak with an
   effect size below the induced noise floor could in principle be masked
   until frequency scaling is eliminated.
3. **A single core, a single CPU model, a single compiler.** Prompt.md's
   long-term goal of evidence "across x86 and ARM and >1 cc version" is
   not attempted here; this run is x86_64/GCC-in-container only.

Consumers who need a stronger guarantee than "a statistical harness found
nothing in one container on one CPU" have the `-d:selloLibsodium` adapter
(RFC-001 slice 10) as the audited-implementation escape hatch -- that
remains the honest answer to "how sure are you," not an inflated claim
about this harness's reach.

## Reproducing this run

```sh
podman run --rm -v "$PWD":/workspace -w /workspace ghcr.io/coreyleavitt/nim:2.2.10 nimble ct
```

`nimble ct` compiles `tests/ct/ct_main.nim` at `-d:release`, pins to core 0
via `taskset` if available (warns and runs unpinned otherwise), and runs
with the default 1,000,000 samples/class. Pass a different sample count as
the sole argument to the compiled binary (`build/ct_main 20000`) for a
faster pilot run; the RFC's stated floor is 1,000,000 samples/class for a
result to be reported as final.
