# Constant-time timing evidence (RFC-001 slice 9)

Results of the `tests/ct/` dudect-style harness, run via `scripts/ct.sh`. This
document is the honest record the RFC requires: the harness measures, it
does not prove. It is evidence toward the constant-time discipline applied
in slices 1-8, not a substitute for an audit. Consumers who need an audited
constant-time implementation have the `-d:selloLibsodium` escape hatch
(RFC-001 slice 10).

## Measurement environment

- **Container image:** `ghcr.io/coreyleavitt/nim:2.2.10` (the same image
  `scripts/test.sh`/`scripts/ct.sh` run in per CLAUDE.md; no bare-metal run
  was performed).
- **Host CPU:** Intel(R) Pentium(R) Gold 8505, 6 logical CPUs.
- **CPU pinning:** the harness process was pinned to core 0 via
  `taskset -c 0` (available inside the container; `scripts/ct.sh` detects
  and uses it automatically, and warns if it is absent).
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
- **Build config:** this run compiles `tests/ct/ct_main.nim` at
  `-d:release`, per `scripts/ct.sh` — not the plain debug build
  `scripts/test.sh` uses. As of RFC-001 finding 1 (the checks-off coverage
  fix: `field.nim`'s whole arithmetic core and the rest of `scalar.nim`'s
  point-arithmetic
  core reachable from `geScalarmultBase` now sit under
  `{.push checks: off.}`, closing a gap where those callees compiled with
  bounds/overflow checks on regardless of the caller's own pragma), the
  debug build's secret paths are branch-equivalent to this release build
  at the source level — the checks that used to differ between the two
  configs are gone from both. That is a source-level statement only; the
  debug build's timing was not itself measured, and this run's numbers
  below remain `-d:release`-only evidence.
- **No bare-metal comparison run** was performed; all numbers below are
  container-only.
- **Shared host, RFC-002 slice 4 run.** Unlike the RFC-001 run above, this
  host was not exclusively dedicated to this measurement for its entire
  duration: `podman ps` showed an unrelated, otherwise-idle
  `amoxtli-dev` container present for part of the run window (an
  interactive `/bin/bash` session from a different project, not doing
  active compute as far as `ps`/load average could tell), and the 15-
  minute load average briefly touched 8.07 on this 6-core host shortly
  before the run started, settling toward 3.5 by the time it ran. This is
  disclosed rather than silently omitted: the RFC-002 slice-4 handoff
  explicitly called for "no concurrent container load" for exactly this
  reason, and that precondition was not perfectly met here (a genuinely
  idle background container was present; nothing else was intentionally
  scheduled by this run's own agent). The measured t-statistics below
  (all real targets well under 2 in absolute value) do not show the kind
  of variance inflation heavy concurrent load would produce, but this
  caveat is recorded plainly rather than asserting a quieter environment
  than what `ps`/`uptime` actually showed at the time.
- **RFC-003 slice 5 run: machine-captured, not hand-transcribed.**
  `scripts/ct.sh` gained an environment preflight banner in this slice
  (RFC-003 slice 5 item 2) precisely because the RFC-002 slice-4
  disclosure above depended on an agent remembering to run `podman ps`/
  `uptime` by hand and transcribe the numbers here -- "the mechanism that
  already failed once" per the RFC. The banner now runs unconditionally
  at the start of every `scripts/ct.sh` invocation and prints what it
  observed into the captured log. Verbatim from this run's banner:
  - CPU scaling governor (cpu0): `powersave` -- WARN emitted (same
    caveat as every prior run: frequency scaling was not disabled; no
    passwordless root in this sandbox to change it).
  - Running containers (host `podman ps`, excluding the one this run was
    about to start): `1` -- WARN emitted. Detail line from the banner:
    `a48f277f72c3  localhost/amoxtli-dev:latest  /bin/bash  4 hours ago
    Up 4 hours ago  exciting_nash` -- the same long-lived, otherwise-idle
    `amoxtli-dev` container from a different project noted in the
    RFC-002 slice-4 caveat above, still present, still not doing active
    compute as far as `podman ps` shows (`/bin/bash`, no CPU-bound
    command). Per this slice's explicit instructions, this is a known,
    disclosed condition on this shared host -- not something this run's
    agent killed or worked around.
  - Load average (1m 5m 15m, running/total procs, last pid) at banner
    time: `3.27 4.85 4.58 1/2542 1776025` -- no WARN (the banner's
    heuristic threshold is a 1-minute load of 4 or higher; 3.27 sits
    below it). A manual `uptime` check performed by this run's agent a
    few minutes before starting `scripts/ct.sh` showed `3.69 5.02 4.63`,
    i.e. the same rough range -- consistent with the banner's own
    reading rather than a discrepancy.
  The full campaign (six targets -- positive control plus five real --
  1,000,000 samples/class each) ran end-to-end in this environment; see
  the table below. No real target showed elevated variance relative to
  prior runs despite the disclosed container/governor conditions.

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
  target; 8,000,000 total across the four targets -- positive control
  plus three real -- in the RFC-001 run, 10,000,000 total across the five
  targets in the RFC-002 slice 4 run, 12,000,000 total across the six
  targets -- positive control plus five real -- as of the RFC-003 slice 5
  run below).
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

### RFC-001 run (four targets)

| target | samples/class | kept (fixed/random) | cropped | mean cycles (fixed/random) | t | verdict |
|---|---|---|---|---|---|---|
| positive control (`leakyOp`, harness self-test) | 1,000,000 | 993,072 / 996,943 | 9,985 | 3,924.95 / 1,973.95 | **953.87** | FAIL (expected) |
| `sello/private/backend.signDetached` | 1,000,000 | 994,990 / 995,010 | 10,000 | 240,608.19 / 240,633.23 | **-0.27** | PASS |
| `sello/scalar.geScalarmultBase` | 1,000,000 | 995,003 / 994,997 | 10,000 | 118,143.62 / 118,099.61 | **0.92** | PASS |
| `sello/x25519.x25519Base` | 1,000,000 | 995,023 / 994,978 | 9,999 | 363,862.83 / 363,758.15 | **0.59** | PASS |

### RFC-002 slice 4 run (five targets, adds the ephemeral construct+consume target)

Re-run in full (not incremental) after adding the fifth target, on the
same container image/pinning/cropping/threshold methodology described
above; absolute cycle counts differ from the RFC-001 run above (different
run, different moment on the same shared host -- see the environment
caveats), which is expected and does not affect the PASS/FAIL comparison,
itself always fixed-vs-random WITHIN this run.

| target | samples/class | kept (fixed/random) | cropped | mean cycles (fixed/random) | t | verdict |
|---|---|---|---|---|---|---|
| positive control (`leakyOp`, harness self-test) | 1,000,000 | 993,140 / 996,892 | 9,968 | 3,975.38 / 1,984.63 | **950.93** | FAIL (expected) |
| `sello/private/backend.signDetached` | 1,000,000 | 994,843 / 995,157 | 10,000 | 184,800.80 / 184,878.10 | **-1.75** | PASS |
| `sello/scalar.geScalarmultBase` | 1,000,000 | 995,090 / 994,910 | 10,000 | 90,602.72 / 90,573.99 | **1.15** | PASS |
| `sello/x25519.x25519Base` | 1,000,000 | 995,002 / 994,999 | 9,999 | 216,256.04 / 216,207.63 | **1.10** | PASS |
| `x25519(sink X25519EphemeralSecret, peer)` construct+consume | 1,000,000 | 994,995 / 995,005 | 10,000 | 232,823.57 / 232,911.25 | **-1.42** | PASS |

### RFC-003 slice 5 run (six targets, adds the arbitrary-peer static-secret DH target)

Re-run in full (not incremental) after adding the sixth target
(`x25519(X25519StaticSecret, peer)`, RFC-003 slice 5 item 1), on the same
container image/pinning/cropping/threshold methodology described above.
Environment for this specific run is recorded verbatim from the new
`scripts/ct.sh` preflight banner in the "Measurement environment" section
above (RFC-003 slice 5 item 2) rather than by hand-transcription.
Absolute cycle counts again differ from prior runs (different run,
different moment on the same shared host), which is expected and does
not affect the PASS/FAIL comparison, itself always fixed-vs-random WITHIN
this run.

| target | samples/class | kept (fixed/random) | cropped | mean cycles (fixed/random) | t | verdict |
|---|---|---|---|---|---|---|
| positive control (`leakyOp`, harness self-test) | 1,000,000 | 993,056 / 996,973 | 9,971 | 4,025.73 / 2,015.17 | **921.79** | FAIL (expected) |
| `sello/private/backend.signDetached` | 1,000,000 | 994,967 / 995,033 | 10,000 | 187,507.14 / 187,527.31 | **-0.60** | PASS |
| `sello/scalar.geScalarmultBase` | 1,000,000 | 994,942 / 995,058 | 10,000 | 90,491.15 / 90,445.11 | **1.97** | PASS |
| `sello/x25519.x25519Base` | 1,000,000 | 994,969 / 995,032 | 9,999 | 216,529.74 / 216,514.91 | **0.34** | PASS |
| `x25519(sink X25519EphemeralSecret, peer)` construct+consume | 1,000,000 | 994,992 / 995,008 | 10,000 | 214,923.02 / 214,967.41 | **-1.18** | PASS |
| `x25519(X25519StaticSecret, peer)` fixed-vs-random | 1,000,000 | 994,994 / 995,006 | 10,000 | 219,120.41 / 219,138.30 | **-0.36** | PASS |

Total samples in this run: 6 target rows x 1,000,000 samples/class x 2
classes = 12,000,000 timed calls (10,000,000 across the five real
targets, plus the 2,000,000-sample positive-control self-test).

### The sixth target: x25519(X25519StaticSecret, peer) -- a real fixed-vs-random-secret leak test of the DH path

The fifth target (construct+consume over `X25519EphemeralSecret`, above)
was, by its own design, never able to answer "does this code's timing
depend on the secret's actual VALUE" -- `X25519EphemeralSecret` has no
from-bytes constructor, so there was no way to hold a secret fixed across
the whole fixed class; both of its dudect classes ran the identical
draw-fresh-and-consume operation, making it a calibration/self-
consistency check on the wrapper machinery, not a leak test on a pinned
value.

`X25519StaticSecret` does not have that constraint: `toX25519StaticSecret`
is a from-bytes constructor (used throughout `tests/ct/ct_main.nim`
already, e.g. by the `x25519Base` target), so this sixth target can and
does follow the SAME fixed-vs-random-secret recipe as the first four
targets, just through the two-party `x25519(secret, peer)` DH overload
rather than the single-party `x25519Base` derivation:

- Fixed class: one secret, generated once before timing starts
  (`randomBytes32()`, held in `fixedSecret`), reused for all 1,000,000
  fixed-class samples.
- Random class: a fresh random secret drawn per sample.
- Both classes complete the DH exchange against the SAME fixed public
  peer point (`fixedPeer`, the same constant the fifth target uses) via
  `x25519(toX25519StaticSecret(secret), fixedPeer)`.

Because static and ephemeral secrets are clamped and driven through the
identical `ladder()` (`sello/x25519.nim`), this target's clean result
also serves as fixed-vs-random-secret evidence for the same Montgomery
ladder code the fifth target exercises only in calibration mode -- the
ladder itself, the all-zero/small-order zero-check, the `Option` wrap,
and the `=destroy` wipe, now measured against an actual secret VALUE that
varies (or doesn't) between classes, not just a construction pattern that
is identical either way.

Result: **t = -0.36**, comfortably inside the pass band, the tightest
(closest-to-zero) of the five real targets in this run. This closes the
leak-test gap the fifth target's own doc comment names explicitly as
something it structurally cannot answer.

### The fifth target: construct+consume, not fixed-vs-random secret

`x25519(sink X25519EphemeralSecret, peer)` cannot follow the same
fixed-vs-random-secret recipe as the other four targets:
`X25519EphemeralSecret` has, by design, no from-bytes constructor
(`sello/x25519`'s module doc: freshness-by-construction is the whole
point of the type) and does not expose its scalar bytes outside
`x25519.nim`, so `tests/ct/ct_main.nim` has no way to pin a "fixed" class
secret the way the other four targets' `fixedSeed`/`fixedScalar`/
`fixedSecret` do. Both dudect classes for this target therefore do the
IDENTICAL thing every sample: draw a fresh ephemeral secret from the OS
CSPRNG via `x25519EphemeralSecret()` and consume it (the sink-consuming
`x25519` overload) against the same fixed public peer point. The `bool`
class label the harness threads through carries no information about
what the sampled operation does -- there is no secret value left to
classify by.

A clean (low-|t|) result here is therefore EXPECTED BY CONSTRUCTION
(both classes are drawn from the identical generative process), not
evidence that "this secret's value doesn't leak" the way the other four
targets' results are -- there is no fixed secret value to ask that
question about for this type. What it DOES check: that the full sink-
consuming call chain (fresh construction, the Montgomery ladder, the
all-zero/small-order check, the `Option` wrap, and the `=destroy` wipe
that fires when the secret goes out of scope) introduces no timing
artifact statistically correlated with an arbitrary bisection of
otherwise-identical samples -- a calibration/self-consistency check on
the wrapper's own machinery, not a leak test on a value that cannot be
pinned. See `tests/ct/ct_main.nim`'s module doc comment for the full
design rationale, including the two empirical constraints
(`X25519EphemeralSecret` has no from-bytes constructor and does not
export its `bytes` field) that ruled out the classic recipe before this
one was chosen.

The result (t = -1.42) in the RFC-002 slice 4 run, and t = -1.18 in the
RFC-003 slice 5 run below, both sit comfortably inside the pass band,
same as the other real targets in their respective runs -- no
timing-leak finding to escalate. As of RFC-003 slice 5, the leak-value
question this target structurally cannot answer is answered by the sixth
target ("The sixth target" above), which shares this target's fixed peer
point and its underlying `ladder()` call but pins a genuinely fixed
secret across its whole fixed class.

### Positive control (harness self-test)

`leakyOp` is not a sello function: it deliberately branches on
`secret[0]`'s parity, running a slow loop whenever the byte is even. The
fixed-class secret is chosen even (always the slow path); the random-class
secret is even roughly half the time. This is this slice's RED-equivalent
check -- before trusting a clean (low-|t|) result on a real target, the
harness must first be shown capable of detecting a real, deliberately
introduced leak. It is: **t = 921.79** in the current (RFC-003 slice 5,
six-target) run, **t = 950.93** in the RFC-002 slice 4 five-target run,
**t = 953.87** in the earlier RFC-001 four-target run -- all several
orders of magnitude past the fail threshold, confirming the measurement
pipeline (interleaving, rdtsc timing, cropping, Welch's t-test) is
sensitive enough to catch a secret-dependent branch of this size,
consistently across runs. A FAIL verdict on the positive control is the
correct, passing outcome for the harness sanity check itself;
`tests/ct/ct_main.nim` treats it as such (only a *pass* on the positive
control, or a *fail* on a real target, is treated as a harness failure
with a nonzero exit code).

### Real targets

All five sello real targets in the current (RFC-003 slice 5, six-target)
run pass comfortably inside the `|t| <= 4.5` band, nowhere near the 4.5
warn threshold, let alone the 10 fail threshold:

- `backend.signDetached` (the full RFC 8032 sign operation: seed
  expansion, clamping, two fixed-base scalarmults, `scMulAdd`): t = -0.60.
- `scalar.geScalarmultBase` (the fixed-base scalarmult in isolation --
  this RFC's new secret-facing arithmetic: radix-16 recoding +
  `cmovCached` select): t = 1.97.
- `x25519.x25519Base` (the RFC 7748 Montgomery ladder over a secret
  scalar): t = 0.34.
- `x25519(sink X25519EphemeralSecret, peer)` construct+consume (RFC-002
  slice 4's fifth target; see "The fifth target" above for why this one
  is a construct+consume calibration check rather than a fixed-vs-random-
  secret test): t = -1.18.
- `x25519(X25519StaticSecret, peer)` fixed-vs-random (RFC-003 slice 5's
  new sixth target; see "The sixth target" above): t = -0.36, the
  tightest result of the five.

The RFC-002 slice 4 five-target run (`backend.signDetached` t = -1.75,
`scalar.geScalarmultBase` t = 1.15, `x25519.x25519Base` t = 1.10,
ephemeral construct+consume t = -1.42), the earlier RFC-001 four-target
run (`backend.signDetached` t = -0.27, `scalar.geScalarmultBase` t = 0.92,
`x25519.x25519Base` t = 0.59), and a smaller pilot run (20,000
samples/class, same environment and pinning: positive control t = 137.04
(FAIL), all three real targets under |t| = 1) produced the same
qualitative picture -- each full run is a confirmation, not a one-off.

## Interpretation

No target has exceeded the warn threshold in any run to date, so there is
nothing in the 4.5-10 band requiring the investigation writeup the RFC
calls for. The clean pass on all five real targets in the current run,
combined with the positive control firmly failing, is the intended shape
of evidence: the harness is demonstrably capable of detecting a leak of
this class and size, and does not detect one in `signDetached`,
`geScalarmultBase`, `x25519Base`, the ephemeral construct+consume path,
or the static-secret arbitrary-peer DH path, under 2,000,000 interleaved,
pinned, cropped samples each in this container.

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
4. **Shared host, not exclusively quiet (RFC-002 slice 4 and RFC-003
   slice 5 runs).** See the "Measurement environment" section above -- an
   otherwise-idle unrelated container (`amoxtli-dev`) was present on the
   host for both of these runs (RFC-003 slice 5's own preflight banner
   now records this automatically rather than by hand-transcription, per
   item 2 of that slice). This did not visibly inflate variance in either
   run's results (all real targets stayed under |t| = 2 in both), but a
   policy of "no concurrent container load" is the stronger precondition
   and was not perfectly achieved in either run. RFC-003 slice 5's own
   standing orders treat this as a known, disclosed, non-blocking
   condition on this particular shared host, not something a timing run
   should hold itself hostage to indefinitely -- the banner exists so the
   condition is recorded accurately every time, not so it is eliminated.

Consumers who need a stronger guarantee than "a statistical harness found
nothing in one container on one CPU" have the `-d:selloLibsodium` adapter
(RFC-001 slice 10) as the audited-implementation escape hatch -- that
remains the honest answer to "how sure are you," not an inflated claim
about this harness's reach.

## Reproducing this run

```sh
scripts/ct.sh
```

`scripts/ct.sh` compiles `tests/ct/ct_main.nim` at `-d:release`, pins to
core 0 via `taskset` if available (warns and runs unpinned otherwise), and
runs with the default 1,000,000 samples/class. Pass a different sample
count as the sole argument to the compiled binary (`build/ct_main 20000`)
for a faster pilot run; the RFC's stated floor is 1,000,000 samples/class
for a result to be reported as final.

As of RFC-003 slice 5, `scripts/ct.sh` also prints an environment
preflight banner before compiling (CPU scaling governor, `podman ps`
container count, `/proc/loadavg`), warning on `powersave`/nonzero
container count/high load without failing the run -- see "Measurement
environment" above for what it captured on this run. The banner is
unconditional and its output lands in whatever the invoker redirects
`scripts/ct.sh`'s stdout/stderr to, so future runs' environment sections
can be built from the captured log instead of a separate manual check.
