# RFC-005: Validation infrastructure — suite gaps, CI, and the public evidence story

- **Status:** DRAFT (stage 1 — slicing done, architect rounds NOT yet run;
  both rounds required per rfc-flow). Drafted 2026-08-14 from the
  first-principles design session (grill) of the same date; the resolved
  decisions table from that session is this RFC's requirements record —
  decisions below cite it rather than re-litigating.
- **Numbering / ordering:** RFC-006 (in-house SHA-512) was drafted out of
  the same session and is independent. Implementation order is Corey's
  scheduling call, with one recorded thermal: RFC-006-first makes this
  RFC's cross-platform jobs simpler (a zero-dependency tree needs no
  `milpa`/`nim.cfg` machinery on macOS/Windows runners — `--path:src` is
  the whole build configuration; see the macOS/Windows slice). Not a hard
  dependency: those jobs can also run against a checked-in dep snapshot.
- **Handoff doc:** `docs/rfc-005-validation-infra.handoff.md` (created when
  stage 3 opens).
- **Standing orders:** identical to RFC-001..004 (PhD-CS bar; genuine forks
  escalate; wrong-spec assumptions escalate; per-slice commits after gates
  pass — noting that mid-RFC, "commit" targets this RFC's own branch once
  the branch model below exists; this RFC bootstraps the rule it will then
  live under).
- **Specs / references:** GitHub Actions + repository rulesets (behavior
  verified against live GitHub, not memory, at implementation time — the
  required-checks-without-PR mechanics are load-bearing); Valgrind memcheck
  client requests (`valgrind/memcheck.h`); gcov/lcov; QEMU user-mode
  emulation; NIST/Wycheproof corpora unchanged.

## Context

sello's validation battery is real but **invisible and manual**: seven gate
scripts run by hand on one shared podman host, results transcribed into
`docs/`. Three structural problems, in increasing order of severity:

1. **Nothing runs automatically.** Every gate is only as fresh as the last
   time someone remembered to run it; the S07 mutation-anchor breakage sat
   silent across an entire slice until the next manual mutation run.
2. **The evidence is unverifiable.** The repo is private and the docs say
   "trust our transcripts." For a library whose entire premise is trust
   earned through evidence, the evidence must be publicly reproducible and
   continuously produced.
3. **The timing instrument is compromised by its environment.** Every
   dudect verdict on file comes from a shared host; RFC-004 paid a
   multi-round artifact-investigation tax twice, and two targets carry
   carve-outs that a quiet box could either retire or genuinely confirm.

Separately, the suite itself has gaps no amount of CI fixes: CT verification
is statistical-only (dudect) when a deterministic instrument exists; nothing
measures coverage; nothing exercises 32-bit or big-endian, the two
environments where ported carry-chain arithmetic historically breaks; and
the toolchain pin (Nim 2.2.10) is load-bearing for several empirically
verified behaviors (sink analysis, `=destroy` firing, assert stripping) with
no canary watching for upstream drift.

## Design

### Part A — new suite capability (the gaps CI would otherwise automate)

**A1. Deterministic CT verification, taint-based (the headline).** A new
harness (`tests/ct_taint/`, `scripts/ct-taint.sh`) runs the secret-holding
paths under Valgrind memcheck with secrets marked UNDEFINED via client
requests (`VALGRIND_MAKE_MEM_UNDEFINED`): any conditional branch or memory
index influenced by undefined (= secret-derived) data is a deterministic
error with a stack trace — the ctgrind construction. This complements
dudect, it does not replace it: taint proves no-branch/no-index *on this
binary*; dudect measures the composite reality on real silicon.

- Tooling choice (recorded): Valgrind, not MemorySanitizer — works against
  the existing gcc-backend release build with zero code changes to the
  core; MSan needs the clang backend plus instrumenting every translation
  unit, considered and declined for now (revisitable).
- The client-request calls live in the harness only (a test-side C header
  include). The core's no-FFI rule is untouched — same register as the
  dudect harness's own `rdtsc` usage.
- **Declassification points are the design's audit artifact.** Some
  secret-derived bits become caller-visible *by documented design* (the
  x25519/ristretto all-zero verdicts, `RistrettoPoint`'s `==` result,
  `scIsCanonicalCT`'s verdict, signature bytes themselves). Each such point
  gets an explicit `VALGRIND_MAKE_MEM_DEFINED` in the harness with a
  comment citing the module doc that sanctions the disclosure. The
  resulting declassification list is a reviewable enumeration of every
  place a secret legally influences control flow — a document the codebase
  has never had, and the harness fails loudly anywhere an *unlisted* one
  exists.
- Targets: `signDetached`/`derivePublic` (seed tainted), `x25519` both
  roles + `x25519Base` (scalar tainted), `ristrettoScalarmult` both
  overloads + `ristrettoScalarmultBase` (scalar tainted), `ristrettoEncode`
  and `` `==` `` (point coordinates tainted — giving the two dudect
  carve-out targets their deterministic hearing), `ristrettoFromUniformBytes`
  (input tainted), `toRistrettoStaticSecret` (import bytes tainted), wipe
  paths. Post-RFC-006, the SHA-512 core joins (message tainted).

**A2. Disassembly gate.** Stage-4 finding 1 (`feSqrtRatioM1`'s
secret-dependent jumps surviving `-O3`) was caught by a human reading
objdump; `scripts/disasm-gate.sh` automates the class: objdump the release
build, resolve the mangled symbols of an enumerated CT-function list (a
small resolver keyed on Nim's `name__module` mangling pattern), extract each
function's conditional-branch profile, and diff against a pinned
expectations file (`tests/ct_disasm/expected.txt`). Loop back-edges on
public counters are expected branches — the pin is the per-function profile,
updated deliberately (a reviewed diff) when code changes, exactly like the
mutation catalog's anchors. A new conditional jump in straight-line CT code
fails the gate with the function name.

**A3. Coverage with a ratchet.** Unit+property suite built with
`--passC:--coverage --passL:--coverage` (gcov over Nim's C output), lcov
aggregation, line coverage of `src/sello/` compared against a committed
baseline (`tests/coverage-baseline.txt`): the gate fails if coverage
*drops*; raising the baseline is a deliberate commit. No arbitrary
threshold — the ratchet encodes "new code arrives tested" without
retroactive theater. (Mutation testing remains the depth instrument; this
is the breadth instrument it never claimed to be.)

**A4. Platform breadth as test capability.** The suite must pass on
32-bit (`--cpu:i386` cross-build, where the field core's `int64`
intermediates become register pairs) and big-endian (s390x via QEMU
user-mode, where every encode/decode byte-order assumption is live). Any
failure found is a genuine bug fixed in-slice with a regression test —
budgeted as real work, not smoke.

**A5. Fuzz campaign continuity.** The fuzz corpus becomes persistent
(committed under `tests/fuzz/corpus/` after minimization — small, reviewed,
the Wycheproof-vendoring register) so nightly campaigns accumulate coverage
instead of restarting from seeds; crash artifacts upload from CI.

**A6. Toolchain canary.** A non-blocking nightly job builds and runs the
suite against Nim devel and latest-stable. Failures notify, never gate —
the pin stays 2.2.10, bumped only by deliberate commit. The empirically
verified version-sensitive behaviors (sink occurrence-count analysis, the
negative-compile fixtures, assert stripping) are exactly what this watches.

### Part B — CI structure (grill decisions 2–4, 6–7)

**Repo goes public first** (grill #2) — hosted runners become free-unlimited
and the evidence becomes verifiable. The base toolchain image
(`ghcr.io/coreyleavitt/nim:2.2.10`) and the `sello-dev` image must be
public-pullable; CI builds `sello-dev` from the committed Containerfile and
pins by digest.

**Merge gate** (one workflow, push-triggered on all branches; its checks are
the ruleset's required set — grill #6): linux/amd64 unit+property suite on
gcc AND clang backends; macOS-arm64 and windows/MinGW-gcc unit suite
(proptest-skip path — the loud-skip machinery already exists; vcc is
explicitly unsupported, the `asm volatile` barrier rules it out);
`--cpu:i386` 32-bit; ASan/UBSan build of the unit suite; libsodium
differential (`test-libsodium.sh` in `sello-dev`); mutation (full catalog);
bmc (all symex files `sxUnsat`); taint CT gate (A1); disasm gate (A2);
coverage ratchet (A3); check-readme; milpa-lock verify. Everything
deterministic; mutation/bmc sit inside the matrix's wall-clock shadow.

**Nightly** (scheduled, non-blocking except for release qualification): long
fuzz with persisted corpus (A5), s390x big-endian (A4), Nim canary (A6),
property tests at cranked example counts.

**Timing tier** (grill #1, #3): the dedicated Ryzen 5 3500U as a
self-hosted runner — quiet-box configuration is part of the slice (boost
disabled, frequency pinned at/below the 2.1 GHz base so throttling is
physically impossible, `performance` governor, SMT off, isolated core, IRQ
steering, nothing co-scheduled). Workflow triggers: schedule (weekly),
`workflow_dispatch`, and release tags ONLY — never `pull_request`, never
push. Runner hardening (public-repo rule): ephemeral (fresh containerized
environment per job, deregistered after), registered to this one workflow,
repo-wide fork-PR approval required. A CI concurrency group makes a running
battery exclusive on the box. The job runs `scripts/ct.sh` (whose preflight
banner will, for the first time on record, report a quiet host), uploads raw
results as artifacts; `docs/ct-results.md` updates remain deliberate
commits, not bot pushes. Hosted CI runs the dudect harness in compile-smoke
mode only — no verdict authority, stated in the workflow name.

**Ruleset on main** (grill #4): required status checks = the merge-gate
check names; NO pull-request requirement; force-push and deletion blocked;
bypass list = repo admin. The merge flow: slices land on the RFC branch, CI
greens the branch head, `git push origin <branch>:main` fast-forwards main
to a SHA whose checks already passed. A locally created merge commit is a
new SHA and gets rejected — merges are fast-forward by policy.

**Release workflow** (tag-triggered): verifies the tagged SHA's merge gate
is green, the latest nightly is green, and a timing-tier run exists within
the freshness window (14 days); then builds release artifacts. The nimble
registry PR (deferred publish logistics) lands once the first release
passes this gate.

### The evidence story (README)

README gains a validation section with live badges (merge gate, nightly,
timing) and a table mapping every claim in the validation bar to the CI job
that continuously enforces it. The platform-support claim becomes exactly
the CI matrix, in those words (grill #5).

## Slices (each one `/tdd`-sized; infra slices verify by running the thing)

1. **Go public + bootstrap.** Repo public; ghcr images public;
   `.github/workflows/merge-gate.yml` with the linux/amd64 gcc job
   (containerized `test.sh` equivalent) + check-readme + milpa-lock verify;
   first green run on main.
2. **Ruleset + branch model.** Ruleset via `gh api` (required checks, no
   PR rule, bypass list, force-push/delete block); verified by an actual
   rejected-then-accepted push pair; grind mechanics note added to
   CLAUDE.md (slices commit to RFC branches henceforth).
3. **Matrix expansion.** clang-backend job; ASan/UBSan job; `--cpu:i386`
   job. Fix-in-slice anything they surface.
4. **macOS + Windows.** Hosted runners, no-milpa build path (see Status
   note on RFC-006 ordering), proptest-skip verified loud; MinGW pinned on
   Windows with vcc-unsupported recorded in README.
5. **Heavy deterministic gates into CI.** `sello-dev` image build+digest
   pin; libsodium-differential job; mutation job; bmc job; all added to the
   required set.
6. **Coverage ratchet (A3).** Instrumented build, lcov, baseline file, gate
   script + CI job; baseline committed from the current suite's real
   number.
7. **Taint CT harness (A1) — part 1.** Harness + client-request plumbing +
   the declassification-point register; first two targets (`signDetached`,
   `x25519` static) proven clean or fixed.
8. **Taint CT harness — part 2.** Remaining targets incl. the two dudect
   carve-out targets and the import path; CI job into the required set;
   module docs cross-reference their declassification entries.
9. **Disasm gate (A2).** Resolver, profile extractor, pinned expectations
   for the enumerated CT-function list, CI job into the required set;
   verified red against a deliberately reintroduced feSqrtRatioM1-class
   branch (the stage-4 finding as its own regression test).
10. **Nightly workflow.** Fuzz with persisted corpus (A5, incl. the
    corpus-commit machinery), s390x big-endian (A4), Nim canary (A6),
    cranked properties; notification wiring.
11. **Timing tier.** 3500U provisioning checklist executed (quiet-box
    config, runner registration, hardening); `timing.yml` with exclusivity
    + trigger restrictions; first quiet-box full battery run; the two
    carve-out targets' verdicts re-adjudicated in `docs/ct-results.md`
    (retired or confirmed — either is a result).
12. **Release + close-out.** Release workflow with freshness gates; README
    badges + validation-map table + platform claim; nimble registry PR;
    CLAUDE.md/CHANGELOG; version bump.

## Ordering & risks

- Slices 1–2 bootstrap the model everything else assumes; 3–9 are
  independent of each other after 2; 10–12 close. The 3500U (slice 11) is
  the only physical-world dependency and can slide without blocking
  anything before 12.
- **Disasm-gate brittleness:** Nim's symbol mangling is convention, not
  contract — the resolver may need per-Nim-version attention; the gate
  fails loud (symbol not found) rather than silently passing, and the pin
  lives with the mutation catalog's update-deliberately register.
- **Valgrind + ORC:** expected clean (Valgrind runs the uninstrumented
  binary), verified empirically in slice 7 before the design hardens; if
  memcheck's definedness tracking proves too noisy through the masking
  arithmetic, the fallback is MSan on a clang build — the decline is
  revisitable, recorded here.
- **QEMU s390x wall-clock:** possibly slow enough to need a reduced
  property count; the unit suite + KATs are the non-negotiable core there.
- **Hosted-runner variance:** none of the merge gate is timing-sensitive by
  design; dudect authority lives on the 3500U only.
- **Carve-out risk:** the quiet box may *confirm* rather than retire a
  carve-out — that is a valid outcome producing a stronger record, not a
  failure of the slice.

## Non-goals (considered and declined)

- **CI-authoritative dudect verdicts on hosted runners** — the environment
  is the pathological version of the shared-host problem already documented.
- **MSan-based taint** — declined for now (clang-backend + full-TU
  instrumentation cost); recorded fallback if Valgrind disappoints.
- **A fixed coverage threshold** — ratchet only; thresholds invite theater.
- **Windows vcc** — the `asm volatile` barrier rules it out; MinGW is the
  supported Windows toolchain, documented.
- **A supported-Nim-version range** — one pinned version + canary;
  "supports latest stable" claims arrive only when the canary has history.
- **BSDs, Android/iOS, bare-metal targets** — nothing stops a port; CI
  claims only what it runs.
- **Auto-committing bots** (results docs, coverage baselines) — every
  committed artifact stays a deliberate human-reviewed change.

## Open questions

- ghcr base-image visibility: `ghcr.io/coreyleavitt/nim:2.2.10` must be
  public-pullable or mirrored; verified in slice 1.
- RFC-006 ordering (see Status) — scheduling, not design.
