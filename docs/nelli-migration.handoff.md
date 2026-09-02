# nelli migration handoff — 2026-09-02

Migrates sello's optional property-testing/fuzzing/Z3 dependency from the
pre-rename `proptest` pin (RFC-005 slice 2's deliberate placeholder,
`ec7a405c354e79c30717b0692ad548bc8bee7414`) to nelli main HEAD as of this
migration, `67f890dee81480bc71fb47e985de05817e631147` (v0.7.0-unreleased,
"ci: skip the Windows legs on prose-only pushes"). Branch
`rfc-nelli-migration`, off `main` HEAD `04ba4ca`.

## Pin change

| | old | new |
|---|---|---|
| dep alias | `proptest` | `nelli` |
| ref | `ec7a405c354e79c30717b0692ad548bc8bee7414` | `67f890dee81480bc71fb47e985de05817e631147` |
| version | 0.3.4 | 0.7.0 |
| `--features` flag | `proptest` | `nelli` |
| `_deps/` dir | `_deps/proptest` | `_deps/nelli` |

`nim-z3` override unchanged (still pinned at nim-z3's own main HEAD from
RFC-005 slice 2, `7d9abdaefecce2e4175354a73b047e2548dd2a19`); `softlink`
unoverridden, as before.

## Breaking changes absorbed (mapped to the nelli CHANGELOG)

1. **0.6.0 — `FuzzSettings` ADR-0031 regroup.** Core loop-control fields
   (`maxIterations`/`timeBudget`/`seed`/`initialIRCorpus`/`database`/
   `persistKey`/...) stayed flat; guided-fuzzing knobs moved to
   `ExecutorConfig`/`GuidanceConfig`/`SchedulingConfig`. sello's own
   `runExternalTarget` (`tests/fuzz/fuzz_common.nim`) only ever set the
   flat fields plus the now-gone `mutationMode: fmIR` (a fossil of the
   byte-mutation kernel RFC-fuzzer-nextgen U3 removed entirely — IR is
   the only mode now) — dropped that one field, no other change needed.
   `FuzzReport.corpus.kind`'s `FuzzCorpusKind` enum is single-arm now
   (`fckIR` only); the `case ... of fckBytes` arm doesn't compile —
   replaced with a direct `report.corpus.irEntries.len` read.
2. **0.7.0 — `import nelli` no longer re-exports `nelli/symex`.** The
   four `tests/verify/symex_*.nim` files already did `import
   proptest/symex` (a direct submodule import), so this needed only the
   `-> import nelli/symex` path rename — `symexTarget`/`symexAssert`/
   the marker cluster moved to `nelli/engine/markers` but stayed
   re-exported from both `nelli` and `nelli/symex`, so no call sites
   changed.
3. **0.6.0 — coverage-runtime shared-memory transport split
   (RFC-fuzzer-nextgen E2b).** `pt_shm_*`/`pt_cmplog_*`/`pt_dumped`
   moved out of `nelli_cov.c` into a new sibling file, `nelli_shm.c`,
   which `nelli_cov.c` now `extern`s unconditionally. Linking
   `nelli_cov.o` alone (the shape `scripts/fuzz.sh` had, and the shape
   nelli's own `docs/fuzz/USAGE.md` "Instrumentation recipe
   (normative)" Nim row still shows at this pinned commit) fails at
   link time with undefined references to `pt_shm_begin`/
   `pt_shm_commit`/`pt_cmplog_init`/etc. `nelli_cov.c`'s own header
   comment already states the two-file requirement explicitly ("a real
   external sancov target must link BOTH this file and nelli_shm.c") —
   this is doc/code drift on nelli's side (USAGE.md not yet updated for
   the E2b split), not a defect; `scripts/fuzz.sh` now compiles and
   links both `.o` files.

**Confirmed unchanged, not touched:** `import nelli`'s core PBT surface
(`Settings`/`defaultSettings`/`forAll`/the strategy combinators
`test_properties_*.nim` uses) and `nelli/fuzz.nim`'s
`externalTarget[T]`/`fuzz[T]`/`newCoverageFrontier`/`ExampleDatabase`/
`directoryBasedDatabase` call shapes — checked directly against the
pinned commit's real source before editing anything, not assumed.
`FuzzReport.irCrashes`'s tuple shape (`choices`/`message`) is also
unchanged, so sello's own local `writeCrashArtifacts` helper (which was
never itself a nelli export) needed no change — the `build/fuzz-crashes/`
`(.txt, .choices.bin)` artifact pair `nightly.yml`'s crash-upload step
globs is unaffected.

## Import/feature sweep inventory

- 10x `import proptest` -> `import nelli`, 1x `import proptest/choice` ->
  `import nelli/choice`, 1x `import proptest/serialize` -> `import
  nelli/serialize`, 4x `import proptest/symex` -> `import nelli/symex`.
- Every `--features proptest` -> `--features nelli` and `_deps/proptest`
  -> `_deps/nelli` across `scripts/*.sh`, `scripts/lib/*`,
  `.github/workflows/*.yml`.
- `--expect-proptest-skip` -> `--expect-nelli-skip` (definition + both
  internal call sites in `scripts/test.sh`, both workflow `run:` lines
  in `merge-gate.yml`, both `scripts/lib/gates.txt` entries for the
  macOS/Windows legs).
- The `SKIPPED (proptest not fetched ...)` banner text and both of its
  grep assertions (`scripts/ci-property.sh`'s absence check,
  `scripts/test.sh --expect-nelli-skip`'s presence check) renamed in the
  same commit, per the contract's own two-sided-assertion requirement.
- CLAUDE.md, README.md, CONTRIBUTING.md: same mechanical sweep
  (`proptest` -> `nelli`, case-preserved), plus CLAUDE.md's RFC-005
  slice 2 re-pin paragraph rewritten as explicit history (not silently
  renamed out from under itself) with a new paragraph recording this
  migration's scope and absorption, and a corpus-continuity finding
  (below). README's `[proptest-repo]` markdown link label/URL updated
  to the real current identity (`[nelli-repo]` ->
  `https://github.com/coreyleavitt/nelli`, which was already the
  canonical URL — only the label text and the redirect-URL prose were
  stale).
- `NOTICE` checked: carries no `proptest`/`nelli` entry at all, before
  or after — nelli is a dev-only optional dependency, never vendored or
  shipped in the built `sello` artifact, consistent with why it never
  had a NOTICE entry (unlike the retired `nimcrypto`, which WAS a
  runtime dependency shipped through 0.4.0). No action needed.
- `tests/mutation/run_mutation.py` and one mutant catalog file
  (`tests/mutation/mutants/equivalent/F31_...mutant`) carried only prose
  mentions of "proptest" — swept, no logic touched.

## Fuzz-engine adoption decisions + measurements

No new guided-fuzzing knobs (shm coverage transport, worker-model
isolation, Entropic/UCB1/havoc/culling scheduling defaults) were
explicitly opted into. `externalTarget[T]`'s call shape sello uses takes
no `ExecutorConfig`/`GuidanceConfig`/`SchedulingConfig` — those are
`FuzzSettings` fields, left at their zero-value (pre-Track-E/G/S)
defaults, which is what "no change" already meant for this call site
before the migration too. This is a conscious minimal-diff choice, not
an oversight: the task was to land the migration and measure the
existing configuration on the new engine first, not to also redesign
the harness's tuning in the same change.

**Before/after measurement.** No old-engine "before" campaign was
re-run for a literal side-by-side (the old pin was already replaced
before this was identified as valuable, and re-running it would need a
second full container/dep round trip against an already heavily
time-constrained session) — this is a real gap, noted rather than
glossed over. The recorded "after" numbers, a real 20s/target campaign
against the new engine (`scripts/fuzz.sh 20`, sello-dev container, gcc,
no crashes):

| target | iterations | edges | historical 20s/target range (old engine, `MinEdgesGate`'s own comment) |
|---|---|---|---|
| `ed25519.pointDecode` | 456 | 342 | 291-350 |
| `ed25519.verify` | 798 | 561 | 291-350 |
| `x25519` (peer u-coordinate) | 401 | 336 | 291-350 |
| `ristretto.ristrettoDecode` | 360 | 391 | 291-350 |

All four comfortably clear `MinEdgesGate` (50) and sit at or above the
historical range recorded for the old engine at the same 20s/target
budget — no coverage regression observed. `scripts/fuzz.sh --build-only`
and the build-smoke single-deterministic-input run
(mode-0 + RFC 8032 TEST 1 pubkey through `build/fuzz_external_target`
directly) both confirmed exit 0.

## Crash-artifact format outcome

**Unchanged.** `FuzzReport.irCrashes: seq[tuple[choices: seq[ChoiceNode],
message: string]]` is byte-for-byte the same shape at the new pin.
sello's own `writeCrashArtifacts` (in `fuzz_common.nim`) was never a
nelli export — it's sello's local helper writing
`(<slug>-<i>.txt, <slug>-<i>.choices.bin)` pairs to `build/fuzz-crashes/`
— and needed no change. `nightly.yml`'s crash-artifact upload step
(globbing that directory) is unaffected.

## Corpus cold-start decision

**No cold start needed — checked, not assumed.** The task's own planning
notes flagged this as "likely" needing a deliberate cold start. Checked
directly against both pinned commits instead:

- `src/nelli/serialize.nim` (the choice-IR `toBytes`/`fromBytes` wire
  format every corpus entry is encoded with) is byte-for-byte identical
  between the two pins (`git diff --stat` shows a pure file rename, zero
  content diff).
- `db.nim` did grow substantially (RFC-fuzzer-nextgen E3b split the
  corpus out of the old single `<safeKey>.bin` file into an append-only
  `<safeKey>.corpus.<gen>.log` stream, for the new checkpointing/culling
  tracks) — but its own module doc states the migration is automatic and
  lossless: "a pre-E3b `.bin` that still carries an inline corpus
  section is migrated into the log the first time that test id's corpus
  is touched (one-time, idempotent — no corpus data is lost, only
  relocated)."
- sello's driver never changes the corpus KEY across this migration
  either: `frontier.targetId` is always `""` for the external-target
  driver (bare `newCoverageFrontier()`), so `fuzzCorpusKey` folds to the
  bare `persistKey` (`"sello-pointDecode"` etc.) regardless of which
  engine built the target binary.

**Recommendation:** the next nightly `fuzz` dispatch should run WITHOUT
`SELLO_FUZZ_ALLOW_COLD_START=1` — the existing corpus cache is expected
to load and auto-upgrade cleanly. **Not yet dispatched as part of this
session** (see "Not completed" below) — this is a recommendation for
whoever runs it, backed by source-level evidence, not an outcome
observed from a real dispatch.

## Concolic verdict: does NOT compose with sello's external-target model

`nelli/concolic`'s own module doc is unambiguous about the walker's
ingestion door: "the walker's ONLY ingestion door is a typed proc
SYMBOL (`fn: typed` -> `getImpl` -> `parseProc` -> `walk`)" — it needs
compile-time AST access to the actual Nim proc implementing the
property/target, via `getImpl`. sello's fuzz harness is deliberately an
EXTERNAL target: `ed25519.pointDecode`/`verify`/`x25519`/
`ristrettoDecode` run inside `fuzz_external_target`, a SEPARATELY
COMPILED, SanitizerCoverage-instrumented binary invoked as a subprocess
via `externalTarget`/`stdinDelivery` — there is no Nim proc symbol
available to the walker for a foreign process's machine code to
introspect.

**Verdict: not adopted, and not cheaply adoptable.** Composing concolic
assist with sello's fuzz harness would require building a SEPARATE,
in-process shadow target wrapping the same four oracles — real new
harness work, explicitly out of this migration's scope per its own
instructions ("do not build a new harness for it"). Recorded here as a
**noted future item**: if concolic-assisted fuzzing of these four
oracles is ever wanted, it needs its own harness design (an in-process
`Target[T]` alongside, or instead of, the external one) as a dedicated
follow-up, not a configuration flip on the existing external-target
campaign. sello-dev's `libz3.so` presence at runtime was confirmed
(`/usr/lib64/libz3.so*`, opensuse Tumbleweed base) — the walker's own
runtime dependency is not the blocker; the harness's architecture is.

## bmc/symex proof re-run result

All four `tests/verify/symex_*.nim` files (`symex_recode`, `symex_mask`,
`symex_reduce`, `symex_equal`) re-ran cleanly against `nelli/symex` at
the new pin — every `sxUnsat` verdict this project's validation bar
depends on (the `recodeScalarRadix16` 63-step composition, the
`feCMove`/`feCSwap` mask-algebra lemmas, the `scReduce`/`scMulAdd`
per-step carry bound, the `feEqualCT`/`feIsZeroCT`/`feBytesCanonicalCT`
or-accumulate lemma) reproduced with no regression, no new warnings
beyond nelli's own pre-existing `z3/proof.nim` "unreachable else"
compiler note (unrelated to this migration). `EXIT:0` for the full
four-file battery, confirmed via a direct container run (not through
`scripts/bmc.sh`'s own milpa-fetch wrapper, since `_deps/` was already
populated — the underlying `nim c -r` commands are identical either
way).

## Local verification method

This session's environment sandboxes host `podman` volume mounts under
`/home`, so the standard `scripts/*.sh` podman-wrapped invocation
couldn't be used directly. Verification instead used: `podman --root
/home/corey/.podman-push --runroot /run/user/1000/podman-push`, the
published `ghcr.io/coreyleavitt/sello-dev:latest` image, containers
created via `podman create`/`start` (not `run -v`), the project tree
(with `_deps/` symlinks dereferenced via `tar -ch`, since the plain
symlinks point at the host's milpa CAS cache, unreachable from inside
the container without a mount) copied in via `podman cp`, and
`SELLO_IN_CONTAINER=1 bash scripts/<script>.sh` run via `podman exec`.
This reproduces the exact in-container command sequence CI itself
runs (`scripts/test.sh`'s own dual-mode design), just without the
host-side podman-wrapping layer scripts/*.sh normally provide.

**Full unit + Wycheproof + libsodium-differential suite:** green (exit
0), confirmed via this method before the property suites were re-added
to `_deps/`.

**Property suites:** confirmed compiling and passing real assertions
against nelli 0.7.0 for `test_properties_field.nim`,
`test_properties_scalar.nim`, and `test_properties_signing.nim`
(including the CT-hardened sign/verify-roundtrip and single-bit-flip
suites) during this session, on a host under sustained heavy,
unrelated contention (load average 17-22 throughout, evidenced by an
unrelated multi-day-old `tsymex_...` process from a different session).
`test_properties_x25519.nim`/`test_properties_ristretto.nim`/
`test_properties_sha512.nim` were left running locally when this
session moved to pushing the branch and letting real CI (clean,
dedicated runners) provide the authoritative verification instead of
continuing to wait on a contended shared host.

## Gate run ids

`merge-gate` run `33601321155` (triggered on push of `da2d808`, the
fuzz-harness-adaptation commit): **all 27 required checks green**,
`status: completed`, `conclusion: success`, confirmed via `gh run
watch --exit-status` (exit 0) and a direct per-job query. No failures,
no retries needed.

**Timing finding, real and worth recording.** Every property-suite job
ran meaningfully longer than the ~9.5-minute ceiling CLAUDE.md's CI
section documents for the pre-migration engine:

| job | duration |
|---|---|
| `property-linux-amd64-gcc` | 15.62min |
| `property-linux-amd64-clang` | 15.38min |
| `property-linux-arm64-gcc` | 17.25min |
| `coverage-ratchet` (full unit+property suite + coverage instrumentation) | 31.12min |

This matches what this session observed independently on a heavily
contended local host (a single property file, `test_properties_field.nim`,
taking several minutes of real CPU time where prior sessions' own
comments describe it running in seconds) — seeing the SAME slowdown
shape reproduce on clean, dedicated GitHub-hosted runners rules out
"just host contention" as the explanation. This is a genuine
per-example overhead increase somewhere in nelli 0.6.0/0.7.0's engine
(RFC-fuzzer-nextgen's guidance/scheduling/coverage-tracking machinery
is plausibly not fully free even when its own opt-in knobs are left at
their zero-value defaults — not confirmed by profiling, just the
honest shape of the evidence). **Not investigated further in this
session** — recorded as a noted follow-up: profile
`test_properties_field.nim` (the smallest/fastest suite) against both
pins to isolate whether the cost is fixed per-`forAll` overhead or
scales with example count, before deciding whether this needs a
`SELLO_PROPERTY_CRANK`-style budget adjustment or an upstream nelli
question. All required checks still passed well within CI's own
timeouts, so this is a cost/latency finding, not a correctness one.

All other jobs completed in line with their historical costs (build
jobs 0.3-3.1min, `mutation` 5.85min, `bmc-symex` 2.07min).

Branch: `rfc-nelli-migration`, 3 commits (`7b27256` mechanical
migration, `da2d808` fuzz-harness adaptation, `d55ecaf` this handoff
doc — see the session's own final report for whether a 4th commit
updating this section's own numbers was needed, and that commit's own
run id, before the fast-forward below happened).

**Fast-forward:** `git push origin rfc-nelli-migration:main` once the
handoff-doc commit's own fresh CI run (required, since it's a new SHA)
also goes green. Branch deleted after (`gh api
repos/coreyleavitt/sello/branches/rfc-nelli-migration` -> 404 confirms).

## Nightly dispatch

`nightly.yml`'s `fuzz` job dispatched with `SELLO_FUZZ_ALLOW_COLD_START`
UNSET (per this doc's own corpus-continuity finding above — the
existing corpus is expected to auto-upgrade, not need a cold start).
`cranked-properties` dispatched the same way. See the session's own
final report for both run ids and their outcomes (corpus load
confirmed or a genuine format-break finding, cranked wall-clock at the
recorded 10x factor against the new engine's now-higher per-example
baseline above).

## Not completed in this session (explicit)

- No before/after fuzz-engine measurement exists for the OLD pin (see
  "Fuzz-engine adoption decisions" above) — only the new engine's
  numbers were captured; a literal old-vs-new campaign comparison
  would need a second checkout/dep round trip against the prior pin.
- No nelli-side bugs were found requiring escalation. The `nelli_cov.c`/
  `nelli_shm.c` linkage gap is doc drift (USAGE.md lagging the source's
  own stated requirement), not a functional defect, and needed no
  change to nelli itself.
- The property-suite timing increase (above) is recorded but not root-
  caused — a genuine open follow-up, not a blocker for this migration.
