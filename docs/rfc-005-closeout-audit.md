# RFC-005 slice 32: close-out audit

Audited 2026-08-30, against `main` HEAD `d8a893a` (merge-gate run
`33320824230` on the immediately preceding content commit `d48fa8d`,
27/27 required checks green — the handoff-record-only commit `d8a893a`
itself was still in flight in a separate merge-gate run at the moment
this audit was written; see the "Liveness verification method" section
below for how that was resolved) and live GitHub state queried directly
via `gh api` on the same date. This is deliverable (a) of RFC-005 slice
32 (Registry + close-out) — see `docs/rfc-005-validation-infra.md` lines
1165-1168 for the slice text and lines 37-75 for the dichotomy this audit
applies.

## The dichotomy (quoted, applied literally)

From `docs/rfc-005-validation-infra.md` lines 44-48:

> *every claim in the validation bar is either (i) continuously enforced
> by a named required check, traceable through the gates manifest, or
> (ii) an explicitly labeled deliberate manual ritual (timing-tier runs,
> results-doc commits, corpus snapshots) whose freshness is bounded by a
> CI-checked gate.*

Every row below is classified **(i)** or **(ii)** against this text
exactly — not "is there a script for this" (every line has one; that was
never the question) but "is the CLAUDE.md line span between running that
script and the property it claims closed by a required check or a
CI-checked freshness bound." A row that is neither is a **FINDING**.

## Liveness verification method

Structural presence (a name in `scripts/lib/gates.txt`, a job name in a
workflow file) is necessary but not sufficient — a manifest entry with no
live enforcement behind it is exactly the "gate proven only green"
failure mode RFC-005's own DoD text warns against. For every
**required-check** row this audit therefore checks three independent
things, not one:

1. The check name is a line in `scripts/lib/gates.txt` (27 entries,
   confirmed: `grep -v '^#' scripts/lib/gates.txt | grep -v '^$' | wc -l`
   → 27).
2. The check name is a job in `.github/workflows/merge-gate.yml`
   (`gates-manifest-sync` already asserts this on every push; re-derived
   here directly rather than trusted secondhand).
3. **The check name is in the LIVE ruleset's required-status-checks
   array**, queried directly: `gh api
   repos/coreyleavitt/sello/rulesets/21282945` (the `main` ruleset's own
   id, from `gh api repos/coreyleavitt/sello/rulesets`). Result: the live
   set's 27 context names, diffed against `gates.txt`'s 27 check names,
   are **byte-for-byte identical** (`diff` empty). This is the audit's
   own independent confirmation of what `ruleset-sync` already checks on
   every push — re-derived here rather than assumed from that check's own
   green status, per this slice's "verify liveness, not structure"
   instruction.
4. **The latest completed push-triggered `merge-gate` run on `main`**
   (run `33320824230`, commit `d48fa8d`, 2026-08-30T15:51:44Z) shows all
   27 jobs `success` — queried directly via `gh run view 33320824230
   --json jobs`, not inferred from a green badge. (A newer run,
   `33323256272` on the handoff-record-only commit `d8a893a`, was still
   `in_progress` at audit time; that commit touches no `src/`, script, or
   workflow file, so its outcome cannot change any row's classification —
   confirmed green before this branch's own push, see the handoff
   record.)

For every **nightly** row: the job name is confirmed present in
`.github/workflows/nightly.yml`, and the latest run carrying that job is
identified and its conclusion recorded. For every **manual-ritual** row:
the declared freshness canary is confirmed real (a committed file, or an
entry in `scripts/lib/validation-map-pending.txt`) exactly as
`validation-map-check.sh` checks — re-run locally this session
(`python3 scripts/lib/validation_map_check.py` → `OK`) rather than
trusted from its last CI green.

## Table A — CLAUDE.md "The validation bar" (11 lines)

| # | Line (abbreviated) | Class | Mechanism(s) | Live-verified | Red-demo evidence | Residual / carve-out |
|---|---|---|---|---|---|---|
| 1 | RFC 8032/RFC 7748 vector conformance | (i) | `unit-linux-amd64-gcc` + 6 sibling `unit-*` legs | 27/27 green, run `33320824230` | Pre-CI TDD red/green (RFC-001/RFC-006 own slice grinds; no GH Actions existed yet at authorship) | none |
| 2 | Google Wycheproof adversarial vectors | (i) | `unit-linux-amd64-gcc` (same unit suite) | as above | as above | no Wycheproof corpus for ristretto255 — RFC 9496 App. A + fuzzing + libsodium differential carry that weight instead, disclosed in-line |
| 3 | dudect timing harness | split: (i) compile-smoke + (ii) full-battery | (i) `build-smoke` compiles `ct_main.nim`, never runs it; (ii) `scripts/ct.sh` maintainer-run, ~1e6 samples/class | (i) confirmed green run `33320824230`; (ii) `docs/ct-results.md`'s "RFC-005 slice 23" section (last full run, post-`{.noinline.}` refresh) | (i) `build-smoke` red demo, slice 16; (ii) no CI red-demo concept applies to a manual ritual — the RFC's own DoD instead asks for the freshness bound, see Residual | **(ii)'s freshness bound is itself DEGRADED**: `dudect-full-battery`'s canary is `scripts/lib/validation-map-pending.txt`'s `dudect-full-battery 28` entry — a committed, honest "pending slice 28" marker, not yet a live query. Three targets (`` ristretto.`==` ``, `x25519(static)`, `sha512` compress) carry a standing carve-out, investigated and attributed to harness-resolution-floor artifact, not a leak — see `docs/ct-results.md` |
| 4 | Taint-based deterministic CT harness | split: (i) compile-smoke + (i) real verdict | (i) `build-smoke` compiles every `tests/ct_taint/` target; (i) `taint-ct-linux-amd64-gcc`/`-clang`, exactly zero memcheck errors per executed path | both confirmed green, run `33320824230` | Slice 19-22/22a: the real, reproducible clang-leg CT finding (`feCMove`/`feCSwap` under clang, 4348 errors/100 contexts on `target_sign`), fixed at its root (`valueBarrier32`), both legs confirmed clean pre- and post-fix (local + hosted CI); planted-leak-flip and anchor-id-rename red demos both confirmed firing on both backends (slice 22) | fully (i) — both halves are now required checks, a genuine strengthening beyond the RFC's own original (ii)-only ambition for this line |
| 5 | Mutation testing (84/84 killed) | (i) | `mutation` (`scripts/mutation.sh`, full catalog, unsharded) | green, run `33320824230`, ~475s hosted | scratch branch `rfc-005-slice15-red-demo`, run `33275913747` (surviving mutant, real red) | 3 retired-equivalent mutants (`F05`, `F31`, `H07`), each with recorded empirical evidence in `docs/mutation-results.md` — not survivors, a distinct disclosed category |
| 6 | Coverage ratchet | (i) | `coverage-ratchet` (`scripts/coverage.sh`, monotone per-file baseline) | green, run `33320824230` | scratch branch `rfc-005-slice17-red-demo`, run `33281550140` (`x25519.nim` 95.4%→95.3%, genuine minimal red; first attempt was an honest false-green, disclosed in the slice's own record, not hidden) | single-pass by default (double-pass determinism check is `--update`/`--verify-determinism`-only, a measured ~26min hosted cost ruled it out of the per-push default) — see **Finding 1** below, where README's own row text has not caught up to this decision |
| 7 | Differential testing against libsodium | (i) | `unit-linux-amd64-gcc-libsodium` (`scripts/test-libsodium.sh`, `SELLO_REQUIRE_LIBSODIUM=1` fatal-skip) | green, run `33320824230` | run `33272136700`, job `99152427489` (dropped `-d:selloLibsodium`, real red) | none — the fatal-skip mechanism closes the "silent no-op suite" gap explicitly |
| 8 | Property-based testing | (i) | `property-linux-amd64-gcc`/`-clang`/`-arm64-gcc` | green, run `33320824230` | Pre-CI TDD red/green at authorship (RFC-001..006); `property-linux-amd64-gcc`'s own CI red demo landed at slice 2 (`RES-LOCKED-DRIFT`, run `32706465557`) | none |
| 9 | Coverage-guided fuzzing | split: (i) compile+one-input-smoke + (ii) nightly campaign + (ii) snapshot ritual | (i) `build-smoke`; (ii) `fuzz` nightly job (450s/target, persisted corpus); (ii) hand-curation into `fuzz_common.nim`'s `*Seeds()` procs | (i) green, run `33320824230`; (ii) latest `nightly` job success in run `33316911555` (2026-08-30) | (i) slice 16 red demo | snapshot-ritual's freshness canary is `scripts/nightly-fuzz.sh`'s own corpus-staleness check (48h default threshold), confirmed real (not `none (by design)`) |
| 10 | Machine-checked Z3 proof (`recodeScalarRadix16` + mask/equality/reduce) | (i), with one disclosed sub-scope exception | `bmc-symex` (`scripts/bmc.sh`, all four `symex_*.nim` files) | green, run `33320824230`, ~165s hosted | scratch-branch red demo (broken symex query), slice 15 record | `symex_reduce.nim`'s whole-body composition (as opposed to its per-step lemma, which IS `sxUnsat`-proved) is **attempted-and-inconclusive**, gated behind `-d:selloBmcReduceFullChain`, off by default, disclosed honestly in both CLAUDE.md and the RFC — this is the one line in the whole validation bar that is neither fully (i) nor fully (ii): the per-step lemma is (i) (it runs in the required check every push), the whole-body composition is an open research question with no ritual claiming to close it, which is the honest, disclosed state, not a gap masquerading as closed |
| 11 | Audited alternative (`-d:selloLibsodium`) | (i) | `api-surface-libsodium` (facade compiles + surface pinned) + `unit-linux-amd64-gcc-libsodium` (row 7, interop) | green, run `33320824230` | slice 18 red demo (`ristretto.ristrettoUnchecked` export) | none |

## Table B — RFC-005 Part A items (A1-A9)

| Item | Title | Class | Mechanism | Live-verified | Red-demo evidence | Notes |
|---|---|---|---|---|---|---|
| A1 | Deterministic CT verification, taint-based | (i) | = Table A row 4 | see row 4 | see row 4 | this RFC's largest new capability (RFC's own text, not merely its headline) |
| A2 | Disassembly gate | (i) | `disasm-gate-gcc`/`disasm-gate-clang` (per-root conditional-branch profile vs. committed per-backend baseline) | green, run `33320824230`; live-required confirmed directly against ruleset `21282945` | scratch branch `rfc-005-slice23-red-demo` (reintroduced `feSqrtRatioM1`-class branch, red on both disasm-gate legs AND both taint-ct legs, confirming complementary-not-redundant instruments), reverted | **not its own CLAUDE.md "validation bar" bullet** and **not its own README validation-map row** — it is a required check, fully (i), traceable through `gates.txt`, but a reader following only the validation-bar bullet list or the README table would not learn it exists. See **Finding 2** below. |
| A3 | Coverage with a ratchet | (i) | = Table A row 6 | see row 6 | see row 6 | see Finding 1 |
| A4 | Platform breadth as test capability | nightly (ii)-shaped but CI-enforced, not a manual ritual | `s390x` nightly job (cross-compile + QEMU, unit+KAT scope; property suites proved prohibitively slow under emulation, a measured finding not an assumption) | latest `s390x` job success in nightly run `33316911555` (1m54s, well inside its 20min budget) | red-demo dispatch `33316382471`, job `99270495227` FAIL as required (planted endian-canary failure) | property-suite scope gap under QEMU is disclosed (CLAUDE.md's own "Ordering & risks" record), not silent |
| A5 | Fuzz campaign continuity | (ii), CI-checked freshness | = Table A row 9 (nightly campaign) | see row 9 | staleness-canary bug found and fixed same-session (hour-truncation bug, commit `ca5fbfe`), confirmed via the slice's own red-path demo | the one standing manual duty the no-bots rule imposes (the snapshot-promotion ritual) is explicitly named and has its own compensating freshness control |
| A6 | Toolchain canary | advisory, deliberately outside the dichotomy | `.github/workflows/toolchain-canary.yml` (`nim-devel`/`nim-latest-stable`/`newest-gcc`/`newest-clang`/`milpa-head`), unbadged by design | latest run `33310308051` success (2026-08-30) | pinned-issue notification wiring exercised via `force_failure` dispatch input | correctly NOT claimed as either (i) or (ii) — it watches drift in tools this project does not control, and the RFC's own text places it outside the enforced-property boundary; the README states this explicitly ("advisory-only... no badge") |
| A7 | Secret-target register | (i) | `secret-target-register` (`tests/registers/secret_targets.nim`, 37 entries, 20 direct/11 coveredBy/0 pending/6 permanent-exempt) | green, run `33320824230` | run `33293087699` (dudect coverage-check red) and run `33293184794` (rule-1 completeness red), both slice 20 | supports A1/A2's own containment checks (`disasmRoots()` ⊇ check, taint-column check) — infrastructure for other rows, not itself a validation-bar claim, correctly has no dedicated CLAUDE.md validation-bar bullet |
| A8 | API-surface gate | (i) | `api-surface`/`api-surface-libsodium` | green, run `33320824230` | run confirmed slice 18 (`ristretto.ristrettoUnchecked` export, red both locally and via real CI on a scratch branch) | see Table A row 11 |
| A9 | Nightly memcheck | nightly | `memcheck` (`scripts/memcheck.sh`, plain untainted Valgrind) | latest `memcheck` job success in nightly run `33316911555` (5m17s, inside its 30min budget) | red-demo dispatch `33316382471`, job `99270495183` FAIL as required (planted fixture) | landed together with A4/s390x in the same session (slice 25), closing a credential-blocked gap that had persisted since slice 26's own authoring time |

## Findings

Two genuine claim-outruns-mechanism findings surfaced by this audit,
neither fixed silently (per this slice's own instruction) — both are
"the row's own text describes a stronger or differently-shaped mechanism
than what actually runs," the exact class of defect this audit exists to
catch:

**Finding 1 — README's `coverage-ratchet` validation-map row overclaims
its per-push mechanism.** The row's Mechanism cell reads: `` `coverage-ratchet`
(`scripts/coverage.sh`, full unit+property suite, fixed proptest seeds,
build+run twice for a determinism check) ``. This describes the
DOUBLE-PASS behavior. But RFC-005 slice 17's own recorded decision
(CLAUDE.md's "Coverage ratchet" CI paragraph, and the handoff doc's
slice 17 entry) is that the required check runs **single-pass by
default** — a real hosted measurement found the double-pass determinism
check costs ~26 minutes, well past the merge-gate wall-clock budget, so
the double pass was demoted to an opt-in (`--update`/`--verify-determinism`),
never the per-push default `gates.txt`'s bare `scripts/coverage.sh`
invocation runs. The row's own words describe the code path the project
deliberately chose NOT to run on every push. This is not a
`validation-map-check.sh` failure (that check does not parse prose
depth inside the Mechanism cell, only the row's structural columns —
Category/Mechanism-job-name/Freshness-canary/Carve-out-doc/Row-key — so
this specific overclaim is invisible to the mechanical drift check, a
genuine blind spot worth naming alongside the finding itself) — it is a
stale sentence a human wrote once and never revisited after the
slice-17 wall-clock finding landed. Recommended fix (not applied by this
audit, per the "list, don't fix silently" instruction): reword the cell
to `` full unit+property suite, fixed proptest seeds, single-pass by
default (`--verify-determinism` opts into the double-pass check) ``.

**Finding 2 — A2 (the disassembly gate) has no dedicated row in
CLAUDE.md's "The validation bar" bullet list or README's validation-map
table.** `disasm-gate-gcc`/`disasm-gate-clang` are real, live-required
checks (confirmed directly against ruleset `21282945`), and CLAUDE.md
documents the mechanism in full under its own "**Disasm gate (A2, RFC-005
slice 23)**" CI-section paragraph — but neither the validation-bar bullet
list nor the README table's 19 rows names it. A reader auditing "what
does sello's validation bar consist of" via either of those two
canonical listings would not learn this instrument exists, even though
it is fully enforced (class (i), no residual). This is the mirror image
of Finding 1: not a claim outrunning its mechanism, but a real,
fully-enforced mechanism with no corresponding claim — an omission
rather than an overclaim, but the same root cause (a line that should
have been added in the same commit as the check, per the RFC's own
"per-slice doc rule," and was not). Recommended fix (not applied by this
audit): add a validation-bar bullet (`` A **disassembly gate**... `` )
and a corresponding README validation-map row, Row key `disasm-gate`,
Category `required-check`.

No other validation-bar line, and no other A1-A9 item, was found to
overclaim or underclaim its live mechanism as of this audit's live
queries.

## Degraded-mode summary (slices 27-29, Corey-physical)

Slices 27 (timing-tier provisioning), 28 (timing-tier runner +
workflow), and 29 (first quiet-box battery + carve-out re-adjudication)
remain open, blocked on physical hardware only the maintainer can
provision (`docs/rfc-005-validation-infra.handoff.md`'s "Corey-owned:
slice 27 (physical timing box)"). Two validation-bar consequences remain
in degraded mode as a direct result, both already honestly disclosed in
the committed record rather than silently masked:

- **The dudect full-battery freshness canary (Table A row 3(ii))** has
  no live query yet — its committed freshness-canary marker is the
  literal string `pending slice 28` in
  `scripts/lib/validation-map-pending.txt`, which `validation-map-check.sh`
  accepts as a real, reviewed, committed fact (not a free-floating
  claim) rather than as evidence the ritual itself is fresh. The battery
  itself last ran at slice 23 (post-`{.noinline.}` refresh) — see
  `docs/ct-results.md`'s "RFC-005 slice 23" section — and is not
  automatically re-run on any cadence until slice 28 lands the
  self-hosted runner and its own 10-day-staleness notification query
  (CLAUDE.md's own slice-26 timing-freshness-canary paragraph, itself
  marked "moves here" pending slice 28).
- **The release gate's timing-freshness clause (clause (iii) of
  `scripts/release-gate.sh`)** cannot currently pass on its own merits —
  no `timing.yml` workflow exists yet (confirmed: `ls .github/workflows/`
  has no timing-tier entry) and no `evidence` branch exists yet
  (confirmed: `gh api repos/coreyleavitt/sello/branches/evidence` → 404).
  Every real release cut before slice 28/29 land MUST go through the
  `--stale-accept` override path, which slice 30 built and demonstrated
  for exactly this reason (`docs/rfc-005-validation-infra.handoff.md`'s
  slice 30 record: "clause (iii) STALE/ABSENT" was the RFC's own expected
  degraded-mode reading given slices 27-29's open status). This is
  disclosed, not hidden: the README validation-map row for
  `release-gate-clauses` states the override path directly in its own
  Claim cell ("or an explicit, notation-checked stale-accept override").

Both items are the RFC's own recorded, pre-authorized degraded mode
(`docs/rfc-005-validation-infra.md`'s "Ordering & risks" section: "27-29
are the only physical-world dependency and can slide without blocking
anything except 30's timing-freshness gate — which the recorded degraded
mode covers if the box is the blocker"), not new findings by this audit.

## What this audit did NOT re-verify

Per the RFC's own scope for this slice (docs, not code), this audit did
not re-run `scripts/ct.sh`'s real timing battery, did not re-run
`scripts/mutation.sh`/`scripts/bmc.sh` locally (their green status on
`main`'s latest run, queried directly above, is the evidence), and did
not attempt to provision or simulate the timing tier. It DID run
`scripts/validation-map-check.sh` locally (result: `OK`) and did directly
query the live GitHub ruleset and the latest `main`/`nightly` run job
lists rather than trusting any committed doc's own retelling of a past
run.
