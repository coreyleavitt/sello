#!/usr/bin/env bash
# scripts/nightly-fuzz.sh -- RFC-005 slice 24 (Nightly part 1: fuzz
# continuity, A5). The nightly fuzz job's one script invocation
# (.github/workflows/nightly.yml's `fuzz` job) -- a long, multi-minute-
# per-target campaign over tests/fuzz/'s four attacker-input oracles
# (`pointDecode`, `verify`, `x25519`'s peer u-coordinate, `ristrettoDecode`
# -- see tests/fuzz/fuzz_common.nim's own module doc for the scope
# statement), with a CORPUS THAT SURVIVES ACROSS RUNS instead of starting
# from the same three-or-so hardcoded seeds every single night (the A5
# text's own framing: "the original draft's accumulation claim silently
# contradicted the no-bots non-goal" -- this script is the mechanism that
# makes accumulation genuinely true).
#
# WHAT THIS SCRIPT ADDS ON TOP OF scripts/fuzz.sh (which it calls, not
# duplicates -- RFC-005 Part B's build-path invariant: one audited copy of
# the sancov-build-then-run recipe, living exactly where it always has):
#
#   1. Corpus restore: this script does NOT restore the corpus itself --
#      that is .github/workflows/nightly.yml's `actions/cache` step's job
#      (this script's own header note below has the cache-key design).
#      This script consumes whatever is already on disk at
#      SELLO_FUZZ_CORPUS_DIR when it starts (restored by that step, or
#      genuinely absent on a cold start) and hands that path straight to
#      tests/fuzz/fuzz_main.nim via the SELLO_FUZZ_CORPUS_DIR env var --
#      the actual load/save mechanics live in nelli's own
#      `directoryBasedDatabase` (tests/fuzz/fuzz_common.nim's "Run +
#      report" section doc paragraph has the full design: one
#      `<persistKey>.bin` file per campaign, atomically read-modified
#      -written on every new-coverage admission DURING the run, not just
#      at the end -- so a mid-campaign kill still leaves a genuinely
#      -grown corpus on disk, not an empty one).
#   2. Corpus SAVE-back: nothing to do here either -- see (1). The
#      workflow's `actions/cache` save step (post-job, `if: always()`)
#      picks up whatever this script's campaign left in
#      SELLO_FUZZ_CORPUS_DIR, success or failure, so even a run that later
#      fails the staleness canary below still contributes its own
#      progress forward to the NEXT run.
#   3. The corpus STALENESS CANARY (this slice's own deliverable, ahead of
#      slice 26's notification wiring -- see the "Staleness canary" section
#      below for the full design and the fails-the-job-only scope, stated
#      honestly): a timestamp marker file inside the corpus directory,
#      written on every run that completes its campaign cleanly, checked
#      against a documented threshold BEFORE that run's own campaign
#      starts (i.e. it evaluates what actions/cache actually restored,
#      not what this run itself is about to produce).
#   4. Crash-artifact handoff: tests/fuzz/fuzz_common.nim's
#      `writeCrashArtifacts` (wired through fuzz_main.nim's
#      SELLO_FUZZ_CRASH_DIR env var) already writes a `(.txt message,
#      .choices.bin serialized-IR)` pair per retained crash to
#      build/fuzz-crashes/ on ANY caller, not just this one -- this
#      script just picks a stable default (below) so the workflow's
#      `actions/upload-artifact` step (an `if: failure()` step -- crash
#      artifacts are only worth uploading when something actually crashed)
#      has a fixed, known path to point at.
#
# Nightly campaign budget (RFC-005 Part B's "Nightly budget" paragraph:
# "the nightly slices record measured per-job times"; this slice's own
# task text: "likely 300-600s/target given 4 targets and hosted-runner
# limits"): 450 SECONDS PER TARGET by default (SELLO_FUZZ_SECONDS
# overrides), i.e. 1800s = 30 minutes total campaign wall clock across the
# four targets -- chosen as the midpoint of that range: meaningfully
# deeper than a maintainer's manual `scripts/fuzz.sh` default (60s/target,
# a smoke-sized sanity check) or scripts/build-smoke.sh's single-input
# compile-smoke (not a campaign at all), while leaving enormous headroom
# under GitHub's 6-hour per-job hosted-runner limit (RFC-005 Part B's
# nightly-budget paragraph: "a job TIMEOUT is distinguished from a job
# FAILURE" -- at 30 minutes total this job is nowhere near that
# boundary, so no timeout-handling machinery beyond the workflow's own
# `timeout-minutes` safety net is needed for THIS job specifically). Wall
# -clock is measured and recorded per the RFC's own instruction --
# see docs/rfc-005-validation-infra.handoff.md's slice 24 entry for the
# real, run-id-cited numbers.
#
# Staleness canary (this slice's own literal deliverable text: "fail the
# JOB if the restored corpus is older than a documented threshold or
# absent when it should exist" -- as of RFC-005 slice 26, a JOB failure
# from this canary is no longer the end of the story: .github/workflows/
# nightly.yml's own `notify` job picks up any non-success `fuzz` job
# conclusion, this one included, and opens/updates a pinned GitHub issue
# -- see that job's own comment for the full notification design):
#   - Marker file: `<corpus-dir>/.last-success`, a Unix timestamp (seconds)
#     written ONLY after a campaign completes with exit 0 (a crash or a
#     coverage-gate failure does NOT refresh it -- a failed run's partial
#     corpus growth still gets cached forward per point 2 above, but the
#     staleness clock keeps counting until a run actually succeeds
#     end-to-end, which is the honest signal: "how long since this corpus
#     was last known-good").
#   - Threshold: SELLO_FUZZ_STALENESS_THRESHOLD_HOURS, default 48 (two
#     missed nightlies' worth of slack against a once-daily schedule --
#     one missed/delayed run is not itself alarming on a hosted scheduler
#     with GitHub's own documented queuing jitter, but two in a row means
#     either the schedule stopped firing or every recent run has been
#     failing before reaching a successful save, either of which is worth
#     a human's attention).
#   - Absent marker: treated as stale UNLESS SELLO_FUZZ_ALLOW_COLD_START=1
#     is set -- the literal "absent when it should exist" half of the
#     deliverable text. A brand-new corpus directory (this feature's own
#     first-ever run, or a deliberately reset cache) is the ONE case
#     absence is expected rather than a sign the restore step silently
#     failed; requiring an explicit opt-in for that case (rather than,
#     say, silently treating "not the first run of the whole workflow"
#     via some other heuristic) means an accidental cache eviction or a
#     genuinely broken restore step fails loud by DEFAULT, matching this
#     project's standing "silent skip must be a red check" posture
#     (scripts/ci-property.sh's own nelli-skip-banner assertion is the
#     precedent this mirrors).
#   - Consequence: a stale-or-absent verdict at start is recorded and
#     enforced at the END of this script (after the campaign itself has
#     run and had its own chance to fail for its own reasons) -- so a
#     stale-corpus run still contributes whatever real fuzzing value the
#     budget bought before the job goes red, rather than aborting before
#     ever exercising the harness. Both failure classes (staleness,
#     campaign) are printed with distinct, unmissable banners so a log
#     reader never has to guess which one fired.
#   - Scope, stated honestly per this slice's own instruction: this is
#     the literal, mechanical freshness check the task text describes --
#     NOT the richer "uncommitted corpus growth > N nightlies since the
#     last human snapshot-commit" canary the RFC's own A5 prose also
#     mentions (that richer canary remains out of scope even after
#     RFC-005 slice 26's notification wiring; this script still only ever
#     FAILS THE JOB on the mechanical freshness check above -- slice 26's
#     addition is that a job failure from THIS canary now also reaches a
#     human, via nightly.yml's own `notify` job, not a change to what this
#     script itself decides). See CLAUDE.md's nightly-workflow paragraph
#     and the snapshot-commit
#     ritual note in tests/fuzz/README for how the two relate.
#
# Corpus-delta summary: already emitted by tests/fuzz/fuzz_common.nim's
# `runExternalTarget` itself (the "corpus persistence: key=... restored
# entries=N" / "entries after run=N (delta +M)" lines, once per target),
# via scripts/fuzz.sh's own stdout -- this script does not duplicate that
# reporting, only surfaces it (nothing here suppresses fuzz.sh's output).
#
# Dual-mode (matching every other RFC-005 script's own standing
# convention -- scripts/ci-property.sh/scripts/build-smoke.sh/scripts/
# fuzz.sh): with no SELLO_IN_CONTAINER set (a maintainer's host), this
# script wraps ITSELF inside the pinned podman image and recurses with
# SELLO_IN_CONTAINER=1. Under SELLO_IN_CONTAINER=1 (the nightly workflow's
# own `container:` field), it runs the in-container body directly. Not
# expected to be invoked locally in the ordinary course of things (this is
# a nightly-schedule/workflow_dispatch job), but kept dual-mode anyway for
# the same reason every other RFC-005 script is: a maintainer investigating
# a nightly failure should be able to reproduce the exact command locally.
#
# Usage:
#   scripts/nightly-fuzz.sh
#   SELLO_IN_CONTAINER=1 scripts/nightly-fuzz.sh
#   SELLO_FUZZ_SECONDS=30 scripts/nightly-fuzz.sh                    # shorter demo/iteration budget
#   SELLO_FUZZ_STALENESS_THRESHOLD_HOURS=0 scripts/nightly-fuzz.sh   # force the staleness canary red
#   SELLO_FUZZ_ALLOW_COLD_START=1 scripts/nightly-fuzz.sh            # first-ever run, no marker yet
set -euo pipefail
cd "$(dirname "$0")/.."

run_in_container() {
  source "$(dirname "$0")/lib/milpa-install.sh"
  install_milpa "build/milpa-venv"

  echo "nightly-fuzz: fetching nelli + transitives (--locked: asserts against the committed milpa.lock)" >&2
  "$MILPA_BIN" fetch --features nelli --locked

  corpus_dir="${SELLO_FUZZ_CORPUS_DIR:-build/fuzz-corpus}"
  crash_dir="${SELLO_FUZZ_CRASH_DIR:-build/fuzz-crashes}"
  seconds="${SELLO_FUZZ_SECONDS:-450}"
  threshold_hours="${SELLO_FUZZ_STALENESS_THRESHOLD_HOURS:-48}"
  allow_cold_start="${SELLO_FUZZ_ALLOW_COLD_START:-0}"
  marker="$corpus_dir/.last-success"

  mkdir -p "$corpus_dir"

  echo "=============================================================="
  echo "nightly-fuzz: corpus dir:        $corpus_dir"
  echo "nightly-fuzz: crash dir:         $crash_dir"
  echo "nightly-fuzz: seconds/target:    $seconds (total: $((seconds * 4))s across 4 targets)"
  echo "nightly-fuzz: staleness thresh:  ${threshold_hours}h"
  echo "nightly-fuzz: allow cold start:  $allow_cold_start"
  echo "=============================================================="

  # --- Staleness canary: evaluate what was RESTORED, before this run's
  # own campaign has a chance to touch the marker. -----------------------
  stale=0
  stale_reason=""
  if [[ -f "$marker" ]]; then
    last_ts="$(cat "$marker")"
    now_ts="$(date +%s)"
    if ! [[ "$last_ts" =~ ^[0-9]+$ ]]; then
      stale=1
      stale_reason="marker file '$marker' exists but is not a valid timestamp ('$last_ts')"
    else
      age_seconds=$(( now_ts - last_ts ))
      age_hours=$(( age_seconds / 3600 ))
      threshold_seconds=$(( threshold_hours * 3600 ))
      echo "nightly-fuzz: restored corpus marker age: ${age_hours}h / ${age_seconds}s (threshold ${threshold_hours}h / ${threshold_seconds}s)"
      # Compare in SECONDS, not truncated hours (this slice's own bug,
      # caught during the staleness red-path DoD demo): two runs minutes
      # apart both truncate to "0h" old, so an hour-granularity compare
      # (`age_hours > threshold_hours`, i.e. `0 > 0`) never trips even
      # with SELLO_FUZZ_STALENESS_THRESHOLD_HOURS=0 -- the documented
      # mechanism for forcing this canary red on demand. Comparing
      # age_seconds against threshold_hours*3600 fixes both: threshold=0
      # trips on any nonzero elapsed time (the intended "force red"
      # behavior), and the real 48h default still means 48 real hours,
      # not "48, rounded from whatever the true age truncates to."
      if (( age_seconds > threshold_seconds )); then
        stale=1
        stale_reason="restored corpus marker is ${age_hours}h (${age_seconds}s) old, exceeds the ${threshold_hours}h (${threshold_seconds}s) threshold"
      fi
    fi
  else
    echo "nightly-fuzz: no corpus marker found at $marker"
    if [[ "$allow_cold_start" != "1" ]]; then
      stale=1
      stale_reason="corpus marker absent at $marker and SELLO_FUZZ_ALLOW_COLD_START not set -- treating this as a failed/missing restore, not an intentional first run"
    else
      echo "nightly-fuzz: SELLO_FUZZ_ALLOW_COLD_START=1 -- treating this as a deliberate first-ever/cold-start run, not a canary failure."
    fi
  fi

  # --- Run the real campaign (scripts/fuzz.sh -- one audited build+run
  # recipe, not duplicated here). Do not abort on its failure -- the
  # staleness verdict above still needs to be reported, and a stale-corpus
  # run's own real campaign result is independently informative. ---------
  export SELLO_FUZZ_CORPUS_DIR="$corpus_dir"
  export SELLO_FUZZ_CRASH_DIR="$crash_dir"
  campaign_status=0
  SELLO_IN_CONTAINER=1 scripts/fuzz.sh "$seconds" || campaign_status=$?

  if [[ "$campaign_status" -eq 0 ]]; then
    date +%s > "$marker"
    echo "nightly-fuzz: campaign completed cleanly -- staleness marker refreshed ($marker)."
  else
    echo "nightly-fuzz: campaign exited $campaign_status -- staleness marker NOT refreshed (corpus growth up to this point is still cached forward, per this script's own header note)."
  fi

  echo "=============================================================="
  echo "nightly-fuzz: SUMMARY"
  echo "nightly-fuzz:   campaign exit status: $campaign_status"
  if [[ "$stale" -eq 1 ]]; then
    echo "nightly-fuzz:   !!! STALENESS CANARY: FAILED -- $stale_reason !!!"
    echo "nightly-fuzz:   (this job failure reaches nightly.yml's own notify job -- RFC-005 slice 26 -- which opens/updates a pinned GitHub issue. See this script's own header comment.)"
  else
    echo "nightly-fuzz:   staleness canary: OK"
  fi
  echo "=============================================================="

  if [[ "$campaign_status" -ne 0 ]]; then
    echo "nightly-fuzz: FAIL -- fuzz campaign itself failed (crash or coverage gate -- see scripts/fuzz.sh output above)." >&2
    exit "$campaign_status"
  fi
  if [[ "$stale" -eq 1 ]]; then
    echo "nightly-fuzz: FAIL -- corpus staleness canary tripped: $stale_reason" >&2
    exit 1
  fi
  echo "nightly-fuzz: OK -- campaign clean, corpus fresh."
}

if [ "${SELLO_IN_CONTAINER:-}" = "1" ]; then
  run_in_container
  exit $?
else
  # Lockfile-conformance preflight (RFC-001 ledger finding 30), same
  # courtesy staleness check every other dual-mode script's host branch
  # runs before its podman invocation.
  source "$(dirname "$0")/lib/milpa-preflight.sh"
  milpa_preflight

  img=ghcr.io/coreyleavitt/nim:2.2.10
  podman run --rm \
    -v "$PWD:/workspace" \
    -v "$HOME/.cache/milpa:/.cache/milpa" \
    -v "$HOME/.cache/milpa:$HOME/.cache/milpa" \
    -w /workspace \
    -e SELLO_IN_CONTAINER=1 \
    -e SELLO_FUZZ_SECONDS \
    -e SELLO_FUZZ_CORPUS_DIR \
    -e SELLO_FUZZ_CRASH_DIR \
    -e SELLO_FUZZ_STALENESS_THRESHOLD_HOURS \
    -e SELLO_FUZZ_ALLOW_COLD_START \
    "$img" \
    bash -c "scripts/nightly-fuzz.sh"
fi
