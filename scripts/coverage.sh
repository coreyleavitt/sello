#!/usr/bin/env bash
# scripts/coverage.sh -- RFC-005 slice 17: the "coverage-ratchet" CI
# check's one script invocation (Part B's build-path invariant), and A3's
# implementation (docs/rfc-005-validation-infra.md lines 352-383).
#
# WHAT THIS MEASURES: builds and runs the full unit+property suite
# (scripts/lib/unit-test-files.sh's own array -- the same suite
# scripts/test.sh runs) with `--passC:--coverage --passL:--coverage
# --lineDir:on` (gcc's `--coverage` = `-fprofile-arcs -ftest-coverage`;
# `--lineDir:on` is what makes gcov's own line records point at
# `src/sello/*.nim` source lines instead of nimcache's content-hashed C
# files, per the RFC's own text), merges every test binary's own gcov
# data via `lcov -a`, extracts `src/sello/*` only, and computes a LINE
# coverage percentage per file plus one aggregate percentage across the
# whole extracted set -- each floored to one decimal (exact integer
# arithmetic; see tests/coverage/coverage_report_gen.py's own module doc
# comment for why float rounding would reintroduce the exact "line-level
# jitter" the floor exists to absorb). Line coverage only -- no branch,
# no function-coverage claim; matches A3's own stated scope.
#
# PER-BINARY OBJECT DIRS (so gcov data from 18 different test binaries
# does not collide): each test file gets its own `--nimcache:<dir>`,
# so its own C translation units, .gcno (compile-time coverage graph) and
# .gcda (runtime hit-count) files all live under a directory unique to
# that ONE binary. `lcov --capture --directory <that dir>` then captures
# exactly that binary's own data, and `lcov -a` merges the 18 resulting
# per-binary .info files into one cumulative dataset (RFC-005 Part B: "a
# single suite-wide line-coverage ratio, matching lcov --summary"), the
# same way this project already merges 18 separately-nimcached test
# binaries' worth of coverage of the SAME shared src/sello/*.nim files
# (field.nim gets compiled fresh into all 18 nimcache dirs, and its
# coverage across all 18 runs is what the merge sums).
#
# WHY sello-dev, NOT the base ghcr.io/coreyleavitt/nim image: only
# sello-dev carries `lcov` (Containerfile, this slice's own addition --
# see CLAUDE.md's own note that this package pulls in a large perl
# dependency chain, accepted since there is no lighter-weight substitute
# in this repo's zypper base). `gcov` itself ships with gcc (already in
# the base image), but lcov's own report-generation/merge/extract tooling
# does not.
#
# FIXED SEEDS for the property suites (A3: "runs the randomized property
# suites under fixed seeds"): VERIFIED EMPIRICALLY THIS SLICE, not merely
# assumed, that no new mechanism was needed here. Every one of the six
# `test_properties_*.nim` files' own settings constructors
# (`covSettings`/`settingsWithExamples`/`settingsForPoints`) builds its
# Settings from nelli's own `defaultSettings()`, which already carries
# a FIXED, non-random default (`Settings.seed = 0x1234567890abcdef'u64`,
# `_deps/nelli/src/nelli/engine/types.nim`) -- and grep across all
# six files confirms none of them ever sets `.seed`, `.testId`, or
# `.derandomize` to anything time/entropy-derived. So a plain
# `scripts/test.sh` run and this script's own coverage-instrumented run
# already explore the IDENTICAL covered set on every invocation, with no
# env-var seed hook needed (unlike RFC-005 slice 26's `SELLO_PROPERTY_CRANK`
# example-count crank, which genuinely had no existing knob to reuse).
# `SELLO_PROPERTY_CRANK` is left unset here deliberately, for the same
# reason: this job's own numbers must match what a maintainer's plain
# `scripts/test.sh`-driven mental model of "the suite" produces, not a
# cranked nightly-only example count.
#
# DETERMINISM CHECK (A3's own DoD: "build+run twice, identical numbers"):
# this script CAN run its ENTIRE build-run-capture-merge-extract-compute
# pipeline TWICE, into two independent working directories
# (build/coverage/run1, build/coverage/run2), and assert the two
# resulting text dumps are byte-identical before treating either as "the
# fresh dump" fed to the regenerable-baseline idiom below -- the literal,
# full-strength reading of the DoD text (a real second build, not a
# cheaper "rerun the same binaries" shortcut).
#
# WALL-CLOCK DECISION (measured, not guessed -- RFC-005 slice 17's own
# "measure first, decide with a recommendation, record" instruction):
# the FIRST real hosted run of this job (a measurement push, mirroring
# slice 15's own precedent) ran the double pass unconditionally and
# measured a real ~26-minute job (two ~12.5-minute passes plus ~1 minute
# of checkout/milpa/nelli-fetch overhead) -- well past the merge
# gate's ~15-minute aim, and by a wide margin the new long pole (the
# previous heaviest required check, property-linux-amd64-gcc, sits at
# ~9.5 minutes). That SAME run's determinism check PASSED (both passes
# produced byte-identical dumps) -- real, positive evidence the pipeline
# IS deterministic (fixed nelli seeds -- see the FIXED SEEDS section
# below -- plus deterministic gcov capture/merge/extract), not merely
# assumed. Rather than build a branch-pattern or sharding fallback (the
# RFC's own pre-authorized escape hatch, `docs/rfc-005-validation-infra.md`'s
# "Ordering & risks" section) for a job this project's own branch model
# (every push, every branch, no path filter, no branch filter -- see
# CLAUDE.md's "No-path-filter rule") has no natural way to narrow, the
# decision recorded here is CHEAPER and just as sound: run a SINGLE pass
# by default (this is what CI's own `coverage-ratchet` job invokes, no
# flags) -- roughly HALF the wall-clock, landing this job close to (not
# under) the previous long pole rather than nearly 3x past it -- and
# reserve the double-pass determinism re-verification for the two moments
# it actually matters: (1) every `--update` (baseline.sh's own "local,
# deliberate act" doctrine already keeps this off the per-push CI path,
# so paying the extra pass there costs nothing in CI wall-clock -- see
# below), and (2) an explicit `--verify-determinism` flag for a
# maintainer who wants to re-confirm the property without regenerating
# the baseline. A regression that made the suite's OWN covered set
# non-deterministic (e.g. a property test accidentally reading real
# entropy) would still surface indirectly on the very next `--update` a
# maintainer runs (a suite that flakes under `--verify-determinism`
# there fails loud, per the block below) -- this is a real, if slightly
# delayed, backstop, not a silently dropped guarantee.
#
# THE REGENERABLE-BASELINE IDIOM (scripts/lib/baseline.sh, RFC-005 Part
# B) governs the RAISE path exactly like every other baseline-consuming
# gate in this project (api-surface, api-surface-libsodium): ANY diff
# between the fresh dump and the committed
# tests/coverage/expected/baseline.txt -- a raise, a drop, or a
# rearrangement -- fails `--check` and must be accepted via a deliberate,
# local-only `--update` (hard-fails under $CI, baseline.sh's own
# standing guard). THIS SLICE'S OWN READING of A3's "raising is a
# deliberate commit / the down-path is governed too" text (recorded here
# per the task's own instruction, since the RFC text does not spell out
# the exact mechanics): the DOWN-PATH governance -- "the gate accepts a
# drop iff the ledger's newest entry cites the new number" -- is enforced
# AT UPDATE TIME, not by the CI check itself. `--update` computes the
# fresh numbers, compares them key-by-key against the CURRENTLY COMMITTED
# baseline.txt (when one exists), and for every key whose fresh value is
# LOWER than committed, REFUSES to write the new baseline.txt at all
# unless tests/coverage/expected/justifications.md's newest (topmost)
# entry's `Cites:` line names that exact key and exact new (lower) value
# (see that file's own header for the precise format the parser expects).
# Once a maintainer has satisfied that gate locally and committed both
# the lowered baseline.txt and the justification entry together, the CI
# check (`--check`, the only mode CI ever runs) is the SAME ordinary
# "fresh == committed" comparison every other baseline-consuming gate
# uses -- it does not re-derive "was this drop justified" from git
# history, because that fact was already adjudicated, once, at the
# moment a human ran --update. This mirrors baseline_update's own
# existing "regeneration is a local, deliberate act" doctrine (the
# CI-hard-fail guard) rather than inventing a second, parallel mechanism;
# it also means a RAISE needs no justification entry at all (a raise
# never fails the drop-detection comparison above), matching this
# script's own reading of "raising is a deliberate commit" as "needs an
# --update + commit like anything else here," not "needs its own ledger
# entry."
#
# Usage:
#   scripts/coverage.sh                     # check, single pass (CI's own mode)
#   scripts/coverage.sh --verify-determinism  # check, but double-pass (build+run twice, assert identical)
#   scripts/coverage.sh --update            # regenerate the committed baseline -- ALWAYS double-pass (see WALL-CLOCK DECISION above); local only -- hard-fails under $CI
#   SELLO_IN_CONTAINER=1 scripts/coverage.sh [--update] [--verify-determinism]
#     # already inside the pinned sello-dev image (CI, or a maintainer's
#     # own already-in-container shell)
#
# Dual-mode (same convention as scripts/bmc.sh/scripts/test-libsodium.sh):
# with no SELLO_IN_CONTAINER set, this script resolves the sello-dev image
# by digest (scripts/lib/sello-dev-image.sh) and wraps itself inside it,
# recursing with SELLO_IN_CONTAINER=1 -- byte-identical logic to CI, not a
# parallel host-side reimplementation.
set -uo pipefail
cd "$(dirname "$0")/.."

update_mode=0
verify_determinism=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --update)
      update_mode=1
      shift
      ;;
    --verify-determinism)
      verify_determinism=1
      shift
      ;;
    *)
      echo "scripts/coverage.sh: usage: scripts/coverage.sh [--update] [--verify-determinism]" >&2
      exit 2
      ;;
  esac
done
# --update always double-runs (see the WALL-CLOCK DECISION section of
# this script's own header comment): a baseline regeneration is exactly
# the moment a maintainer wants the strongest evidence the new pinned
# numbers are reproducible, and --update is already a deliberate,
# infrequent, local-only act (baseline.sh's own CI hard-fail already
# keeps it off the per-push path), so paying the extra pass there is
# free in the sense that matters -- it never touches CI wall-clock.
if [[ "$update_mode" -eq 1 ]]; then
  verify_determinism=1
fi

# ---------------------------------------------------------------------
# run_coverage_once <workdir> -- builds+runs the full suite with coverage
# instrumentation into <workdir>, merges+extracts via lcov, and PRINTS
# the stable text dump (tests/coverage/coverage_report_gen.py's own
# output) to stdout. Assumes unit_test_files is already populated (see
# scripts/lib/unit-test-files.sh) and that `nim`/`lcov`/`python3` are all
# on PATH (true inside sello-dev; this function is only ever called from
# the SELLO_IN_CONTAINER=1 branch below).
# ---------------------------------------------------------------------
run_coverage_once() {
  local workdir="$1"
  rm -rf "$workdir"
  mkdir -p "$workdir/nimcache" "$workdir/info"

  local f b
  local -a info_files=()
  for f in "${unit_test_files[@]}"; do
    b="$(basename "$f" .nim)"
    echo "coverage: building+running $f (--coverage, nimcache=$workdir/nimcache/$b)" >&2
    if ! nim c --passC:--coverage --passL:--coverage --lineDir:on \
        --nimcache:"$workdir/nimcache/$b" -r "$f" \
        > "$workdir/nimcache/$b.build.log" 2>&1; then
      echo "coverage: FAIL -- $f did not build/run cleanly under --coverage instrumentation." >&2
      echo "coverage: this is a build/test failure, not a coverage-number question -- see the log below." >&2
      tail -n 80 "$workdir/nimcache/$b.build.log" >&2
      return 1
    fi
    if ! lcov --capture --directory "$workdir/nimcache/$b" \
        --output-file "$workdir/info/$b.info" \
        --rc branch_coverage=0 \
        --ignore-errors inconsistent,unsupported,gcov,deprecated -q \
        > "$workdir/info/$b.lcov.log" 2>&1; then
      echo "coverage: FAIL -- lcov capture failed for $f -- see the log below." >&2
      cat "$workdir/info/$b.lcov.log" >&2
      return 1
    fi
    info_files+=("$workdir/info/$b.info")
  done

  local -a add_args=()
  for f in "${info_files[@]}"; do
    add_args+=(-a "$f")
  done
  if ! lcov "${add_args[@]}" -o "$workdir/merged.info" \
      --rc branch_coverage=0 --ignore-errors inconsistent,unsupported,gcov,deprecated -q \
      > "$workdir/merge.log" 2>&1; then
    echo "coverage: FAIL -- lcov merge (-a) failed -- see the log below." >&2
    cat "$workdir/merge.log" >&2
    return 1
  fi

  if ! lcov --extract "$workdir/merged.info" '*/src/sello/*' \
      -o "$workdir/extracted.info" \
      --rc branch_coverage=0 --ignore-errors inconsistent,unsupported,gcov,deprecated -q \
      > "$workdir/extract.log" 2>&1; then
    echo "coverage: FAIL -- lcov extract failed -- see the log below." >&2
    cat "$workdir/extract.log" >&2
    return 1
  fi

  python3 tests/coverage/coverage_report_gen.py "$workdir/extracted.info"
}

if [ "${SELLO_IN_CONTAINER:-}" = "1" ]; then
  source "$(dirname "$0")/lib/milpa-install.sh"
  install_milpa "build/milpa-venv"
  echo "coverage: fetching nelli + transitives (--locked: asserts against the committed milpa.lock)" >&2
  "$MILPA_BIN" fetch --features nelli --locked

  # Re-source AFTER the fetch, mirroring scripts/mutation.sh's own
  # in-container pattern -- a bare CI checkout starts with no
  # _deps/nelli, so sourcing before the fetch would silently exclude
  # every test_properties_*.nim file from the coverage run.
  source "$(dirname "$0")/lib/unit-test-files.sh"
  if [[ ${#skipped_property_files[@]} -gt 0 ]]; then
    echo "coverage: FAIL -- nelli was fetched above, but scripts/lib/unit-test-files.sh" >&2
    echo "coverage: still reports ${#skipped_property_files[@]} skipped property file(s)." >&2
    echo "coverage: this should be unreachable in CI; investigate before trusting these numbers." >&2
    exit 1
  fi

  if [[ "$verify_determinism" -eq 1 ]]; then
    echo "coverage: === run 1/2 (determinism check) ===" >&2
    run1_out="$(run_coverage_once build/coverage/run1)" || exit 1
    echo "coverage: === run 2/2 (determinism check) ===" >&2
    run2_out="$(run_coverage_once build/coverage/run2)" || exit 1

    if [[ "$run1_out" != "$run2_out" ]]; then
      echo "" >&2
      echo "coverage: FAIL -- determinism check: two independent build+run passes produced" >&2
      echo "coverage: DIFFERENT coverage numbers. This gate requires the suite's covered set" >&2
      echo "coverage: to be reproducible (fixed nelli seeds, deterministic gcov merge) --" >&2
      echo "coverage: investigate before trusting either run's numbers. Diff (run1 -> run2):" >&2
      diff <(printf '%s\n' "$run1_out") <(printf '%s\n' "$run2_out") >&2 || true
      exit 1
    fi
    echo "coverage: determinism check OK -- both runs produced identical numbers." >&2
    fresh_body="$run1_out"
  else
    echo "coverage: === single pass (determinism re-verified via --update/--verify-determinism, not every push -- see this script's own header comment) ===" >&2
    fresh_body="$(run_coverage_once build/coverage/run1)" || exit 1
  fi
  fresh_file="$(mktemp)"
  printf '%s\n' "$fresh_body" > "$fresh_file"
  trap 'rm -f "$fresh_file"' EXIT

  source "$(dirname "$0")/lib/baseline.sh"
  pin_file="tests/coverage/expected/baseline.txt"
  generator_desc="tests/coverage/coverage_report_gen.py via scripts/coverage.sh (line coverage, aggregate + per-file, floored to one decimal, extracted from a merged lcov .info across the full unit+property suite -- see this script's own header comment)"
  regen_cmd_str="scripts/coverage.sh --update"

  if [[ "$update_mode" -eq 1 ]]; then
    source "$(dirname "$0")/lib/coverage-down-path.sh"
    coverage_down_path_guard "$pin_file" "tests/coverage/expected/justifications.md" "$fresh_body" || exit 1
    baseline_update "$pin_file" "$generator_desc" "$regen_cmd_str" -- cat "$fresh_file"
  else
    baseline_check "$pin_file" "$generator_desc" "$regen_cmd_str" -- cat "$fresh_file"
  fi
  exit $?
else
  source "$(dirname "$0")/lib/milpa-preflight.sh"
  milpa_preflight

  source "$(dirname "$0")/lib/sello-dev-image.sh"
  resolve_sello_dev_image || exit 1

  extra_args=""
  [[ "$update_mode" -eq 1 ]] && extra_args+=" --update"
  [[ "$verify_determinism" -eq 1 ]] && extra_args+=" --verify-determinism"
  podman run --rm \
    -e CI \
    -v "$PWD:/workspace" \
    -v "$HOME/.cache/milpa:/.cache/milpa" \
    -v "$HOME/.cache/milpa:$HOME/.cache/milpa" \
    -w /workspace \
    "$img" \
    bash -c "SELLO_IN_CONTAINER=1 scripts/coverage.sh$extra_args"
  exit $?
fi
