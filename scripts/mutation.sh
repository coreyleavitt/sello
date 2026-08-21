#!/usr/bin/env bash
# scripts/mutation.sh — curated mutation-testing harness (RFC-002 slice 5).
#
# proptest's own `mutation.nim` v1 is `int -> int` only, so it cannot target
# Nim source directly; this is sello's own thin patch-based harness in its
# place. The actual mutate/compile/run/classify/report loop lives in
# tests/mutation/run_mutation.py (see its module doc comment for the full
# method and the mutant file format); this script is just the podman
# invocation + milpa preflight + forwarding "which files make up the unit
# suite", following the same shape as scripts/test.sh and scripts/fuzz.sh.
#
# Layout:
#   tests/mutation/mutants/*.mutant   — the curated catalog (84 mutants as of
#                                        RFC-006 slice 4's twelve-mutant
#                                        sha512.nim batch, up from 73/70/50
#                                        through the review-round/RFC-004/
#                                        round-3 batches before it, up from
#                                        RFC-003 slice 3's 46 and RFC-002
#                                        slice 5's original 36 — file-
#                                        addressed, so growing it to cover a
#                                        new source file is just adding more
#                                        *.mutant files, no harness changes),
#                                        one plain-text exact-string-patch
#                                        file per mutant.
#   tests/mutation/run_mutation.py    — the driver that actually applies,
#                                        compiles, runs, classifies, and
#                                        writes docs/mutation-results.md.
#
# Usage:  scripts/mutation.sh
#
# Wall clock: this compiles and runs the FULL unit suite once per mutant
# (one container-internal `nim c -r` pass per test file, per mutant) — the
# RFC calls for exactly this ("one container run per mutant is expected...
# full unit suite per the RFC — do not silently subset"). Everything happens
# inside ONE podman invocation, not one per mutant: run_mutation.py reuses a
# single scratch copy of the source tree across the whole campaign, which
# lets Nim's own nimcache carry unrelated dependencies (proptest and its own
# transitive deps, when fetched — sello resolves no unconditional
# dependency at all as of RFC-006) across mutants instead of paying their
# full compile cost each time —
# only the mutated file(s) and their transitive dependents actually
# recompile per mutant. Measured, not merely estimated (the original "low
# tens of minutes" guess was never checked against a real run): 318s for
# the original 36-mutant catalog (RFC-002 slice 5); the 46-mutant catalog
# RFC-003 slice 3 grew it to has measured 385-477s across separate runs
# on this shared host (RFC-003 slices 3 and 6) — both single-digit
# minutes, scaling roughly linearly with catalog size at a shade over
# 10s/mutant averaged across the whole campaign, with real run-to-run
# variance from host load rather than a fixed constant (individual
# mutants range from ~1.5s, killed almost instantly by a cheap unit file,
# to ~40s when the killing test happens to sit late in the file list).
# Budget accordingly as the catalog grows further; a survivor that needs
# a new test still requires re-running this script (or a targeted subset
# while iterating) to confirm the kill. RFC-006 slice 4 grew the catalog
# to 84 mutants (73 -> 84, an 11-mutant sha512.nim batch minus one retired
# as a confirmed-equivalent replacement, see docs/mutation-results.md's
# catalog numbering note) — measured 553s on this shared host, still
# single-digit minutes and consistent with the same roughly-linear scaling.
#
# Needs only the base Nim image (python3 is present there; confirmed
# empirically, same standard as the rest of this project's toolchain
# claims) — no libsodium/z3, so no sello-dev image, matching
# scripts/test.sh/scripts/fuzz.sh's "base image, no network" profile.
#
# Mounts: the project + the milpa CAS (at both its canonical path and its
# host-absolute path, so milpa's absolute dep symlinks under _deps/ resolve
# in-container, including from the scratch copy run_mutation.py makes under
# /tmp — the canonical-path mount is what makes that copy's _deps/ symlinks
# resolve regardless of the scratch directory's depth; see
# run_mutation.py's module doc comment) — same pattern as scripts/test.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

# unit_test_files ("which unit test files make up the suite") is defined in
# scripts/lib/unit-test-files.sh and sourced here, not retyped — same single
# source of truth scripts/test.sh and scripts/test-libsodium.sh already
# share (round-2 finding 25).
source "$(dirname "$0")/lib/unit-test-files.sh"

# Lockfile-conformance preflight (RFC-001 ledger finding 30) — see
# scripts/lib/milpa-preflight.sh for exactly what this does and does not
# treat as fatal.
source "$(dirname "$0")/lib/milpa-preflight.sh"
milpa_preflight

# Loud degraded-suite warning (mirrors scripts/test.sh's own per-file
# SKIPPED banner) -- unit-test-files.sh silently drops the four
# test_properties_*.nim files from unit_test_files whenever _deps/proptest
# is absent (a fresh clone's plain `milpa fetch`, with no
# `--features proptest`, never populates it). scripts/test.sh compensates
# by echoing a SKIPPED line per omitted file so that's visible in its own
# output; this script has no equivalent per-file echo (the omitted files
# never even reach run_mutation.py's argv), so without this banner a
# mutation run on such a host would report an equally "clean" kill rate
# off a materially weaker suite with nothing flagging the degradation.
if [[ ${#skipped_property_files[@]} -gt 0 ]]; then
  echo "=================================================================="
  echo "WARNING: proptest not fetched (_deps/proptest absent) -- the"
  echo "following property-test files are EXCLUDED from this mutation run:"
  for f in "${skipped_property_files[@]}"; do
    echo "  - $f"
  done
  echo ""
  echo "The kill-rate result below reflects a REDUCED suite, missing all"
  echo "property-based coverage those files provide. For a full-strength"
  echo "mutation run, fetch proptest first: milpa fetch --features proptest"
  echo "=================================================================="
fi

img=ghcr.io/coreyleavitt/nim:2.2.10

podman run --rm \
  -v "$PWD:/workspace" \
  -v "$HOME/.cache/milpa:/.cache/milpa" \
  -v "$HOME/.cache/milpa:$HOME/.cache/milpa" \
  -w /workspace \
  "$img" \
  python3 tests/mutation/run_mutation.py "${unit_test_files[@]}"
