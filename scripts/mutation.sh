#!/usr/bin/env bash
# scripts/mutation.sh — curated mutation-testing harness (RFC-002 slice 5).
#
# nelli's own `mutation.nim` v1 is `int -> int` only, so it cannot target
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
# Usage:  scripts/mutation.sh                # full catalog
#         scripts/mutation.sh --shard 2/4     # RFC-005 slice 15: one
#                                                round-robin quarter of the
#                                                catalog (this leading flag
#                                                is forwarded verbatim to
#                                                tests/mutation/run_mutation.py
#                                                — see that file's own
#                                                parse_shard()/shard_catalog()
#                                                for the exact partition;
#                                                this script does no
#                                                validation of its own)
#         SELLO_IN_CONTAINER=1 scripts/mutation.sh   # already inside the
#                                                       pinned image (CI)
#
# Wall clock: this compiles and runs the FULL unit suite once per mutant
# (one container-internal `nim c -r` pass per test file, per mutant) — the
# RFC calls for exactly this ("one container run per mutant is expected...
# full unit suite per the RFC — do not silently subset"). Everything happens
# inside ONE podman invocation, not one per mutant: run_mutation.py reuses a
# single scratch copy of the source tree across the whole campaign, which
# lets Nim's own nimcache carry unrelated dependencies (nelli and its own
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
# RFC-005 slice 15 measured this catalog's real HOSTED-runner cost (a
# fresh checkout, no warm nimcache) for the placement decision — see
# CLAUDE.md's own "Mutation + bmc jobs" CI paragraph and the RFC's
# "Ordering & risks" section for the exact numbers and the sharding
# decision they produced.
#
# Needs only the base Nim image (python3 is present there; confirmed
# empirically, same standard as the rest of this project's toolchain
# claims) — no libsodium/z3, so no sello-dev image, matching
# scripts/test.sh/scripts/fuzz.sh's "base image, no network" profile. This
# is a deliberate departure from the RFC's own "one image, consolidate"
# preference for bmc.sh (below): sello-dev's package set (libsodium-devel,
# z3-devel, the multilib/valgrind/lcov/cross-compile toolchains) buys this
# script nothing — mutation testing never links against libsodium or z3 —
# so pulling the heavier image here would only add cold-pull cost with no
# offsetting benefit, unlike bmc.sh, which genuinely needs z3-devel.
#
# Mounts (host mode): the project + the milpa CAS (at both its canonical
# path and its host-absolute path, so milpa's absolute dep symlinks under
# _deps/ resolve in-container, including from the scratch copy
# run_mutation.py makes under /tmp — the canonical-path mount is what makes
# that copy's _deps/ symlinks resolve regardless of the scratch directory's
# depth; see run_mutation.py's module doc comment) — same pattern as
# scripts/test.sh. Host mode is UNCHANGED by the RFC-005 slice 15 dual-mode
# retrofit below and continues to rely on the host's own already-fetched
# `_deps/nelli` (via `milpa fetch --features nelli`, run at least
# once) exactly as before — it does NOT fetch nelli itself the way the
# new SELLO_IN_CONTAINER=1 branch does (see that branch's own comment for
# why a bare CI checkout needs a different story).
set -euo pipefail
cd "$(dirname "$0")/.."

# --shard i/N (RFC-005 slice 15): an optional leading flag, forwarded
# verbatim to tests/mutation/run_mutation.py — this script does no
# parsing/validation of its own (that file's parse_shard() owns the
# format and error messages), mirroring scripts/test.sh's own --cc/
# --sanitize pass-through convention.
shard_args=()
if [[ "${1:-}" == "--shard" ]]; then
  if [[ $# -lt 2 ]]; then
    echo "scripts/mutation.sh: --shard requires a value (e.g. --shard 2/4)" >&2
    exit 2
  fi
  shard_args=(--shard "$2")
  shift 2
fi

# unit_test_files ("which unit test files make up the suite") is defined in
# scripts/lib/unit-test-files.sh and sourced here, not retyped — same single
# source of truth scripts/test.sh and scripts/test-libsodium.sh already
# share (round-2 finding 25). Host mode uses whatever this first sourcing
# finds (host-side _deps/nelli state); the SELLO_IN_CONTAINER=1 branch
# below re-sources AFTER its own fresh nelli fetch, so its own
# unit_test_files/skipped_property_files reflect the fetch it just did, not
# this pre-fetch state.
source "$(dirname "$0")/lib/unit-test-files.sh"

if [ "${SELLO_IN_CONTAINER:-}" = "1" ]; then
  # RFC-005 slice 15 — already inside the pinned image (CI's own
  # `container:` field): no podman wrapper to invoke, and (unlike host
  # mode, which relies on a maintainer's pre-existing `milpa fetch
  # --features nelli`) no host-side _deps/ to mount either — a CI
  # checkout starts bare. Fetch nelli ourselves, mirroring
  # scripts/ci-property.sh's/scripts/build-smoke.sh's own in-container
  # fetch pattern, so this run exercises the SAME full unit+property suite
  # a maintainer's local `scripts/mutation.sh` run always has (nelli
  # fetched) — running this job against a reduced, property-suite-less
  # catalog would silently weaken the gate relative to what
  # docs/mutation-results.md's committed "84/84 killed" record actually
  # covers, exactly the degraded-suite risk the WARNING banner below
  # exists to flag for a host run and that this fetch avoids entirely in
  # CI.
  source "$(dirname "$0")/lib/milpa-install.sh"
  install_milpa "build/milpa-venv"
  echo "mutation: fetching nelli + transitives (--locked: asserts against the committed milpa.lock)" >&2
  "$MILPA_BIN" fetch --features nelli --locked

  # Re-source now that _deps/nelli exists — the sourcing above (before
  # the fetch) ran against a bare checkout and would have filtered every
  # test_properties_*.nim file out.
  source "$(dirname "$0")/lib/unit-test-files.sh"

  if [[ ${#skipped_property_files[@]} -gt 0 ]]; then
    echo "mutation: FAIL -- nelli was fetched above, but" \
         "scripts/lib/unit-test-files.sh still reports" \
         "${#skipped_property_files[@]} skipped property file(s)." >&2
    echo "mutation: this should be unreachable in CI; investigate before trusting this run's kill rate." >&2
    exit 1
  fi

  if [[ ${#shard_args[@]} -gt 0 ]]; then
    echo "mutation: running shard ${shard_args[1]} against ${#unit_test_files[@]} unit test files" >&2
  else
    echo "mutation: running the full catalog against ${#unit_test_files[@]} unit test files" >&2
  fi
  python3 tests/mutation/run_mutation.py "${shard_args[@]}" "${unit_test_files[@]}"
else
  # Lockfile-conformance preflight (RFC-001 ledger finding 30) — see
  # scripts/lib/milpa-preflight.sh for exactly what this does and does not
  # treat as fatal. Host-only: _deps/milpa.lock are host-side state,
  # meaningless to check from inside the container this preflight gates
  # entry to.
  source "$(dirname "$0")/lib/milpa-preflight.sh"
  milpa_preflight

  # Loud degraded-suite warning (mirrors scripts/test.sh's own per-file
  # SKIPPED banner) -- unit-test-files.sh silently drops the four
  # test_properties_*.nim files from unit_test_files whenever _deps/nelli
  # is absent (a fresh clone's plain `milpa fetch`, with no
  # `--features nelli`, never populates it). scripts/test.sh compensates
  # by echoing a SKIPPED line per omitted file so that's visible in its own
  # output; this script has no equivalent per-file echo (the omitted files
  # never even reach run_mutation.py's argv), so without this banner a
  # mutation run on such a host would report an equally "clean" kill rate
  # off a materially weaker suite with nothing flagging the degradation.
  if [[ ${#skipped_property_files[@]} -gt 0 ]]; then
    echo "=================================================================="
    echo "WARNING: nelli not fetched (_deps/nelli absent) -- the"
    echo "following property-test files are EXCLUDED from this mutation run:"
    for f in "${skipped_property_files[@]}"; do
      echo "  - $f"
    done
    echo ""
    echo "The kill-rate result below reflects a REDUCED suite, missing all"
    echo "property-based coverage those files provide. For a full-strength"
    echo "mutation run, fetch nelli first: milpa fetch --features nelli"
    echo "=================================================================="
  fi

  img=ghcr.io/coreyleavitt/nim:2.2.10

  podman run --rm \
    -v "$PWD:/workspace" \
    -v "$HOME/.cache/milpa:/.cache/milpa" \
    -v "$HOME/.cache/milpa:$HOME/.cache/milpa" \
    -w /workspace \
    "$img" \
    python3 tests/mutation/run_mutation.py "${shard_args[@]}" "${unit_test_files[@]}"
fi
