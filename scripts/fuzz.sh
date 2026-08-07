#!/usr/bin/env bash
# Coverage-guided fuzzing campaign (RFC-001 review finding 12, reworked by
# RFC-002 slice 3 into an EXTERNAL SanitizerCoverage target) over
# tests/fuzz/fuzz_main.nim / fuzz_external_target.nim. See those files'
# module doc comments for the full scope statement: attacker-controlled-
# input surface ONLY (ed25519.pointDecode, ed25519.verify, x25519's peer
# public u-coordinate) -- never the secret-scalar signing path, which is
# dudect's job (scripts/ct.sh), not a mutation fuzzer's.
#
# RFC-002 slice 3: the harness used to drive proptest's in-process
# `fuzzWith` against `{.cover.}`-instrumented wrapper procs -- a 2-edge
# coverage universe (decode ok/reject, verify accept/reject, x25519 some/
# none), saturated within the first few iterations. It now drives
# proptest's `externalTarget`/`fuzz` against a SEPARATE binary
# (`build/fuzz_external_target`, compiled from `fuzz_external_target.nim`)
# built with real SanitizerCoverage instrumentation
# (`-fsanitize-coverage=trace-pc -fno-pie`, gcc's PC-hash bitmap backend)
# and linked against proptest's vendored, UNFLAGGED `proptest_cov.c`
# runtime -- see `_deps/proptest/docs/fuzz/USAGE.md`'s "Instrumentation
# recipe (normative)" Nim row for the exact recipe this script follows.
# Audited sello sources stay pragma-free: only the harness's own external
# target file gets the sancov compile flags, never `src/sello/*`.
#
# Deliberately separate from scripts/test.sh (like scripts/ct.sh): this is
# an open-ended campaign, not a fixed-assertion pass/fail suite, and its
# default bound (minutes) is much longer than the rest of the suite. The
# driver DOES still hard-fail (non-zero exit) on either of two conditions,
# enforced from inside fuzz_common.nim's `runExternalTarget`: any crash
# (a retained SIGABRT/SIGSEGV/etc. from a `doAssert` or a genuine memory
# fault in the target), or a per-target coverage-edge count below
# `MinEdgesGate` -- the "an order of magnitude above the old 1-2" smoke
# gate RFC-002 slice 3 item 1 calls for, evidence the SanitizerCoverage
# wiring is actually steering the mutator rather than silently degrading
# to black-box random.
#
# Usage:
#   scripts/fuzz.sh                    # default: 60s/target x 3 = ~3 min total
#   scripts/fuzz.sh 15                 # 15s/target x 3 = ~45s total (smoke-sized)
#   SELLO_FUZZ_SECONDS=15 scripts/fuzz.sh   # same, via env (arg wins if both given)
#
# Needs only the base Nim image + the optional proptest milpa dep --
# `milpa fetch --features proptest` (see scripts/test.sh's header comment
# for the full optional-dep rationale). No z3/libsodium linkage: fuzz.nim
# never imports proptest/symex (confirmed in the B4a summary,
# docs/rfc-001-signing.handoff.md), so the plain base image suffices --
# gcc (for the sancov compile) already ships in that image alongside Nim's
# own C backend.
#
# Mounts: the project + the milpa CAS (at both the canonical path and its
# host-absolute path, so milpa's absolute dep symlinks under _deps/
# resolve in-container) -- same pattern as scripts/test.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

# Lockfile-conformance preflight (RFC-001 ledger finding 30) -- see
# scripts/lib/milpa-preflight.sh for exactly what this does and does not
# treat as fatal.
source "$(dirname "$0")/lib/milpa-preflight.sh"
milpa_preflight

seconds="${1:-${SELLO_FUZZ_SECONDS:-60}}"
img=ghcr.io/coreyleavitt/nim:2.2.10

podman run --rm \
  -v "$PWD:/workspace" \
  -v "$HOME/.cache/milpa:/.cache/milpa" \
  -v "$HOME/.cache/milpa:$HOME/.cache/milpa" \
  -w /workspace \
  -e "SELLO_FUZZ_SECONDS=$seconds" \
  "$img" \
  bash -c '
    set -euo pipefail

    # Stage 1: the vendored proptest_cov.c runtime, compiled WITHOUT the
    # sancov flag (it would otherwise instrument its own callback and
    # recurse into a crash -- USAGE.md is explicit about this). The gcc
    # backend needs PROPTEST_COV_GCC defined on the runtime translation
    # unit to match the trace-pc wire format the target side emits.
    mkdir -p build
    gcc -DPROPTEST_COV_GCC -fno-pie -c _deps/proptest/src/proptest/proptest_cov.c -o build/proptest_cov.o

    # Stage 2: the instrumented external target. `-fno-pie`/`-no-pie` pins
    # the load address (gccs PC-hash backend hashes absolute return
    # addresses, so ASLR would break determinism across runs otherwise).
    nim c --outdir:build \
          --passC:"-fsanitize-coverage=trace-pc -fno-pie" \
          --passL:"-no-pie build/proptest_cov.o" \
          -d:release tests/fuzz/fuzz_external_target.nim

    # Stage 3: the plain (uninstrumented) driver, which spawns
    # build/fuzz_external_target once per generated input via
    # proptests externalTarget/fuzz.
    nim c --outdir:build -d:release -r tests/fuzz/fuzz_main.nim
  '
