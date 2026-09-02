#!/usr/bin/env bash
# Coverage-guided fuzzing campaign (RFC-001 review finding 12, reworked by
# RFC-002 slice 3 into an EXTERNAL SanitizerCoverage target) over
# tests/fuzz/fuzz_main.nim / fuzz_external_target.nim. See those files'
# module doc comments for the full scope statement: attacker-controlled-
# input surface ONLY (ed25519.pointDecode, ed25519.verify, x25519's peer
# public u-coordinate, and -- RFC-004 slice 8a -- ristretto.ristrettoDecode)
# -- never the secret-scalar signing path, which is dudect's job
# (scripts/ct.sh), not a mutation fuzzer's.
#
# RFC-002 slice 3: the harness used to drive nelli's in-process
# `fuzzWith` against `{.cover.}`-instrumented wrapper procs -- a 2-edge
# coverage universe (decode ok/reject, verify accept/reject, x25519 some/
# none), saturated within the first few iterations. It now drives
# nelli's `externalTarget`/`fuzz` against a SEPARATE binary
# (`build/fuzz_external_target`, compiled from `fuzz_external_target.nim`)
# built with real SanitizerCoverage instrumentation
# (`-fsanitize-coverage=trace-pc -fno-pie`, gcc's PC-hash bitmap backend)
# and linked against nelli's vendored, UNFLAGGED `nelli_cov.c`
# runtime -- see `_deps/nelli/docs/fuzz/USAGE.md`'s "Instrumentation
# recipe (normative)" Nim row for the exact recipe this script follows.
# Audited sello sources stay pragma-free: no {.cover.} markup or other
# fuzzing-specific annotation is added to `src/sello/*` -- the harness's
# own external target file (fuzz_external_target.nim) is the only source
# file written for this campaign. That said, the sancov instrumentation
# itself is NOT scoped to that one file: `--passC` is a Nim compiler
# GLOBAL flag, applied to every C translation unit the build emits,
# including the ones generated from `src/sello/*` and pulled in
# transitively by fuzz_external_target.nim's imports. So sello's own
# compiled object code IS instrumented at the C level, alongside the
# harness's -- deliberately, since that instrumentation is exactly what
# produces the coverage-edge signal (`MinEdgesGate` below) guiding the
# mutator through sello's own decode/verify branches. "Pragma-free" is a
# source-level statement about sello's .nim files, not a claim that
# sello's compiled code is excluded from instrumentation.
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
#   scripts/fuzz.sh                    # default: 60s/target x 4 = ~4 min total
#   scripts/fuzz.sh 15                 # 15s/target x 4 = ~1 min total (smoke-sized)
#   SELLO_FUZZ_SECONDS=15 scripts/fuzz.sh   # same, via env (arg wins if both given)
#   scripts/fuzz.sh --build-only       # compile stages 1-3 only; run NEITHER
#                                         binary (RFC-005 slice 16, below)
#   SELLO_IN_CONTAINER=1 scripts/fuzz.sh [...]   # already inside the pinned
#                                                   image (see "Dual-mode" below)
#
# --build-only (RFC-005 slice 16, the build-smoke check): builds the
# nelli_cov.o runtime object, the SanitizerCoverage-instrumented
# external target (stage 1+2, unchanged), AND compiles (but does not run)
# the plain driver, `fuzz_main.nim` (stage 3, `-r` dropped). This is
# exactly Part B's "compiles the fuzz external target + driver" half of
# build-smoke's definition. It deliberately stops at compile for the
# driver: `scripts/build-smoke.sh` performs its own single deterministic
# input through the already-built `build/fuzz_external_target` directly
# (piped via stdin, no nelli campaign loop involved) rather than
# invoking this script's normal stage-3 campaign run -- `MinEdgesGate`
# below is calibrated against real multi-second campaigns (observed
# 291-350 edges at 20s/target) and would make a required merge-gate check
# flaky at a deliberately minimal smoke budget with no iteration-count
# knob to pin it down exactly. A direct single-input run is a strictly
# stronger proof that the compiled, linked, instrumented binary actually
# executes end-to-end than watching a campaign attempt a possibly-too-
# short budget. Ignores any positional seconds argument / SELLO_FUZZ_SECONDS
# when set.
#
# Dual-mode (RFC-005 slice 16 retrofit -- this script previously had only
# one mode, always wrapping itself in podman; scripts/test.sh,
# scripts/check-readme.sh, and scripts/ci-property.sh already had this
# split from earlier slices). With no SELLO_IN_CONTAINER set (a
# maintainer's host), this script wraps itself in the pinned podman image
# exactly as it always has. Under SELLO_IN_CONTAINER=1 (CI's own
# `container:` field, or a caller -- scripts/build-smoke.sh -- already
# running inside one), it runs the identical commands directly with no
# podman wrapper and no host milpa-lock preflight, mirroring every other
# dual-mode script's own rationale: there is no host to preflight-check
# from inside a container CI already runs in, and nesting a second podman
# invocation inside a CI container job would need a podman binary (and
# usually privilege) the pinned Nim image does not carry. One `cmd`
# string builds "what actually runs" exactly once; both entrypoints hand
# it to `bash -c` (locally or via `podman run`).
#
# Needs only the base Nim image + the optional nelli milpa dep --
# `milpa fetch --features nelli` (see scripts/test.sh's header comment
# for the full optional-dep rationale). No z3/libsodium linkage: fuzz.nim
# never imports nelli/symex (confirmed in the B4a summary,
# docs/rfc-001-signing.handoff.md), so the plain base image suffices --
# gcc (for the sancov compile) already ships in that image alongside Nim's
# own C backend.
#
# Mounts: the project + the milpa CAS (at both the canonical path and its
# host-absolute path, so milpa's absolute dep symlinks under _deps/
# resolve in-container) -- same pattern as scripts/test.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

build_only=0
if [[ "${1:-}" == "--build-only" ]]; then
  build_only=1
  shift
fi

seconds="${1:-${SELLO_FUZZ_SECONDS:-60}}"
img=ghcr.io/coreyleavitt/nim:2.2.10

# Stage 1+2 (unchanged in either mode): the vendored nelli_cov.c
# runtime, compiled WITHOUT the sancov flag (it would otherwise
# instrument its own callback and recurse into a crash -- USAGE.md is
# explicit about this), then the instrumented external target itself.
# `-fno-pie`/`-no-pie` pins the load address (gcc's PC-hash backend
# hashes absolute return addresses, so ASLR would break determinism
# across runs otherwise).
#
# nelli migration finding (doc drift, not a build defect once found):
# nelli_cov.c now unconditionally `extern`s the shared-memory transport's
# `pt_shm_*`/`pt_cmplog_*`/`pt_dumped` symbols (RFC-fuzzer-nextgen E2b,
# `nelli_shm.c`) -- confirmed by linking nelli_cov.c alone, which fails
# with undefined references to exactly those symbols. `nelli_cov.c`'s own
# header comment is explicit about this ("a real external sancov target
# must link BOTH this file and nelli_shm.c"), but docs/fuzz/USAGE.md's
# "Instrumentation recipe (normative)" Nim row still shows only
# nelli_cov.c -- the same class of doc/code drift the 0.7.0 CHANGELOG
# records INTERFACE.md having had (fixed there by making it
# test-checked). nelli_shm.c compiles the same unflagged way and needs no
# NELLI_COV_GCC define of its own (it carries no sancov-specific code --
# see its own header comment on why it was split out of nelli_cov.c).
cmd='set -euo pipefail
mkdir -p build
gcc -DNELLI_COV_GCC -fno-pie -c _deps/nelli/src/nelli/nelli_cov.c -o build/nelli_cov.o
gcc -fno-pie -c _deps/nelli/src/nelli/nelli_shm.c -o build/nelli_shm.o
nim c --outdir:build \
      --passC:"-fsanitize-coverage=trace-pc -fno-pie" \
      --passL:"-no-pie build/nelli_cov.o build/nelli_shm.o" \
      -d:release tests/fuzz/fuzz_external_target.nim
'
if [[ "$build_only" -eq 1 ]]; then
  cmd+='echo "fuzz.sh --build-only: compiling driver (fuzz_main.nim), not running it"
nim c --outdir:build -d:release tests/fuzz/fuzz_main.nim
echo "fuzz.sh --build-only: build complete -- build/fuzz_external_target and build/fuzz_main both compiled, neither run."
'
else
  # Stage 3 (normal mode): the plain (uninstrumented) driver, which spawns
  # build/fuzz_external_target once per generated input via nelli's
  # externalTarget/fuzz.
  cmd+='nim c --outdir:build -d:release -r tests/fuzz/fuzz_main.nim
'
fi

if [ "${SELLO_IN_CONTAINER:-}" = "1" ]; then
  SELLO_FUZZ_SECONDS="$seconds" bash -c "$cmd"
else
  # Lockfile-conformance preflight (RFC-001 ledger finding 30) -- see
  # scripts/lib/milpa-preflight.sh for exactly what this does and does not
  # treat as fatal.
  source "$(dirname "$0")/lib/milpa-preflight.sh"
  milpa_preflight

  podman run --rm \
    -v "$PWD:/workspace" \
    -v "$HOME/.cache/milpa:/.cache/milpa" \
    -v "$HOME/.cache/milpa:$HOME/.cache/milpa" \
    -w /workspace \
    -e "SELLO_FUZZ_SECONDS=$seconds" \
    "$img" \
    bash -c "$cmd"
fi
