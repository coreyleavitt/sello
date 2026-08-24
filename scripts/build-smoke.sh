#!/usr/bin/env bash
# scripts/build-smoke.sh -- RFC-005 slice 16: the "build-smoke" CI check's
# one script invocation (Part B's build-path invariant: every job's run
# step is exactly one scripts/ invocation).
#
# Purpose (RFC-005 Part B, round-2 finding A5): three harnesses
# (tests/fuzz/, tests/ct/) that otherwise first compile at a maintainer's
# manual scripts/fuzz.sh / scripts/ct.sh invocation or a future nightly
# job -- discovered broken only THEN, "nights later" (the S07 class
# finding A5 names verbatim) -- get a merge-gate-required compile-and-
# minimal-run check instead, on every push:
#
#   1. Builds the SanitizerCoverage-instrumented fuzz external target
#      (real -fsanitize-coverage=trace-pc, real proptest_cov.c link --
#      not a stubbed-out compile) and compiles the plain driver
#      (fuzz_main.nim), via `scripts/fuzz.sh --build-only` (that flag's
#      own header comment in fuzz.sh has the full design). Runs ONE
#      deterministic input directly through the built target binary
#      (below) -- proving the compiled, linked, instrumented binary
#      actually executes end-to-end, not merely that it links.
#   2. Compiles tests/ct/ct_main.nim (-d:release, same flags as a real
#      run) via `scripts/ct.sh --build-only`. NEVER runs the dudect
#      timing battery -- see the loud log line below and ct.sh's own
#      --build-only header paragraph. This is deliberately the only
#      thing hosted CI ever does with this harness (RFC-005 Part B:
#      "hosted CI runs the dudect harness in compile-smoke mode only --
#      no verdict authority"); the real environment-sensitive
#      >= 1e6-samples/class battery stays a maintainer-run, manually
#      interpreted instrument (docs/ct-results.md), never a green/red CI
#      signal. RFC-005 Part B's own wording asks that this be "stated in
#      the workflow name" -- satisfied here in spirit via an explicit,
#      unmissable log line rather than a job-name qualifier, since this
#      one job's name ("build-smoke") already covers the fuzz target/
#      driver too, not only ct_main, and a rename to fit ct_main's own
#      caveat would misname the other two.
#
# SCOPE, stated honestly (this slice was taken deliberately OUT OF ORDER
# -- slices 10/14/15 remain blocked on a Corey-owned ghcr `write:packages`
# credential for the `sello-dev` image push; slice 16 needed only the
# always-available base `ghcr.io/coreyleavitt/nim` image, so it was pulled
# forward rather than blocking on that credential): the RFC's own
# phased sequencing (Part B's build-smoke paragraph: "extended in phase 3
# to the taint/disasm binaries") schedules the taint harness (slice 19)
# and disasm gate (slice 23) binaries for LATER slices -- neither exists
# in this repository yet (no `src/sello/private/taint_shim.c`, no
# `private/taint.nim`, no `tests/ct_disasm/`). This script covers exactly
# what exists today (the fuzz target/driver and ct_main) and says so in
# its own log output below; it is NOT a gap to silently backfill, and
# slices 19/23 are expected to extend this same script and job in place
# when they land, not fork a new one (RFC-005 Part B's build-path
# invariant: one scripts/ invocation per job, widened in place).
#
# Dual-mode (matching scripts/ci-property.sh's own standing convention):
# with no SELLO_IN_CONTAINER set (a maintainer's host), this script wraps
# ITSELF, unmodified, inside the pinned podman image and recurses with
# SELLO_IN_CONTAINER=1 -- byte-identical logic to the CI job, not a
# parallel host-side reimplementation that could drift from what the
# required check actually does. Under SELLO_IN_CONTAINER=1 (CI's own
# `container:` field), it runs the in-container body below directly.
#
# Design note -- build-sharing, not duplication (RFC-005 slice 16's own
# instruction to prefer a shared build path over hand-copying commands):
# this script does NOT re-type scripts/fuzz.sh's/scripts/ct.sh's own
# build commands (SanitizerCoverage flags, the proptest_cov.c link
# recipe, the `-d:release` compile line). Both of those scripts gained a
# `--build-only` flag plus the same SELLO_IN_CONTAINER dual-mode split
# this script has (see each script's own header comment for the full
# retrofit rationale) -- this script is a thin conductor over the two of
# them, one audited copy of each build recipe living exactly where it
# always has (the script a maintainer would run by hand for the real
# thing), never a second copy here to drift out of sync.
#
# The fuzz driver (fuzz_main.nim) imports proptest -- unlike ct_main.nim,
# which imports nothing beyond std/sello (see ct.sh's own --build-only
# header note) -- so this script needs the same milpa-install-then-fetch
# preamble scripts/ci-property.sh uses (scripts/lib/milpa-install.sh,
# `milpa fetch --features proptest --locked`) before calling
# `scripts/fuzz.sh --build-only`.
#
# Usage:  scripts/build-smoke.sh
#         SELLO_IN_CONTAINER=1 scripts/build-smoke.sh   # already inside
#                                                          # the pinned image
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "${SELLO_IN_CONTAINER:-}" = "1" ]; then
  source "$(dirname "$0")/lib/milpa-install.sh"
  install_milpa "build/milpa-venv"

  echo "build-smoke: fetching proptest + transitives (--locked: asserts against the committed milpa.lock)" >&2
  "$MILPA_BIN" fetch --features proptest --locked

  echo "=============================================================="
  echo "build-smoke: PHASE 1/3 -- fuzz external target (real SanitizerCoverage"
  echo "build-smoke: instrumentation) + driver: compile only, via"
  echo "build-smoke: scripts/fuzz.sh --build-only"
  echo "=============================================================="
  SELLO_IN_CONTAINER=1 scripts/fuzz.sh --build-only

  echo ""
  echo "=============================================================="
  echo "build-smoke: PHASE 2/3 -- one deterministic input through the built,"
  echo "build-smoke: instrumented target binary directly (not the proptest"
  echo "build-smoke: mutation campaign -- see scripts/fuzz.sh's --build-only"
  echo "build-smoke: header comment for why)"
  echo "=============================================================="
  target_bin="build/fuzz_external_target"
  if [[ ! -x "$target_bin" ]]; then
    echo "build-smoke: FAIL -- $target_bin not found after scripts/fuzz.sh --build-only." >&2
    exit 1
  fi
  # One real, known-valid input: mode byte 0x00 (pointDecode) followed by
  # RFC 8032 sec7.1 TEST 1's 32-byte public key -- the same tv1Pk constant
  # tests/fuzz/fuzz_common.nim's own pointDecodeSeeds() uses to seed the
  # real campaign's corpus. A genuine accepted point, not an arbitrary
  # byte string, so this run exercises handlePointDecode's full accept
  # path (the pointEncode identity-roundtrip doAssert included), not only
  # the trivial early-length-reject branch a random/empty input would hit.
  printf '\x00\xd7\x5a\x98\x01\x82\xb1\x0a\xb7\xd5\x4b\xfe\xd3\xc9\x64\x07\x3a\x0e\xe1\x72\xf3\xda\xa6\x23\x25\xaf\x02\x1a\x68\xf7\x07\x51\x1a' | "$target_bin"
  echo "build-smoke: one input ran through $target_bin cleanly (exit 0) -- the"
  echo "build-smoke: instrumented binary executes end-to-end, not merely compiles."

  echo ""
  echo "=============================================================="
  echo "build-smoke: PHASE 3/3 -- ct_main: compile only, via scripts/ct.sh --build-only"
  echo "=============================================================="
  SELLO_IN_CONTAINER=1 scripts/ct.sh --build-only

  echo ""
  echo "=============================================================="
  echo "build-smoke: OK."
  echo "build-smoke:   - fuzz external target + driver compiled; one real input"
  echo "build-smoke:     ran cleanly through the instrumented target binary."
  echo "build-smoke:   - ct_main compiled. COMPILE-SMOKE ONLY -- ct_main was NOT"
  echo "build-smoke:     run; no timing samples were collected; this check has NO"
  echo "build-smoke:     dudect verdict authority. The real timing battery runs"
  echo "build-smoke:     only via a maintainer's own plain 'scripts/ct.sh'."
  echo "build-smoke:   - SCOPE (taken out of order; see this script's own header"
  echo "build-smoke:     comment and CLAUDE.md): the taint (slice 19) and disasm"
  echo "build-smoke:     (slice 23) binaries do not exist in this repository yet"
  echo "build-smoke:     and are therefore NOT covered by this check -- those"
  echo "build-smoke:     slices extend this same script/job when they land."
  echo "=============================================================="
else
  # Lockfile-conformance preflight (RFC-001 ledger finding 30), same
  # courtesy staleness check every other dual-mode script's host branch
  # runs before its podman invocation. Host-only: _deps/milpa.lock are
  # host-side state, meaningless to check from inside the container this
  # preflight gates entry to. This job's OWN milpa/proptest fetch (inside
  # the container, from the commit pinned in scripts/lib/milpa-pin.txt) is
  # independent of and does not consult this host-side state -- it is
  # deliberately a from-scratch mirror of the CI job, matching
  # scripts/ci-property.sh's own precedent exactly.
  source "$(dirname "$0")/lib/milpa-preflight.sh"
  milpa_preflight

  img=ghcr.io/coreyleavitt/nim:2.2.10
  podman run --rm \
    -v "$PWD:/workspace" \
    -v "$HOME/.cache/milpa:/.cache/milpa" \
    -v "$HOME/.cache/milpa:$HOME/.cache/milpa" \
    -w /workspace \
    "$img" \
    bash -c "SELLO_IN_CONTAINER=1 scripts/build-smoke.sh"
fi
