#!/usr/bin/env bash
# Run tests/ct's dudect-style constant-time timing harness. Replaces the
# old `nimble ct` task. Deliberately separate from scripts/test.sh -- this
# is statistical and environment-sensitive (t-statistics, not a fixed
# pass/fail vector), takes much longer (>= 1e6 samples/class per target),
# and its honest interpretation belongs in docs/ct-results.md, not the
# green/red signal of the main suite.
#
# Usage:  scripts/ct.sh
#
# Mounts: the project + the milpa CAS (at both the canonical path and its
# host-absolute path, so milpa's absolute dep symlinks under _deps/
# resolve in-container). Prerequisite: `milpa fetch` has been run on the
# host at least once (see scripts/test.sh).
set -euo pipefail
cd "$(dirname "$0")/.."

# Lockfile-conformance preflight (RFC-001 ledger finding 30) -- see
# scripts/lib/milpa-preflight.sh for exactly what this does and does not
# treat as fatal.
source "$(dirname "$0")/lib/milpa-preflight.sh"
milpa_preflight

img=ghcr.io/coreyleavitt/nim:2.2.10

podman run --rm \
  -v "$PWD:/workspace" \
  -v "$HOME/.cache/milpa:/.cache/milpa" \
  -v "$HOME/.cache/milpa:$HOME/.cache/milpa" \
  -w /workspace \
  "$img" \
  bash -c '
    set -e
    nim c -d:release --outdir:build tests/ct/ct_main.nim
    bin=build/ct_main
    if command -v taskset >/dev/null 2>&1; then
      echo "pinning to core 0 via taskset"
      taskset -c 0 "$bin"
    else
      echo "taskset not found -- running WITHOUT CPU pinning (see docs/ct-results.md)"
      "$bin"
    fi
  '
