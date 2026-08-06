#!/usr/bin/env bash
# Coverage-guided fuzzing campaign (RFC-001 review finding 12) over
# tests/fuzz/fuzz_main.nim, using COREY'S proptest library's in-process
# `fuzzWith` (IR mutation mode). See fuzz_main.nim / fuzz_common.nim's
# module doc comments for the full scope statement: attacker-controlled-
# input surface ONLY (ed25519.pointDecode, ed25519.verify, x25519's peer
# public u-coordinate) -- never the secret-scalar signing path, which is
# dudect's job (scripts/ct.sh), not a mutation fuzzer's.
#
# Deliberately separate from scripts/test.sh (like scripts/ct.sh): this is
# an open-ended campaign, not a fixed-assertion pass/fail suite, and its
# default bound (minutes) is much longer than the rest of the suite.
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
# docs/rfc-001-signing.handoff.md), so the plain base image suffices.
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
  bash -c 'nim c --outdir:build -r tests/fuzz/fuzz_main.nim'
