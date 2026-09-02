#!/usr/bin/env bash
# scripts/api-surface-dump.sh -- RFC-005 slice 18 (API-surface gate, A8):
# the generator half. Prints a deterministic dump of sello's public
# facade surface (src/sello.nim's own `export` statements, resolved to
# full signatures) to stdout for the given build config. Config-
# parametric because the facade legitimately widens under
# `-d:selloLibsodium` (SodiumInitError, widened `{.raises.}` on the
# sign/keygen path) -- see CLAUDE.md's A8 entry and
# tests/api/api_surface_gen.py's own module doc comment for the full
# mechanism/blind-spots writeup (the verify-first spike's outcome).
#
# This script is a thin conductor over the real generator
# (tests/api/api_surface_gen.py, a `nim jsondoc`-driven Python driver --
# the "named work, not a stock tool" the RFC calls for; see that file's
# own module doc for why `nim jsondoc` and not `nim doc`/a compiled probe
# module) -- it does not reimplement any of that logic, only sets up the
# environment the generator needs (a zero-dependency nim.cfg) and the
# dual-mode container wrap every other scripts/*.sh in this project uses.
#
# Usage:
#   scripts/api-surface-dump.sh <plain|selloLibsodium>
#   SELLO_IN_CONTAINER=1 scripts/api-surface-dump.sh <plain|selloLibsodium>
#     # already inside the pinned image (CI, or scripts/api-surface-check.sh
#     # calling this from its own in-container body)
#
# No milpa/nelli needed (the generator only needs `nim jsondoc` and
# python3, both already in the base image) -- same "zero-dependency"
# category as scripts/check-readme.sh, hence the same minimal dual-mode
# shape (ci-setup.sh's nim.cfg, no milpa preflight chain).
set -euo pipefail
cd "$(dirname "$0")/.."

config="${1:-}"
if [[ "$config" != "plain" && "$config" != "selloLibsodium" ]]; then
  echo "api-surface-dump.sh: usage: scripts/api-surface-dump.sh <plain|selloLibsodium>" >&2
  exit 2
fi

cmd="set -e"
cmd+=$'\n'"scripts/ci-setup.sh"
cmd+=$'\n'"python3 tests/api/api_surface_gen.py $config"

if [ "${SELLO_IN_CONTAINER:-}" = "1" ]; then
  # Already inside the pinned toolchain image (CI, or a caller like
  # scripts/api-surface-check.sh that is itself already in-container) --
  # run directly, no podman wrapper, no host milpa-lock preflight (same
  # split as scripts/check-readme.sh; see that script's header comment).
  bash -c "$cmd"
else
  # Lockfile-conformance preflight (RFC-001 ledger finding 30), same
  # courtesy every other dual-mode script's host branch runs -- harmless
  # here too even though this gate needs no milpa dependency of its own
  # (this checkout may still carry nelli/z3/softlink from an earlier
  # `milpa fetch --features nelli`, and the preflight only checks
  # consistency, not that any particular dep is present).
  source "$(dirname "$0")/lib/milpa-preflight.sh"
  milpa_preflight

  img=ghcr.io/coreyleavitt/nim:2.2.10
  podman run --rm \
    -v "$PWD:/workspace" \
    -v "$HOME/.cache/milpa:/.cache/milpa" \
    -v "$HOME/.cache/milpa:$HOME/.cache/milpa" \
    -w /workspace \
    "$img" \
    bash -c "$cmd"
fi
