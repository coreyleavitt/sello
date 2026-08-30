#!/usr/bin/env bash
# scripts/secret-target-register-check.sh -- RFC-005 slice 20 (A7): the
# "secret-target-register" CI check. Runs
# tests/registers/secret_target_check.py's two-rule completeness check
# (every exported proc accepting a secret-role type, and every exported
# secret-import constructor, has a tests/registers/secret_targets.nim
# entry) against both build configs (plain, selloLibsodium).
#
# Modeled directly on scripts/api-surface-dump.sh's dual-mode shape: the
# checker only needs `nim jsondoc` (via the reused
# tests/api/api_surface_gen.py machinery) and python3, both already in
# the base ghcr.io/coreyleavitt/nim image -- no libsodium-devel needed
# even for the selloLibsodium config, for the identical reason
# api-surface-check.sh's own header comment records (`nim jsondoc` is a
# Nim-semantic-pass-only tool that never invokes a C compiler/linker, so
# an FFI `{.importc, header.}` declaration resolves as a plain name
# binding with no header present). Unlike api-surface-check.sh, this is
# not a baseline-diff gate (there is no generated dump to pin -- the
# register is the hand-authored, reviewed artifact, and this check only
# asserts it stays COMPLETE against the live facade) so it does not
# source scripts/lib/baseline.sh.
#
# Usage:
#   scripts/secret-target-register-check.sh
#   SELLO_IN_CONTAINER=1 scripts/secret-target-register-check.sh
#     # already inside the pinned image (CI)
set -euo pipefail
cd "$(dirname "$0")/.."

cmd="set -e"
cmd+=$'\n'"scripts/ci-setup.sh"
cmd+=$'\n'"python3 tests/registers/secret_target_check.py"

if [ "${SELLO_IN_CONTAINER:-}" = "1" ]; then
  bash -c "$cmd"
else
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
