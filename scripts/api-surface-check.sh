#!/usr/bin/env bash
# scripts/api-surface-check.sh -- RFC-005 slice 18: the "api-surface" /
# "api-surface-libsodium" CI checks. Regenerates the facade-surface dump
# for the given config (via scripts/api-surface-dump.sh) and diffs it
# against the committed baseline at
# tests/api-surface/expected/<config>.txt, using the shared
# scripts/lib/baseline.sh idiom (RFC-005 Part B's regenerable-baseline
# contract -- see that file's own header for the full shape).
#
# A generated public-symbol dump of the facade diffed against a committed
# baseline is this whole gate's purpose (RFC-005 Part B, A8): `PublicKey`/
# `keypair`/etc. going missing is a regression test_facade.nim already
# catches (it pins REACHABILITY), but nothing before this slice caught an
# ACCIDENTAL ADD -- and for the two deliberately-unexported symbols
# (`ristretto.ristrettoUnchecked`, `scalar.SecretScalar`) an accidental
# add would be a security event, not just a semver one (CLAUDE.md's own
# framing, reproduced here). This check is what makes that a red build
# instead of a hoped-for code-review catch.
#
# Usage:
#   scripts/api-surface-check.sh <plain|selloLibsodium>              # check (CI's own mode)
#   scripts/api-surface-check.sh <plain|selloLibsodium> --update      # regenerate the committed baseline (local only -- see scripts/lib/baseline.sh; hard-fails under $CI)
#   SELLO_IN_CONTAINER=1 scripts/api-surface-check.sh <plain|selloLibsodium> [--update]
#     # already inside the pinned image (CI, or scripts/merge-gate.sh --update-baselines
#     # calling this from a maintainer's own already-in-container shell)
#
# Dual-mode (same convention as every other scripts/*.sh in this project):
# with no SELLO_IN_CONTAINER set, this script wraps ITSELF in the pinned
# podman image and recurses with SELLO_IN_CONTAINER=1 exported, so
# scripts/api-surface-dump.sh's own call (below) runs in-container without
# a second, nested podman wrap.
set -euo pipefail
cd "$(dirname "$0")/.."

config="${1:-}"
if [[ "$config" != "plain" && "$config" != "selloLibsodium" ]]; then
  echo "api-surface-check.sh: usage: scripts/api-surface-check.sh <plain|selloLibsodium> [--update]" >&2
  exit 2
fi
shift
update_mode=0
if [[ "${1:-}" == "--update" ]]; then
  update_mode=1
  shift
fi

if [ "${SELLO_IN_CONTAINER:-}" != "1" ]; then
  # Wrap the whole in-container body below in the pinned image and
  # recurse -- byte-identical logic to CI, not a parallel host-side
  # reimplementation (scripts/ci-property.sh's own precedent).
  source "$(dirname "$0")/lib/milpa-preflight.sh"
  milpa_preflight

  img=ghcr.io/coreyleavitt/nim:2.2.10
  extra_arg=""
  [[ "$update_mode" -eq 1 ]] && extra_arg=" --update"
  podman run --rm \
    -e CI \
    -v "$PWD:/workspace" \
    -v "$HOME/.cache/milpa:/.cache/milpa" \
    -v "$HOME/.cache/milpa:$HOME/.cache/milpa" \
    -w /workspace \
    "$img" \
    bash -c "SELLO_IN_CONTAINER=1 scripts/api-surface-check.sh $config$extra_arg"
  exit $?
fi

source "$(dirname "$0")/lib/baseline.sh"

pin_file="tests/api-surface/expected/${config}.txt"
generator_desc="tests/api/api_surface_gen.py via scripts/api-surface-dump.sh ($config config; nim jsondoc-based facade surface dump -- see that Python module's own doc comment for the mechanism and its recorded blind spots)"
regen_cmd_str="scripts/api-surface-check.sh $config --update"

if [[ "$update_mode" -eq 1 ]]; then
  baseline_update "$pin_file" "$generator_desc" "$regen_cmd_str" -- \
    env SELLO_IN_CONTAINER=1 scripts/api-surface-dump.sh "$config"
else
  baseline_check "$pin_file" "$generator_desc" "$regen_cmd_str" -- \
    env SELLO_IN_CONTAINER=1 scripts/api-surface-dump.sh "$config"
fi
