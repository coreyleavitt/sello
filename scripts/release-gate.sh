#!/usr/bin/env bash
# scripts/release-gate.sh -- RFC-005 slice 30: the "release-gate" job's
# one script invocation, and the host-runnable entry point a maintainer
# uses before cutting a real release. Evaluates all four release clauses
# from docs/rfc-005-validation-infra.md's release-workflow paragraph
# against a tag that already exists locally (fetch it first: `git fetch
# --tags`), printing a per-clause table and exiting nonzero if any clause
# fails.
#
# The real clause logic lives in scripts/lib/release_gate.py (a python3
# script, not a bash reimplementation -- the same "structured text/JSON,
# not YAML" precedent scripts/validation-map-check.sh's own header
# documents for tests/api/api_surface_gen.py and
# scripts/lib/validation_map_check.py). This script is the thin,
# gates.txt-manifest-shaped entry point, needing no container/podman/nim
# toolchain at all -- it is pure git + `gh api` + python3, exactly like
# scripts/ruleset-sync-check.sh and scripts/gates-manifest-check.sh.
#
# Usage:
#   scripts/release-gate.sh <tag> [--stale-accept] [--timing-fixture SHA,DATE]
#
# --stale-accept: accept a STALE (absent or freshness-window-exceeded)
#   timing-tier verdict, PROVIDED the release-notes body (CHANGELOG.md's
#   section for the tag's version) carries the literal notation
#   `timing-evidence: stale`. Never overrides a HARD FAIL (non-ancestor
#   timing SHA, a src/sello/ diff since the timing SHA, or a missing
#   docs/ct-results.md citation) -- see release_gate.py's own module doc
#   comment for the full clause-by-clause design.
#
# --timing-fixture SHA,DATE: a documented, off-by-default test hook that
#   substitutes a literal (SHA, ISO date) pair for the real timing.yml/
#   evidence-branch query -- used ONLY to red-demo clause (iii)'s
#   ancestry/window/diff logic before RFC-005 slices 28/29 (the real
#   timing tier + evidence branch) exist. Never used for a real release.
#
# Requires: git, python3, gh (authenticated -- reads are unauthenticated-
# capable on this public repo, but gh must still be installed and able to
# run `gh api`).
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v python3 >/dev/null 2>&1; then
  echo "release-gate: python3 not found on PATH." >&2
  exit 1
fi
if ! command -v gh >/dev/null 2>&1; then
  echo "release-gate: gh not found on PATH." >&2
  exit 1
fi

if [[ $# -lt 1 ]]; then
  echo "usage: scripts/release-gate.sh <tag> [--stale-accept] [--timing-fixture SHA,DATE]" >&2
  exit 2
fi

exec python3 scripts/lib/release_gate.py "$@"
