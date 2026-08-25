#!/usr/bin/env bash
# scripts/validation-map-check.sh -- RFC-005 slice 31: the "validation-map"
# CI check. Parses README.md's Validation section (the hand-curated table
# mapping every CLAUDE.md "validation bar" claim to its enforcing
# mechanism, RFC-005 Part B's evidence-story paragraph) and asserts, per
# row category, that the mechanism it names is real:
#   required-check rows -- the named job exists in
#     .github/workflows/merge-gate.yml AND scripts/lib/gates.txt (the
#     ruleset's required-check set is GENERATED from gates.txt at apply
#     time, so gates.txt membership is the checkable proxy for "this is
#     actually enforced on main" -- re-querying the live GitHub ruleset
#     here too would duplicate scripts/ruleset-sync-check.sh's own job
#     rather than add coverage).
#   nightly rows -- the named job exists in .github/workflows/nightly.yml.
#   manual-ritual rows -- the declared freshness canary is real: a
#     committed file (existence-checked), an entry in the committed
#     scripts/lib/validation-map-pending.txt allowlist ("pending slice
#     N"), or one of a small, hardcoded no-canary-by-design set (rituals
#     the RFC never demanded a freshness canary for at all).
#
# Also checks (round-2 corrections (ii)/(iii) to the evidence-story
# paragraph, plus this slice's own (b)/(c)/(d) scope): every README
# badge URL carries `?branch=main`; the toolchain-canary workflow has NO
# badge anywhere in README.md; the platform-support claim's named CI legs
# exist in the gates manifest and workflow, plus the WASM
# unsupported-for-secrets disclosure is present; the CT compiler-scope
# claim's gcc/clang versions and image digest match
# scripts/lib/image-pins.txt's committed production toolchain-versions
# record (the pin file is the source of truth for those numbers, not the
# README prose).
#
# The actual parsing/assertions live in
# scripts/lib/validation_map_check.py (a python3 script, not a
# reimplementation in bash -- markdown-table cell splitting is unpleasant
# in pure bash and this project already leans on python3 for exactly this
# class of "structured text, not YAML, not JSON" parsing job, e.g.
# tests/api/api_surface_gen.py and scripts/lib/baseline.sh's own difflib
# fallback). This script is the thin, gates.txt-manifest-shaped entry
# point.
#
# Container vs. plain runner: pure text scan over committed files -- no
# Nim/podman/milpa needed, so this runs on a plain `ubuntu-latest` runner
# in CI (see merge-gate.yml's own job comment; same rationale as
# gates-manifest-sync/ruleset-sync/policy-lint). Still exactly one
# scripts/ invocation, host-runnable with no container wrap (the
# gates.txt "plain, host-runnable command" convention).
#
# Usage: scripts/validation-map-check.sh
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v python3 >/dev/null 2>&1; then
  echo "validation-map-check: python3 not found on PATH." >&2
  exit 1
fi

exec python3 scripts/lib/validation_map_check.py
