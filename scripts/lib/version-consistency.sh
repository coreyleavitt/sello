#!/usr/bin/env bash
# scripts/lib/version-consistency.sh -- RFC-005 slice 30 deliverable (b):
# a standalone, host-runnable check of the release workflow's
# version-consistency clause alone -- `sello.nimble`'s version ==
# `CHANGELOG.md`'s `## [x.y.z]` heading == the tag name == `milpa.kdl`'s
# version field. Exposed as its own small script (rather than folding
# entirely into scripts/release-gate.sh) so a maintainer can sanity-check
# "did I bump every copy of the version number" the moment before tagging,
# with no network/gh dependency at all -- unlike every other release-gate
# clause, this one is pure local file comparison.
#
# Shares its real parsing/comparison logic with scripts/release-gate.sh
# (via scripts/lib/release_gate.py's `--version-only` mode) rather than a
# second hand-typed copy -- one audited implementation of "what does
# 'the version' mean" for this project.
#
# Usage:
#   scripts/lib/version-consistency.sh <tag>
#
# <tag> is a NAME, not necessarily an existing git ref -- this check reads
# only sello.nimble/CHANGELOG.md/milpa.kdl plus the tag string itself, so
# it can be run against a tag you have not created yet (e.g. to confirm
# `v0.5.0` would pass before running `git tag`).
set -euo pipefail
cd "$(dirname "$0")/../.."

if ! command -v python3 >/dev/null 2>&1; then
  echo "version-consistency: python3 not found on PATH." >&2
  exit 1
fi

if [[ $# -ne 1 ]]; then
  echo "usage: scripts/lib/version-consistency.sh <tag>" >&2
  exit 2
fi

exec python3 scripts/lib/release_gate.py "$1" --version-only
