#!/usr/bin/env bash
# scripts/ci-setup.sh — writes the zero-dependency nim.cfg (`--path:"src"`)
# on a bare checkout (RFC-005 slice 1). nim.cfg is gitignored and normally
# emitted wholesale by `milpa fetch` (see CLAUDE.md's "Building & testing"
# section); the core CI job needs no milpa at all, since sello resolves
# zero dependencies as of RFC-006 -- this script exists so that job never
# has to install or invoke milpa just to make `import sello` resolve.
#
# Idempotent: does nothing if nim.cfg already exists -- never clobbers a
# milpa-generated nim.cfg (e.g. one carrying proptest/z3/softlink --path
# lines from a local `milpa fetch --features proptest`), and a second
# invocation on an already-set-up checkout is a silent no-op rather than
# a rewrite.
#
# Usage:  scripts/ci-setup.sh
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -f nim.cfg ]; then
  echo "ci-setup: nim.cfg already present -- leaving it as-is" >&2
  exit 0
fi

printf '%s\n' '--path:"src"' > nim.cfg
echo "ci-setup: wrote zero-dependency nim.cfg (--path:\"src\")" >&2
