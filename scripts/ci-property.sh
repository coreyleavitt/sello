#!/usr/bin/env bash
# scripts/ci-property.sh — RFC-005 slice 2: the property-suite CI job's
# one script invocation (Part B's build-path invariant: every job's run
# step is exactly one scripts/ invocation). Runs inside the digest-pinned
# Nim toolchain image (the workflow's own `container:`), so this assumes
# SELLO_IN_CONTAINER semantics throughout -- there is no host to
# preflight-check and no podman wrapper to skip (see scripts/test.sh's own
# header comment on the same split).
#
# Three things this script does that the plain core unit job
# (scripts/ci-setup.sh + scripts/test.sh) does not need:
#
#   1. Builds milpa from the commit pinned in scripts/lib/milpa-pin.txt
#      (scripts/lib/milpa-install.sh) -- the core unit job needs no milpa
#      at all (sello resolves zero dependencies as of RFC-006), but the
#      property suites need the optional proptest dependency, which only
#      milpa can fetch.
#   2. Runs `milpa fetch --features proptest --locked`. `--locked` is
#      milpa's own built-in assertion that the resolve matches the
#      COMMITTED milpa.lock exactly (identity + provenance, i.e. the
#      dag-sha256 content identity as well as the git commit SHA) --
#      RFC-005 Part B's mandated "the property jobs' CI step asserts the
#      fetched commit equals the committed expected SHA (dag-sha256
#      identity where milpa exposes it)". This is the direct replacement
#      for `milpa verify`, which milpa 0.0.1 cannot run against a
#      non-default feature selection (see scripts/lib/milpa-preflight.sh's
#      own comment on the same limitation, on the host-preflight side of
#      the split). A tampered or drifted milpa.kdl/milpa.lock pair fails
#      loud here, before any test compiles.
#   3. Asserts the proptest SKIPPED banner is ABSENT from the test run's
#      output. scripts/test.sh silently prints
#      "SKIPPED (proptest not fetched -- ...)" for each test_properties_*
#      file when _deps/proptest is missing (RFC-003 slice 2 item 4) --
#      exactly the right behavior for a bare `scripts/test.sh` invocation
#      on a fresh clone, and exactly the wrong thing to happen silently in
#      THIS job, whose entire purpose is running those files for real. A
#      silent skip here must be a red check, not a quietly weaker suite
#      (RFC-005 Part B).
#
# Usage:  scripts/ci-property.sh
set -euo pipefail
cd "$(dirname "$0")/.."

source "$(dirname "$0")/lib/milpa-install.sh"
install_milpa "build/milpa-venv"

echo "ci-property: fetching proptest + transitives (--locked: asserts against the committed milpa.lock)" >&2
"$MILPA_BIN" fetch --features proptest --locked

echo "ci-property: running the unit+property suite" >&2
log="build/ci-property-test.log"
mkdir -p "$(dirname "$log")"
# Propagate test.sh's own exit status past the `tee` pipeline (a bare
# `cmd | tee log` reports tee's exit status under `set -o pipefail`,
# which is what we want here -- pipefail is already on via set -euo
# pipefail above, so this is exactly right rather than incidental).
SELLO_IN_CONTAINER=1 scripts/test.sh 2>&1 | tee "$log"

if grep -q 'SKIPPED (proptest not fetched' "$log"; then
  echo "" >&2
  echo "ci-property: FAIL -- the proptest SKIPPED banner appears in this run's log." >&2
  echo "ci-property: this job exists to run the property suites for real; a skip here" >&2
  echo "ci-property: means _deps/proptest did not end up populated despite the fetch" >&2
  echo "ci-property: step above reporting success -- investigate, do not silence." >&2
  exit 1
fi

echo "ci-property: proptest SKIPPED banner absent, as required -- property suites ran for real." >&2
