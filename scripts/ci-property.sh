#!/usr/bin/env bash
# scripts/ci-property.sh — RFC-005 slice 2: the property-suite CI job's
# one script invocation (Part B's build-path invariant: every job's run
# step is exactly one scripts/ invocation). In CI this runs inside the
# digest-pinned Nim toolchain image (the workflow's own `container:`),
# under SELLO_IN_CONTAINER=1.
#
# RFC-005 slice 3 retrofit: gained the same SELLO_IN_CONTAINER dual-mode
# split scripts/test.sh and scripts/check-readme.sh already had, so this
# script can appear as a literal, host-runnable entry in
# scripts/lib/gates.txt (merge-gate.sh's manifest) instead of needing
# merge-gate.sh-side podman-wrapping logic of its own. Host mode (no
# SELLO_IN_CONTAINER set) does NOT reimplement the in-container logic
# below against host-side milpa state -- that would test a different
# thing from what CI's required check actually runs. Instead it wraps
# THIS SCRIPT, unmodified, inside the pinned image and recurses with
# SELLO_IN_CONTAINER=1 -- byte-identical logic to the CI job, including
# building milpa fresh from the pinned commit every time (deliberate: the
# whole point of this job, locally or in CI, is exercising that exact
# pin). See the bottom of this file for the host-mode branch.
#
# Three things the in-container body does that the plain core unit job
# (scripts/ci-setup.sh + scripts/test.sh) does not need:
#
#   1. Builds milpa from the commit pinned in scripts/lib/milpa-pin.txt
#      (scripts/lib/milpa-install.sh) -- the core unit job needs no milpa
#      at all (sello resolves zero dependencies as of RFC-006), but the
#      property suites need the optional nelli dependency, which only
#      milpa can fetch.
#   2. Runs `milpa fetch --features nelli --locked`. `--locked` is
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
#   3. Asserts the nelli SKIPPED banner is ABSENT from the test run's
#      output. scripts/test.sh silently prints
#      "SKIPPED (nelli not fetched -- ...)" for each test_properties_*
#      file when _deps/nelli is missing (RFC-003 slice 2 item 4) --
#      exactly the right behavior for a bare `scripts/test.sh` invocation
#      on a fresh clone, and exactly the wrong thing to happen silently in
#      THIS job, whose entire purpose is running those files for real. A
#      silent skip here must be a red check, not a quietly weaker suite
#      (RFC-005 Part B).
#
# Usage:  scripts/ci-property.sh
#         SELLO_IN_CONTAINER=1 scripts/ci-property.sh   # already inside
#                                                          # the pinned image (CI)
#         scripts/ci-property.sh --cc clang               # clang-backend leg
#                                                          # (RFC-005 slice 8)
#
# --cc <name> (RFC-005 slice 8): forwarded verbatim to scripts/test.sh
# below, in BOTH the in-container body (the "$@" appended to the
# `scripts/test.sh` call) and the host-mode recursion (appended to the
# recursive `SELLO_IN_CONTAINER=1 scripts/ci-property.sh` invocation) --
# this script does no parsing or validation of its own, since
# scripts/test.sh already owns --cc's meaning, error-checking, and its
# platform-identity canary; this script is purely a pass-through so
# `property-linux-amd64-clang` in scripts/lib/gates.txt/merge-gate.yml can
# read as literally `scripts/ci-property.sh --cc clang`, matching
# `unit-linux-amd64-clang`'s `scripts/test.sh --cc clang` sibling.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "${SELLO_IN_CONTAINER:-}" = "1" ]; then
  source "$(dirname "$0")/lib/milpa-install.sh"
  install_milpa "build/milpa-venv"

  echo "ci-property: fetching nelli + transitives (--locked: asserts against the committed milpa.lock)" >&2
  "$MILPA_BIN" fetch --features nelli --locked

  echo "ci-property: running the unit+property suite" >&2
  log="build/ci-property-test.log"
  mkdir -p "$(dirname "$log")"
  # Propagate test.sh's own exit status past the `tee` pipeline (a bare
  # `cmd | tee log` reports tee's exit status under `set -o pipefail`,
  # which is what we want here -- pipefail is already on via set -euo
  # pipefail above, so this is exactly right rather than incidental).
  # "$@" forwards this script's own arguments (e.g. --cc clang) straight
  # through to scripts/test.sh, unmodified (RFC-005 slice 8).
  SELLO_IN_CONTAINER=1 scripts/test.sh "$@" 2>&1 | tee "$log"

  if grep -q 'SKIPPED (nelli not fetched' "$log"; then
    echo "" >&2
    echo "ci-property: FAIL -- the nelli SKIPPED banner appears in this run's log." >&2
    echo "ci-property: this job exists to run the property suites for real; a skip here" >&2
    echo "ci-property: means _deps/nelli did not end up populated despite the fetch" >&2
    echo "ci-property: step above reporting success -- investigate, do not silence." >&2
    exit 1
  fi

  echo "ci-property: nelli SKIPPED banner absent, as required -- property suites ran for real." >&2
else
  # Host mode (RFC-005 slice 3): not already inside the pinned image --
  # wrap this exact script inside it via podman and recurse with
  # SELLO_IN_CONTAINER=1, mirroring CI's own `container:` field + `run:
  # scripts/ci-property.sh` step exactly, rather than a parallel
  # host-side reimplementation that could drift from what the required
  # check actually does.
  #
  # Lockfile-conformance preflight (RFC-001 ledger finding 30), same
  # courtesy staleness check scripts/test.sh's own host branch runs
  # before its podman invocation -- host-only, since _deps/milpa.lock are
  # host-side state, meaningless to check from inside the container this
  # preflight gates entry to. Note this job's OWN milpa/nelli fetch
  # (inside the container, from the commit pinned in
  # scripts/lib/milpa-pin.txt) is independent of and does not consult
  # this host-side state -- it is deliberately a from-scratch mirror of
  # the CI job, not a shortcut through whatever the host already fetched.
  source "$(dirname "$0")/lib/milpa-preflight.sh"
  milpa_preflight

  # Forward this script's own arguments (e.g. --cc clang, RFC-005 slice 8)
  # into the recursive in-container invocation, each shell-quoted via
  # printf %q so the reconstructed command line is byte-identical to "$@"
  # regardless of its contents -- same recursion shape as before this
  # slice, just no longer argument-less.
  inner_cmd="SELLO_IN_CONTAINER=1 scripts/ci-property.sh"
  for a in "$@"; do
    inner_cmd+=" $(printf '%q' "$a")"
  done

  img=ghcr.io/coreyleavitt/nim:2.2.10
  podman run --rm \
    -v "$PWD:/workspace" \
    -v "$HOME/.cache/milpa:/.cache/milpa" \
    -v "$HOME/.cache/milpa:$HOME/.cache/milpa" \
    -w /workspace \
    "$img" \
    bash -c "$inner_cmd"
fi
