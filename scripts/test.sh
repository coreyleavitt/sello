#!/usr/bin/env bash
# Run sello's unit test suite (pure-Nim backend) inside the base Nim
# toolchain image. Replaces the old `nimble test` task now that milpa is
# the resolver. As of RFC-006 (in-house SHA-512 retired the nimcrypto
# dependency), a plain `milpa fetch` resolves ZERO dependencies for the
# core library -- _deps/ is empty unless proptest has been fetched (see
# below).
#
# Usage:  scripts/test.sh              # plain pure-Nim backend, default C compiler (gcc)
#         scripts/test.sh -d:release   # extra defines forwarded to each nim c
#         scripts/test.sh --cc clang   # compile with clang instead of gcc (RFC-005 slice 8)
#         scripts/test.sh --cc clang -d:release   # --cc composes with defines; must come first
#
# --cc <name> (RFC-005 slice 8, the clang-backend matrix leg): threads
# `--cc:<name>` into every `nim c` invocation below, so this ONE script
# serves both the unit-linux-amd64-gcc and unit-linux-amd64-clang required
# checks (scripts/lib/gates.txt: `scripts/test.sh` vs `scripts/test.sh
# --cc clang`) -- no forked clang-flavored script, per RFC-005 Part B's
# build-path invariant. Must be the FIRST argument if present (a simple
# `read -r` of "$1"/"$2", not a general getopts parser -- this script has
# exactly one optional flag with a value, and every other argument stays
# an opaque pass-through define as before). Left unset, `nim c` resolves
# its own default backend (gcc on this project's pinned Linux image,
# unchanged from every prior slice). The FIRST unit test file's compile
# is additionally run through scripts/lib/toolchain-canary.sh, which
# proves via Nim's own `--listCmd` output that the compiler actually
# invoked matches what was requested (or the gcc default) -- not merely
# that the flag was accepted -- see that script's own header for why a
# `clang --version` sanity check alone would not be enough. One code
# path: `cc_flag`/`cc_name` are plain bash variables consumed while
# building the `cmd` string below, so both entrypoints (SELLO_IN_CONTAINER=1
# and the podman-wrapped host branch) get identical --cc/canary behavior
# with no branch-specific handling of either.
#
# Mounts: the project + the milpa CAS (at both the canonical path and its
# host-absolute path, so milpa's absolute dep symlinks under _deps/
# resolve in-container -- same pattern as proptest's scripts/runtest.sh).
#
# Prerequisite: `milpa fetch` has been run on the host at least once (populates
# _deps/ and nim.cfg from milpa.lock). Not invoked automatically here, matching
# proptest's scripts/ convention -- keeps this script network-free and lets
# `--frozen` verification stay an explicit, separate step (`milpa verify`).
#
# SELLO_IN_CONTAINER=1 (RFC-005 slice 1): CI already runs this script
# inside the pinned toolchain image (the workflow's own `container:`), so
# there is no podman wrapper left to invoke and no HOST-side milpa state
# to preflight-check -- lib/milpa-preflight.sh's own header is explicit
# that `_deps/`/`milpa.lock` are host-side state the podman mount merely
# exposes; a container job either runs against a bare zero-dep nim.cfg
# (scripts/ci-setup.sh) or its own subsequently-fetched _deps/, and
# either way there is no host to check. One code path, two entrypoints:
# the `cmd` string built below is the single source of "what the suite
# run actually does," normally handed to `podman run ... bash -c "$cmd"`;
# under SELLO_IN_CONTAINER=1 it is instead handed to a plain local
# `bash -c "$cmd"`, skipping the podman/milpa-preflight branch entirely.
#
# OS-portability audit (part of this mode's own DoD, since the
# in-container branch is what the future macOS/Windows-Git-Bash CI jobs
# will run natively): the `cmd` string below is built entirely from
# forward-slash relative paths (`tests/unit/test_*.nim`, accepted as-is by
# Nim on Windows), plain `nim c`/`echo`/`set -e` lines with no shell
# builtin or flag specific to a Linux userland, and is executed via a bare
# `bash -c` relying on PATH resolution -- no `/bin/bash` hardcoding, no
# `/proc`, no GNU-coreutils-only flags. `cd "$(dirname "$0")/.."` and the
# `source`s above it use only `dirname`/`cd`, both present in Git Bash.
# Nothing in this branch shells out to a Linux-only tool (no `apt`, no
# `/dev/...` path, no `ldconfig`). Conclusion: clean, no Linux-isms found.
#
# Additional prerequisite for the property-based tests (test_properties_*,
# RFC-001 finding 10): proptest is an OPTIONAL milpa dep (milpa.kdl:
# `optional=#true`, auto-gated behind a same-named "proptest" feature flag,
# RFC #23 §3.2) so consumers of sello never transitively fetch
# proptest+nim-z3+softlink just by depending on sello. A plain `milpa fetch`
# prunes it (verified empirically: nim.cfg gains no proptest/z3/softlink
# --path lines and _deps/ is left empty -- there is no other dependency
# left to populate it). To enable it for local
# dev, run once: `milpa fetch --features proptest` -- this resolves and
# fetches proptest AND its own transitive deps (z3, softlink; proptest's own
# manifest declares z3 unconditionally), and nim.cfg gains their --path
# lines. Note this also rewrites the *committed* milpa.lock's proptest/z3/
# softlink entries in your working tree; that's expected milpa behavior
# (activation is recomputed from the manifest + requested features on every
# fetch, not preserved from a prior lock state) -- see the B4a summary in
# docs/rfc-001-signing.handoff.md. `import proptest` compiles fine in this
# script's base image with no z3 shared library installed: the only module
# that imports `z3` is `proptest/symex`, which the top-level `proptest`
# module never imports (confirmed empirically).
set -euo pipefail
cd "$(dirname "$0")/.."

# --cc <name> (RFC-005 slice 8) -- see the header comment above. Must be
# the leading argument if present; everything else (including anything
# after a consumed --cc pair) is forwarded verbatim as before.
cc_name="gcc"
cc_flag=""
if [[ "${1:-}" == "--cc" ]]; then
  if [[ -z "${2:-}" ]]; then
    echo "scripts/test.sh: --cc requires a compiler name, e.g. --cc clang" >&2
    exit 2
  fi
  cc_name="$2"
  cc_flag="--cc:$cc_name"
  shift 2
fi

extra_defines=("$@")

# unit_test_files ("which unit test files make up the suite") is defined in
# scripts/lib/unit-test-files.sh and sourced here, not retyped -- the same
# file is sourced by scripts/test-libsodium.sh, so the two matrices read one
# array instead of two hand-maintained copies that could silently drift
# apart (round-2 finding 25; the old comment here claimed "cannot drift"
# while actually being two independently-typed-out arrays -- this sourcing
# is what makes that claim true).
source "$(dirname "$0")/lib/unit-test-files.sh"

# End-of-run validation-tier visibility (round-3 fix batch B, finding B6) --
# see scripts/lib/tier-summary.sh's own header comment.
source "$(dirname "$0")/lib/tier-summary.sh"

img=ghcr.io/coreyleavitt/nim:2.2.10

cmd="set -e"
canary_done=0
for f in "${unit_test_files[@]}"; do
  cmd+=$'\n'"echo '=== $f ==='"
  if [[ "$canary_done" -eq 0 ]]; then
    # Platform-identity canary (RFC-005 slice 8): the first file's compile
    # is routed through scripts/lib/toolchain-canary.sh instead of a bare
    # `nim c`, proving Nim actually invoked the requested compiler (or the
    # gcc default) rather than merely accepting the flag. This IS this
    # file's real compile+run (`-r`), not an extra throwaway build.
    cmd+=$'\n'"scripts/lib/toolchain-canary.sh $cc_name nim c $cc_flag ${extra_defines[*]:-} --listCmd -f -r $f"
    canary_done=1
  else
    cmd+=$'\n'"nim c $cc_flag ${extra_defines[*]:-} -r $f"
  fi
done
# Property suites skipped because _deps/proptest is absent (RFC-003 slice 2
# item 4) -- same loud self-skip register as test_libsodium_interop's
# runtime skip(), but decided here in bash since the failure mode being
# avoided (a missing `import proptest`) is a compile error, not something
# a runtime skip() inside the test binary could ever reach.
for f in "${skipped_property_files[@]}"; do
  cmd+=$'\n'"echo '=== $f ==='"
  cmd+=$'\n'"echo 'SKIPPED (proptest not fetched -- run: milpa fetch --features proptest)'"
done

if [ "${SELLO_IN_CONTAINER:-}" = "1" ]; then
  # Already inside the pinned toolchain image (CI) -- run the same
  # commands directly, no podman wrapper, no host milpa-lock preflight.
  bash -c "$cmd"
else
  # Lockfile-conformance preflight (RFC-001 ledger finding 30): fails fast
  # on the host if milpa.lock and _deps/ are genuinely out of sync, before
  # the podman invocation below ever starts. See
  # scripts/lib/milpa-preflight.sh for exactly what this does and does not
  # treat as fatal. Host-only: `_deps/`/`milpa.lock` are host-side state,
  # meaningless to check from inside the container this preflight is
  # gating entry to.
  source "$(dirname "$0")/lib/milpa-preflight.sh"
  milpa_preflight

  podman run --rm \
    -v "$PWD:/workspace" \
    -v "$HOME/.cache/milpa:/.cache/milpa" \
    -v "$HOME/.cache/milpa:$HOME/.cache/milpa" \
    -w /workspace \
    "$img" \
    bash -c "$cmd"
fi

print_tier_summary "scripts/test.sh"
