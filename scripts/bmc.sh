#!/usr/bin/env bash
# Machine-checked (Z3) proof of scalar.recodeScalarRadix16's digit-range
# invariant (RFC-001 review finding 22) via tests/verify/symex_recode.nim,
# using COREY'S proptest library's symbolic-execution engine
# (proptest/symex). See that file's module doc comment for exactly what is
# and isn't proved (the digit-RANGE invariant, exhaustively, over the
# whole bit-255-clear input domain; NOT the digit-reconstruction identity,
# which stays sampled -- see B4a's property tests).
#
# HARD KILL TIMEOUT, like proptest's own scripts/dt-bounded.sh: Z3 queries
# can hang the solver outright on pathological mixed-theory shapes (a
# documented proptest incident spun a full core for 24+ minutes on one
# query). A hung solver here must never peg a box indefinitely -- this
# script `timeout --signal=KILL`s the whole podman run and tears down the
# container even if the podman client itself is what gets killed.
#
# Usage:  scripts/bmc.sh [timeout_secs]      # default 300s
#
# Needs the sello-dev image (Containerfile: base Nim image + libsodium-devel
# + z3-devel). Builds it if missing and network allows; otherwise fails
# with podman's own build error.
#
# Mounts: the project + the milpa CAS (at both the canonical path and its
# host-absolute path, so milpa's _deps/z3 and _deps/softlink absolute
# symlinks resolve in-container) -- same pattern as scripts/test.sh /
# proptest's own scripts/dt.sh. Prerequisite: `milpa fetch --features
# proptest` has been run on the host at least once (populates _deps/z3,
# _deps/softlink, _deps/proptest and their nim.cfg --path lines).
set -uo pipefail
cd "$(dirname "$0")/.."

# Lockfile-conformance preflight (RFC-001 ledger finding 30) -- see
# scripts/lib/milpa-preflight.sh for exactly what this does and does not
# treat as fatal. This script does not use `set -e` (it inspects `podman
# run`'s own exit code below to distinguish a kill-timeout from a solver
# verdict), so the preflight's failure is checked explicitly here instead
# of relying on shell-level errexit.
source "$(dirname "$0")/lib/milpa-preflight.sh"
milpa_preflight || exit 1

timeout_secs="${1:-300}"
img=localhost/sello-dev:latest
podman image exists "$img" || podman build -t "$img" -f Containerfile .

cname="sello_bmc_$$"
cleanup() { podman rm -f "$cname" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

timeout --signal=KILL "$timeout_secs" podman run --rm --name "$cname" \
  -v "$PWD:/workspace" \
  -v "$HOME/.cache/milpa:/.cache/milpa" \
  -v "$HOME/.cache/milpa:$HOME/.cache/milpa" \
  -w /workspace \
  "$img" \
  bash -c "nim c --threads:on --hints:off -r tests/verify/symex_recode.nim"
rc=$?

if [ "$rc" -eq 137 ] || [ "$rc" -eq 124 ]; then
  echo ">>> HUNG: symex_recode.nim killed after ${timeout_secs}s -- treat as" \
       "a solver/walker non-termination issue, not a slow proof." >&2
  exit 137
fi
exit "$rc"
