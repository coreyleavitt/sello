#!/usr/bin/env bash
# Machine-checked (Z3) proofs, via COREY'S proptest library's symbolic-
# execution engine (proptest/symex), run in one invocation:
#   - tests/verify/symex_recode.nim: scalar.recodeScalarRadix16's
#     digit-range invariant (RFC-001 review finding 22).
#   - tests/verify/symex_mask.nim: field.feCMove/feCSwap's arithmetic-
#     masking algebra (round-3 fix batch Z, item Z1).
#   - tests/verify/symex_reduce.nim: scalar.scReduce/scMulAdd's shared
#     carry-propagation macro's per-step bound invariant, plus (gated
#     behind -d:selloBmcReduceFullChain, OFF by default -- see that
#     file's own RESOURCE WALL section) an attempted, empirically
#     intractable-in-this-environment whole-body composition (round-3
#     fix batch Z, items Z2/Z3).
# See each file's own module doc comment for exactly what is and isn't
# proved -- do not assume parity between them; each documents its own
# scope, encoding choices, and honest limits.
#
# HARD KILL TIMEOUT, like proptest's own scripts/dt-bounded.sh: Z3 queries
# can hang the solver outright on pathological mixed-theory shapes (a
# documented proptest incident spun a full core for 24+ minutes on one
# query). A hung solver here must never peg a box indefinitely -- this
# script `timeout --signal=KILL`s the whole podman run and tears down the
# container even if the podman client itself is what gets killed. The
# three files below run as three SEPARATE `nim c -r` invocations chained
# with `&&`, not one combined binary -- so a kill mid-way still shows,
# via each file's own stdout already flushed, which ones completed before
# the timeout hit, rather than losing all progress to one opaque kill.
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
  bash -c "
    set -e
    nim c --threads:on --hints:off -r tests/verify/symex_recode.nim
    nim c --threads:on --hints:off -r tests/verify/symex_mask.nim
    nim c --threads:on --hints:off -r tests/verify/symex_reduce.nim
  "
rc=$?

if [ "$rc" -eq 137 ] || [ "$rc" -eq 124 ]; then
  echo ">>> HUNG: symex_recode.nim killed after ${timeout_secs}s -- treat as" \
       "a solver/walker non-termination issue, not a slow proof." >&2
  exit 137
fi
exit "$rc"
