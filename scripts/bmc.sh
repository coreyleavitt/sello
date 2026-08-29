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
#   - tests/verify/symex_equal.nim: the or-accumulate shape shared by
#     field.feEqualCT/feIsZeroCT/feBytesCanonicalCT (RFC-004 slice 1b):
#     the accumulated word is zero iff every byte pair is equal, over the
#     full 32-byte-pair composition in one query.
# See each file's own module doc comment for exactly what is and isn't
# proved -- do not assume parity between them; each documents its own
# scope, encoding choices, and honest limits.
#
# HARD KILL TIMEOUT, like proptest's own scripts/dt-bounded.sh: Z3 queries
# can hang the solver outright on pathological mixed-theory shapes (a
# documented proptest incident spun a full core for 24+ minutes on one
# query). A hung solver here must never peg a box indefinitely -- this
# script `timeout --signal=KILL`s the whole podman run (host mode) or the
# bare four-file proof chain (CI, RFC-005 slice 15 -- see below) and tears
# down the container even if the podman client itself is what gets killed.
# The four files below run as four SEPARATE `nim c -r` invocations chained
# with `&&`, not one combined binary -- so a kill mid-way still shows,
# via each file's own stdout already flushed, which ones completed before
# the timeout hit, rather than losing all progress to one opaque kill.
#
# RFC-005 slice 15's CI timeout-triage policy (see CLAUDE.md's own "Mutation
# + bmc jobs" CI paragraph for the calibrated timeout-minutes value and the
# real hosted numbers it was calibrated from): a timeout here is TRIAGED,
# never green-washed -- retry once (hosted variance); a SECOND timeout on
# the same code is investigated as a solver regression, not silently
# re-run until it happens to pass. The merge gate has no notify job of its
# own (unlike nightly.yml's timeout-vs-cancel annotation-based split,
# RFC-005 slice 26) -- a bmc timeout here is simply a red required check,
# same as any other failure; the distinction is a maintainer's own
# judgment call when triaging a red run, not a mechanized signal.
#
# Usage:  scripts/bmc.sh [timeout_secs]      # default 300s, host mode
#         SELLO_IN_CONTAINER=1 scripts/bmc.sh [timeout_secs]   # already
#                                               inside the pinned sello-dev
#                                               image (CI)
#
# Needs the sello-dev image (Containerfile: base Nim image + libsodium-devel
# + z3-devel + the rest of RFC-005's package set) -- z3-devel is the one
# this script actually needs; the rest of that image's package set is
# unused here but pulling a second, bmc-only image was declined (the RFC's
# own "one image, consolidate" preference -- see CLAUDE.md's own "Image
# consolidation" paragraph). As of RFC-005 slice 7, host mode pulls
# `ghcr.io/coreyleavitt/sello-dev` BY DIGEST per the pin in
# scripts/lib/image-pins.txt (scripts/lib/sello-dev-image.sh) rather than
# building locally if missing -- see that file's header comment for the
# SELLO_DEV_LOCAL_BUILD/SELLO_DEV_IMAGE_REF escape hatches. CI (RFC-005
# slice 15) needs none of this -- the job's own `container:` field already
# pins the exact same digest, so the SELLO_IN_CONTAINER=1 branch below
# skips podman/image-resolution entirely.
#
# Host mode mounts: the project + the milpa CAS (at both the canonical path
# and its host-absolute path, so milpa's _deps/z3 and _deps/softlink
# absolute symlinks resolve in-container) -- same pattern as
# scripts/test.sh / proptest's own scripts/dt.sh. Prerequisite: `milpa
# fetch --features proptest` has been run on the host at least once
# (populates _deps/z3, _deps/softlink, _deps/proptest and their nim.cfg
# --path lines). CI mode (SELLO_IN_CONTAINER=1) has no such host state to
# rely on -- a bare checkout starts with none of `_deps/z3`/
# `_deps/softlink`/`_deps/proptest` populated, so that branch fetches them
# itself (mirroring scripts/ci-property.sh's/scripts/build-smoke.sh's own
# in-container milpa-install-then-fetch pattern) before running the four
# proof files.
set -uo pipefail
cd "$(dirname "$0")/.."

# Lockfile-conformance preflight (RFC-001 ledger finding 30) -- see
# scripts/lib/milpa-preflight.sh for exactly what this does and does not
# treat as fatal. Host-only: _deps/milpa.lock are host-side state,
# meaningless to check from inside the container this preflight gates
# entry to (CI's own fresh checkout has no such state to check either).
# This script does not use `set -e` (it inspects the proof chain's own
# exit code below to distinguish a kill-timeout from a solver verdict), so
# every fallible step below is checked explicitly rather than relying on
# shell-level errexit.

timeout_secs="${1:-300}"

if [ "${SELLO_IN_CONTAINER:-}" = "1" ]; then
  # RFC-005 slice 15 — already inside the pinned sello-dev image (CI's own
  # `container:` field): no podman wrapper, no image resolution, no host
  # milpa-lock preflight (there is no host to preflight-check from inside
  # the container CI already runs in — the identical reasoning
  # scripts/test.sh's own SELLO_IN_CONTAINER=1 branch documents). Fetches
  # milpa + proptest (which pulls in z3/softlink transitively — see
  # milpa.kdl's own overrides block) itself, since a bare CI checkout has
  # none of that populated the way a maintainer's host does.
  source "$(dirname "$0")/lib/milpa-install.sh"
  install_milpa "build/milpa-venv" || exit 1

  echo "bmc: fetching proptest + z3 + softlink (--locked: asserts against the committed milpa.lock)" >&2
  "$MILPA_BIN" fetch --features proptest --locked || exit 1

  timeout --signal=KILL "$timeout_secs" bash -c "
    set -e
    nim c --threads:on --hints:off -r tests/verify/symex_recode.nim
    nim c --threads:on --hints:off -r tests/verify/symex_mask.nim
    nim c --threads:on --hints:off -r tests/verify/symex_reduce.nim
    nim c --threads:on --hints:off -r tests/verify/symex_equal.nim
  "
  rc=$?
else
  # Lockfile-conformance preflight (RFC-001 ledger finding 30) -- see
  # scripts/lib/milpa-preflight.sh for exactly what this does and does not
  # treat as fatal. This script does not use `set -e` (it inspects `podman
  # run`'s own exit code below to distinguish a kill-timeout from a solver
  # verdict), so the preflight's failure is checked explicitly here instead
  # of relying on shell-level errexit.
  source "$(dirname "$0")/lib/milpa-preflight.sh"
  milpa_preflight || exit 1

  # Resolves `img` -- pull-by-digest of the published sello-dev image by
  # default, or a local build under SELLO_DEV_LOCAL_BUILD=1 (RFC-005 slice
  # 7 -- see scripts/lib/sello-dev-image.sh's own header comment). This
  # script doesn't `set -e` (see the header comment above), so the resolve
  # failure is checked explicitly, same as the preflight above.
  source "$(dirname "$0")/lib/sello-dev-image.sh"
  resolve_sello_dev_image || exit 1

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
      nim c --threads:on --hints:off -r tests/verify/symex_equal.nim
    "
  rc=$?
fi

if [ "$rc" -eq 137 ] || [ "$rc" -eq 124 ]; then
  echo ">>> HUNG: one of tests/verify/symex_{recode,mask,reduce,equal}.nim" \
       "killed after ${timeout_secs}s -- treat as a solver/walker" \
       "non-termination issue, not a slow proof." >&2
  exit 137
fi
exit "$rc"
