#!/usr/bin/env bash
# scripts/check-readme.sh — extract every ```nim fence from README.md and
# `nim check` it in-container, so a README example that no longer compiles
# against the current facade (round-2 finding 24 -- the X25519 example
# drifted onto a removed `array[32, byte]` signature after X25519Key
# shipped) fails a script run instead of silently rotting until a reader
# copy-pastes it.
#
# Every ```nim fence in README.md today is written to be fully
# compilable on its own (top-level statements, no `discard main()`
# wrapper needed) -- preferred over marking any of them partial per this
# script's own design goal. A fence CAN opt out by putting "no-check" on
# its opening fence line (```` ```nim no-check ````) for a future
# deliberately-partial snippet; none currently do.
#
# Usage:  scripts/check-readme.sh
#         SELLO_IN_CONTAINER=1 scripts/check-readme.sh   # already inside
#                                                          # the pinned image (CI)
#
# Mounts: the project + the milpa CAS (at both the canonical path and its
# host-absolute path), same pattern as scripts/test.sh. Prerequisite:
# `milpa fetch` has been run on the host at least once (populates _deps/
# and nim.cfg, which `import sello` in the extracted fences resolves
# through) -- or, under SELLO_IN_CONTAINER=1 with no local `_deps/` at
# all, scripts/ci-setup.sh has written the zero-dependency nim.cfg first
# (README fences only exercise `import sello`, never nelli).
#
# RFC-005 slice 2 retrofit: this script used to hardcode the podman
# invocation and skip scripts/lib/milpa-preflight.sh entirely (both
# named as traps in the RFC) -- it now follows scripts/test.sh's own
# split exactly: SELLO_IN_CONTAINER=1 runs the extracted-fence checks
# directly (CI already IS the pinned image, so there is no podman layer
# left to add and no host-side milpa state to preflight), and the
# host/local path gains the milpa-lock preflight scripts/test.sh already
# had and this script did not.
set -euo pipefail
cd "$(dirname "$0")/.."

outdir="build/readme-check"
rm -rf "$outdir"
mkdir -p "$outdir"

# Extract every ```nim ... ``` fence from README.md into its own file
# under $outdir, plus a manifest recording each fence's number, its
# CHECK/SKIP disposition (SKIP iff the opening fence line contains the
# literal "no-check"), and the extracted file's path.
awk -v outdir="$outdir" '
  BEGIN { n = 0; inFence = 0 }
  /^```nim/ {
    inFence = 1
    n++
    fname = outdir "/fence_" sprintf("%02d", n) ".nim"
    disposition = ($0 ~ /no-check/) ? "SKIP" : "CHECK"
    print n, disposition, fname >> (outdir "/manifest.txt")
    next
  }
  /^```/ {
    if (inFence) { inFence = 0; close(fname) }
    next
  }
  { if (inFence) print > fname }
' README.md

if [[ ! -f "$outdir/manifest.txt" ]]; then
  echo "check-readme.sh: no \`\`\`nim fences found in README.md" >&2
  exit 1
fi

cmd="set -e"
while read -r num disposition fname; do
  if [[ "$disposition" == "SKIP" ]]; then
    cmd+=$'\n'"echo '=== fence $num ($fname): SKIPPED (no-check) ==='"
  else
    cmd+=$'\n'"echo '=== fence $num ($fname) ==='"
    cmd+=$'\n'"nim check $fname"
  fi
done < "$outdir/manifest.txt"

if [ "${SELLO_IN_CONTAINER:-}" = "1" ]; then
  # Already inside the pinned toolchain image (CI) -- run directly, no
  # podman wrapper, no host milpa-lock preflight (same split as
  # scripts/test.sh; see this script's header comment).
  bash -c "$cmd"
else
  # Lockfile-conformance preflight (RFC-001 ledger finding 30), same as
  # scripts/test.sh -- host-only, since _deps/milpa.lock are host-side
  # state meaningless to check from inside the container this preflight
  # gates entry to.
  source "$(dirname "$0")/lib/milpa-preflight.sh"
  milpa_preflight

  img=ghcr.io/coreyleavitt/nim:2.2.10
  podman run --rm \
    -v "$PWD:/workspace" \
    -v "$HOME/.cache/milpa:/.cache/milpa" \
    -v "$HOME/.cache/milpa:$HOME/.cache/milpa" \
    -w /workspace \
    "$img" \
    bash -c "$cmd"
fi

echo "check-readme.sh: all README.md \`\`\`nim fences compile."
