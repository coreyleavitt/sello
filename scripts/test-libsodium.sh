#!/usr/bin/env bash
# Run sello's unit test suite against the libsodium adapter backend
# (-d:selloLibsodium). Replaces the old `nimble testLibsodium` task.
#
# Same unit_test_files list as scripts/test.sh, recompiled with
# -d:selloLibsodium so signing.nim dispatches to the libsodium FFI adapter
# (private/backend_sodium.nim) and test_libsodium_interop.nim's real
# bidirectional interop checks compile in. sello/ed25519.verify is never
# affected -- it has no backend dispatch and stays pure-Nim under this
# flag too.
#
# Requires libsodium-devel -- built from the sello-owned Containerfile
# (repo root) into the "sello-dev" image (also carries z3-devel for
# scripts/bmc.sh; one dev image covers both matrices -- see the
# Containerfile's own header comment), not the base Nim image. Builds the
# image if missing and network allows; otherwise fails with podman's own
# image-not-found error.
#
# Usage:  scripts/test-libsodium.sh
#
# Mounts: the project + the milpa CAS (at both the canonical path and its
# host-absolute path, so milpa's absolute dep symlinks under _deps/
# resolve in-container). Prerequisite: `milpa fetch` has been run on the
# host at least once (see scripts/test.sh).
#
# Additional prerequisite for the property-based tests (test_properties_*):
# proptest is an OPTIONAL milpa dep -- run `milpa fetch --features proptest`
# once before invoking this script. See scripts/test.sh's header comment
# for the full optional-dep wiring rationale (kept there, not duplicated).
set -euo pipefail
cd "$(dirname "$0")/.."

# unit_test_files is defined once in scripts/lib/unit-test-files.sh and
# sourced here AND by scripts/test.sh -- see that file's header comment
# for why (round-2 finding 25: this used to be a second hand-typed copy
# of the array, not actually incapable of drifting from test.sh's).
source "$(dirname "$0")/lib/unit-test-files.sh"

# Lockfile-conformance preflight (RFC-001 ledger finding 30) -- see
# scripts/lib/milpa-preflight.sh for exactly what this does and does not
# treat as fatal.
source "$(dirname "$0")/lib/milpa-preflight.sh"
milpa_preflight

# End-of-run validation-tier visibility (round-3 fix batch B, finding B6,
# shared with scripts/test.sh -- see scripts/lib/tier-summary.sh).
source "$(dirname "$0")/lib/tier-summary.sh"

img=localhost/sello-dev:latest
podman image exists "$img" || podman build -t "$img" -f Containerfile .

cmd="set -e"
for f in "${unit_test_files[@]}"; do
  cmd+=$'\n'"echo '=== $f ==='"
  cmd+=$'\n'"nim c -d:selloLibsodium -r $f"
done
# Property suites skipped because _deps/proptest is absent (RFC-003 slice 2
# item 4) -- see scripts/test.sh's matching comment / scripts/lib/
# unit-test-files.sh for the detection logic shared by both scripts.
for f in "${skipped_property_files[@]}"; do
  cmd+=$'\n'"echo '=== $f ==='"
  cmd+=$'\n'"echo 'SKIPPED (proptest not fetched -- run: milpa fetch --features proptest)'"
done

podman run --rm \
  -v "$PWD:/workspace" \
  -v "$HOME/.cache/milpa:/.cache/milpa" \
  -v "$HOME/.cache/milpa:$HOME/.cache/milpa" \
  -w /workspace \
  "$img" \
  bash -c "$cmd"

print_tier_summary "scripts/test-libsodium.sh (-d:selloLibsodium)"
