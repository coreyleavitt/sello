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
# Requires libsodium-devel -- carried by the "sello-dev" image (built from
# the sello-owned Containerfile, repo root; also carries z3-devel for
# scripts/bmc.sh plus the rest of RFC-005's package set -- see the
# Containerfile's own header comment), not the base Nim image. As of
# RFC-005 slice 7, pulls `ghcr.io/coreyleavitt/sello-dev` BY DIGEST per the
# pin in scripts/lib/image-pins.txt (scripts/lib/sello-dev-image.sh) rather
# than building locally if missing -- see that file's header comment for
# the SELLO_DEV_LOCAL_BUILD/SELLO_DEV_IMAGE_REF escape hatches.
#
# SELLO_IN_CONTAINER=1 (RFC-005 slice 14, the libsodium-differential merge
# -gate job): the same dual-mode split scripts/test.sh/scripts/ci-property.sh
# already had. CI runs this script inside the `sello-dev` image directly
# (the job's own `container:` field), so there is no podman wrapper left
# to invoke and no host-side milpa state to preflight-check -- one code
# path (the `cmd` string below is "what the suite run actually does"),
# two entrypoints: normally handed to `podman run ... bash -c "$cmd"`
# (host mode, below); under SELLO_IN_CONTAINER=1, handed to a plain local
# `bash -c "$cmd"` instead, skipping both the podman wrap and the host
# lockfile-conformance preflight (scripts/lib/milpa-preflight.sh) and
# sello-dev image resolution (scripts/lib/sello-dev-image.sh) -- neither
# means anything from inside a container CI already pinned to the exact
# image via its own `container:` field.
#
# SELLO_REQUIRE_LIBSODIUM=1 (RFC-005 slice 14): exported unconditionally
# into the suite run below, in BOTH entrypoints -- this script's entire
# purpose is running the real libsodium interop checks, so a silent
# degrade to test_libsodium_interop.nim's no-op skip suite (e.g. a future
# edit that accidentally drops -d:selloLibsodium from this script's own
# per-file `nim c` line) must be a red check, not a quietly-weaker run.
# See that file's own module doc comment for the test-level half of this
# (a doAssert instead of skip() when this env var is set and the
# -d:selloLibsodium branch was not compiled in). This script ALSO greps
# the run's combined output for unittest's own `[SKIPPED]` marker
# (std/unittest's ConsoleOutputFormatter default PRINT_ALL output level
# prints exactly this bracketed marker per skipped test -- verified
# against the vendored unittest.nim source, not assumed) and fails loud
# if it appears, as a second, independent layer of the same assertion:
# tests/unit/ has exactly one skip() call today (in
# test_libsodium_interop.nim's else branch), so this catches that one
# directly AND any future skip() call anywhere else in the unit suite
# that this script compiles -- the same "silent skip must be a red
# check" register scripts/ci-property.sh's proptest-skip-banner assertion
# already holds, applied here with a grep pattern chosen so it does NOT
# false-positive on the unrelated, differently-worded proptest-skip
# banner ("SKIPPED (proptest not fetched ...)", no brackets, printed via
# a plain `echo`, not std/unittest) this same run's property-suite lines
# may also legitimately print when _deps/proptest is absent (this script
# fetches no proptest of its own -- see the "Additional prerequisite"
# paragraph below, unchanged from before this slice).
#
# Usage:  scripts/test-libsodium.sh
#         SELLO_IN_CONTAINER=1 scripts/test-libsodium.sh   # already inside
#                                                            # the pinned
#                                                            # sello-dev
#                                                            # image (CI)
#
# Mounts (host mode): the project + the milpa CAS (at both the canonical
# path and its host-absolute path, so milpa's absolute dep symlinks under
# _deps/ resolve in-container). Prerequisite: `milpa fetch` has been run
# on the host at least once (see scripts/test.sh).
#
# Additional prerequisite for the property-based tests (test_properties_*):
# proptest is an OPTIONAL milpa dep -- run `milpa fetch --features proptest`
# once before invoking this script. See scripts/test.sh's header comment
# for the full optional-dep wiring rationale (kept there, not duplicated).
# Neither entrypoint below fetches proptest itself, so with no prior fetch
# the property files self-skip via their own loud, differently-worded
# banner (unaffected by SELLO_REQUIRE_LIBSODIUM -- see above), exactly as
# they did before this slice.
set -euo pipefail
cd "$(dirname "$0")/.."

# unit_test_files is defined once in scripts/lib/unit-test-files.sh and
# sourced here AND by scripts/test.sh -- see that file's header comment
# for why (round-2 finding 25: this used to be a second hand-typed copy
# of the array, not actually incapable of drifting from test.sh's).
source "$(dirname "$0")/lib/unit-test-files.sh"

# End-of-run validation-tier visibility (round-3 fix batch B, finding B6,
# shared with scripts/test.sh -- see scripts/lib/tier-summary.sh).
source "$(dirname "$0")/lib/tier-summary.sh"

cmd="set -e"
# SELLO_REQUIRE_LIBSODIUM=1 -- see the header comment above. Exported
# inside the `cmd` string (not the outer script's own shell) so it
# reaches the Nim binary's own process environment in BOTH entrypoints:
# a plain local `bash -c "$cmd"` under SELLO_IN_CONTAINER=1, and the
# podman-wrapped `bash -c "$cmd"` in host mode below (podman does not
# inherit the host shell's environment into the container by default).
cmd+=$'\n'"export SELLO_REQUIRE_LIBSODIUM=1"
for f in "${unit_test_files[@]}"; do
  cmd+=$'\n'"echo '=== $f ==='"
  cmd+=$'\n'"nim c -d:selloLibsodium -r $f"
done
# Property suites skipped because _deps/proptest is absent (RFC-003 slice 2
# item 4) -- see scripts/test.sh's matching comment / scripts/lib/
# unit-test-files.sh for the detection logic shared by both scripts. This
# banner is plain text ("SKIPPED (proptest not fetched ...)"), not
# std/unittest's own bracketed "[SKIPPED]" marker, so it does not trip the
# grep-based assertion below.
for f in "${skipped_property_files[@]}"; do
  cmd+=$'\n'"echo '=== $f ==='"
  cmd+=$'\n'"echo 'SKIPPED (proptest not fetched -- run: milpa fetch --features proptest)'"
done

log="build/test-libsodium.log"
mkdir -p "$(dirname "$log")"

if [ "${SELLO_IN_CONTAINER:-}" = "1" ]; then
  # Already inside the pinned sello-dev image (CI) -- run the same
  # commands directly, no podman wrapper, no host milpa-lock preflight, no
  # sello-dev image resolution (the job's own `container:` field already
  # pinned the exact image).
  bash -c "$cmd" 2>&1 | tee "$log"
else
  # Lockfile-conformance preflight (RFC-001 ledger finding 30) -- see
  # scripts/lib/milpa-preflight.sh for exactly what this does and does not
  # treat as fatal. Host-only: _deps/milpa.lock are host-side state,
  # meaningless to check from inside the container this preflight gates
  # entry to.
  source "$(dirname "$0")/lib/milpa-preflight.sh"
  milpa_preflight

  # Resolves `img` -- pull-by-digest of the published sello-dev image by
  # default, or a local build under SELLO_DEV_LOCAL_BUILD=1 (RFC-005 slice
  # 7 -- see scripts/lib/sello-dev-image.sh's own header comment). CI
  # never reaches this branch -- unit-linux-amd64-gcc-libsodium runs with
  # SELLO_IN_CONTAINER=1, already inside sello-dev via its own
  # `container:` pin.
  source "$(dirname "$0")/lib/sello-dev-image.sh"
  resolve_sello_dev_image

  podman run --rm \
    -v "$PWD:/workspace" \
    -v "$HOME/.cache/milpa:/.cache/milpa" \
    -v "$HOME/.cache/milpa:$HOME/.cache/milpa" \
    -w /workspace \
    "$img" \
    bash -c "$cmd" 2>&1 | tee "$log"
fi

# SELLO_REQUIRE_LIBSODIUM's script-level backup assertion -- see the
# header comment above for why this is a second, independent layer on top
# of test_libsodium_interop.nim's own doAssert, not the primary
# mechanism: the doAssert already turns the ONE skip() this suite can
# reach today into a hard `nim c -r` failure (which `set -e` inside `cmd`
# above already propagates, well before this point). This grep instead
# proves, from the run's own combined output, that no std/unittest
# `[SKIPPED]` marker of ANY kind slipped through -- future-proofing
# against a skip() added somewhere else in the unit suite with no
# SELLO_REQUIRE_LIBSODIUM awareness of its own.
if grep -q '\[SKIPPED\]' "$log"; then
  echo "" >&2
  echo "test-libsodium: FAIL -- a std/unittest [SKIPPED] marker appears in this run's log." >&2
  echo "test-libsodium: this script always compiles with -d:selloLibsodium and exports" >&2
  echo "test-libsodium: SELLO_REQUIRE_LIBSODIUM=1, so no unit-suite test should ever call" >&2
  echo "test-libsodium: skip() during this run -- investigate which test skipped and why," >&2
  echo "test-libsodium: do not silence this by removing the env var or the assertion." >&2
  exit 1
fi
echo "test-libsodium: no [SKIPPED] marker found, as required -- the libsodium interop suite ran for real." >&2

print_tier_summary "scripts/test-libsodium.sh (-d:selloLibsodium)"
