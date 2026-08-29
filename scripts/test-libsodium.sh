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
# to invoke and no host-side milpa/proptest state to rely on -- see the
# "proptest is now REQUIRED" paragraph below for what the in-container
# body does about that that host mode does not need to.
#
# proptest is now REQUIRED for this script, not merely optional (a genuine
# finding, reproduced locally before being coded around, not assumed):
# test_libsodium_interop.nim's `when defined(selloLibsodium)` branch does
# an unconditional `import proptest` at module scope, needed for its OWN
# embedded differential/random-sweep property checks (the ristretto255
# hash-to-group/scalarmult sweeps, the SHA-512 random-input sweep) -- this
# is NOT limited to the standalone test_properties_*.nim files the way
# scripts/test.sh's own optional-proptest story is. Compiling this file
# under -d:selloLibsodium with no proptest fetched is a hard COMPILE
# ERROR ("cannot open file: proptest"), not a graceful runtime skip --
# reproduced directly against this exact script before this comment was
# written. Host mode therefore preflight-checks _deps/proptest and fails
# fast with an actionable message (see below) rather than letting the
# podman run fail confusingly mid-suite; the SELLO_IN_CONTAINER=1 body
# fetches proptest itself via milpa (mirroring scripts/ci-property.sh's/
# scripts/build-smoke.sh's own in-container fetch pattern), since CI
# starts from a bare checkout with no _deps/ of its own.
#
# Standalone property-suite files (test_properties_*.nim) are ALWAYS
# excluded from this script's own compiled set, regardless of whether
# proptest ends up fetched (RFC-005 slice 14, a confident scope call,
# recorded here): -d:selloLibsodium affects exactly ONE src/sello module
# (signing.nim's backend dispatch) -- field.nim/scalar.nim/x25519.nim/
# ristretto.nim/private/sha512.nim never branch on it at all, so five of
# these six files would exercise byte-identical pure-Nim code paths to
# their plain-build run, at real wall-clock cost (test_properties_scalar
# alone measured well over a minute in the RFC-005 slice 10 --cpu:i386
# investigation's own amd64-native baseline), for zero incremental
# coverage; carrying the sixth (test_properties_signing.nim, which WOULD
# exercise the libsodium-backed sign/keygen path under real property
# generation) alone would mean forking scripts/lib/unit-test-files.sh's
# shared array into a per-caller allowlist, breaking the single-source
# convention round-2 finding 25 established. This leg's real differential
# property coverage of the libsodium backend already lives inside
# test_libsodium_interop.nim itself (the property "derivePublic and
# signDetached agree byte-for-byte across backends" suite, among others)
# -- the standalone files add nothing this leg doesn't already have
# elsewhere, under this specific build config.
#
# Usage:  scripts/test-libsodium.sh
#         SELLO_IN_CONTAINER=1 scripts/test-libsodium.sh   # already inside
#                                                            # the pinned
#                                                            # sello-dev
#                                                            # image (CI)
#
# Mounts (host mode): the project + the milpa CAS (at both the canonical
# path and its host-absolute path, so milpa's absolute dep symlinks under
# _deps/ resolve in-container). Prerequisite: `milpa fetch --features
# proptest` has been run on the host at least once (see the "proptest is
# now REQUIRED" paragraph above) -- checked up front, below, with a fail-
# fast message rather than a confusing mid-run compile error.
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

# RFC-005 slice 14 -- always exclude the standalone property-suite files
# from this script's own compiled set, regardless of what
# scripts/lib/unit-test-files.sh's own (proptest-presence-driven) filter
# already decided -- see the header comment above for the full rationale.
# Idempotent either way: unit-test-files.sh's filter and this one target
# the exact same tests/unit/test_properties_*.nim glob, so a file already
# moved into skipped_property_files by that filter is simply not seen
# again here.
libsodium_filtered_files=()
for f in "${unit_test_files[@]}"; do
  case "$f" in
    tests/unit/test_properties_*.nim) skipped_property_files+=("$f") ;;
    *) libsodium_filtered_files+=("$f") ;;
  esac
done
unit_test_files=("${libsodium_filtered_files[@]}")

cmd="set -e"
# SELLO_REQUIRE_LIBSODIUM=1 (RFC-005 slice 14) -- see
# test_libsodium_interop.nim's own module doc comment for the full
# rationale. Exported inside the `cmd` string (not the outer script's own
# shell) so it reaches the Nim binary's own process environment in BOTH
# entrypoints: a plain local `bash -c "$cmd"` under SELLO_IN_CONTAINER=1,
# and the podman-wrapped `bash -c "$cmd"` in host mode below (podman does
# not inherit the host shell's environment into the container by
# default).
cmd+=$'\n'"export SELLO_REQUIRE_LIBSODIUM=1"
for f in "${unit_test_files[@]}"; do
  cmd+=$'\n'"echo '=== $f ==='"
  cmd+=$'\n'"nim c -d:selloLibsodium -r $f"
done
# Standalone property-suite files -- always skipped by this script (see
# the header comment above), one uniform, always-accurate banner
# regardless of whether proptest happens to be fetched -- unlike
# scripts/test.sh's own skip banner (which really does mean "proptest not
# fetched"), this one is a permanent scope decision, so it says so
# instead of reusing that wording, which would be actively misleading
# once proptest IS fetched (as it always is under SELLO_IN_CONTAINER=1,
# see below).
for f in "${skipped_property_files[@]}"; do
  cmd+=$'\n'"echo '=== $f ==='"
  cmd+=$'\n'"echo 'SKIPPED (unit+interop-suite scope only -- see scripts/test-libsodium.sh header comment)'"
done

log="build/test-libsodium.log"
mkdir -p "$(dirname "$log")"

if [ "${SELLO_IN_CONTAINER:-}" = "1" ]; then
  # Already inside the pinned sello-dev image (CI) -- fetch proptest
  # ourselves (a bare checkout has no _deps/ of its own; see the header
  # comment's "proptest is now REQUIRED" paragraph), then run the suite
  # directly, no podman wrapper, no host milpa-lock preflight, no
  # sello-dev image resolution (the job's own `container:` field already
  # pinned the exact image).
  source "$(dirname "$0")/lib/milpa-install.sh"
  install_milpa "build/milpa-venv"
  echo "test-libsodium: fetching proptest + transitives (--locked: asserts against the committed milpa.lock) -- needed for test_libsodium_interop.nim's own embedded differential/property sweeps under -d:selloLibsodium" >&2
  "$MILPA_BIN" fetch --features proptest --locked

  bash -c "$cmd" 2>&1 | tee "$log"
else
  # Lockfile-conformance preflight (RFC-001 ledger finding 30) -- see
  # scripts/lib/milpa-preflight.sh for exactly what this does and does not
  # treat as fatal. Host-only: _deps/milpa.lock are host-side state,
  # meaningless to check from inside the container this preflight gates
  # entry to.
  source "$(dirname "$0")/lib/milpa-preflight.sh"
  milpa_preflight

  # RFC-005 slice 14's own preflight, host-mode only: proptest is now
  # REQUIRED (see the header comment above), not merely nice-to-have --
  # fail fast with an actionable message here rather than letting the
  # podman run below fail confusingly mid-suite with a bare "cannot open
  # file: proptest" from deep inside test_libsodium_interop.nim's compile.
  if [ ! -d "_deps/proptest" ]; then
    echo "" >&2
    echo "scripts/test-libsodium.sh: FAIL -- _deps/proptest is absent." >&2
    echo "scripts/test-libsodium.sh: proptest is REQUIRED for this script (not merely" >&2
    echo "scripts/test-libsodium.sh: optional the way it is for scripts/test.sh) --" >&2
    echo "scripts/test-libsodium.sh: test_libsodium_interop.nim's -d:selloLibsodium branch" >&2
    echo "scripts/test-libsodium.sh: unconditionally imports it for its own embedded" >&2
    echo "scripts/test-libsodium.sh: differential/property sweeps. Run:" >&2
    echo "scripts/test-libsodium.sh:   milpa fetch --features proptest" >&2
    echo "scripts/test-libsodium.sh: then retry." >&2
    exit 1
  fi

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

# SELLO_REQUIRE_LIBSODIUM's script-level backup assertion -- see
# test_libsodium_interop.nim's own module doc comment for why this is a
# second, independent layer on top of that file's own doAssert, not the
# primary mechanism: the doAssert already turns the ONE skip() this suite
# can reach today into a hard `nim c -r` failure (which `set -e` inside
# `cmd` above already propagates, well before this point). This grep
# instead proves, from the run's own combined output, that no
# std/unittest `[SKIPPED]` marker of ANY kind slipped through --
# future-proofing against a skip() added somewhere else in the (now
# unit+interop-suite-scoped) compiled set with no SELLO_REQUIRE_LIBSODIUM
# awareness of its own. The standalone property files' own skip banner
# (printed via plain `echo` above, not std/unittest) is a different,
# unbracketed string and does not trip this grep.
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

print_tier_summary "scripts/test-libsodium.sh (-d:selloLibsodium)" \
  "unit+interop-suite scope only, not proptest-absence -- see scripts/test-libsodium.sh's own header comment"
