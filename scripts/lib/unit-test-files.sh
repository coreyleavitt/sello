#!/usr/bin/env bash
# scripts/lib/unit-test-files.sh — single source of truth for "which unit
# test files make up the suite" (round-2 finding 25). `source`d by both
# scripts/test.sh and scripts/test-libsodium.sh, so the two matrices read
# the same array instead of maintaining independently-typed-out copies
# that a hand edit to one could silently leave out of sync with the
# other. Not a standalone script -- has no shebang effect, only declares
# `unit_test_files` (and `skipped_property_files`, RFC-003 slice 2 item 4)
# into the sourcing shell.
unit_test_files=(
  tests/unit/test_field.nim
  tests/unit/test_scalar.nim
  tests/unit/test_ct.nim
  tests/unit/test_signing.nim
  tests/unit/test_ed25519.nim
  tests/unit/test_facade.nim
  tests/unit/test_x25519.nim
  tests/unit/test_wycheproof.nim
  tests/unit/test_wycheproof_x25519.nim
  tests/unit/test_libsodium_interop.nim
  tests/unit/test_properties_field.nim
  tests/unit/test_properties_scalar.nim
  tests/unit/test_properties_signing.nim
  tests/unit/test_properties_x25519.nim
)

# proptest is an OPTIONAL milpa dep (see scripts/test.sh's header comment):
# a fresh clone's plain `milpa fetch` never populates `_deps/proptest`, so
# the four `test_properties_*.nim` files above fail to compile with a bare
# "cannot open file: proptest" error mid-loop -- there is no graceful
# skip today (RFC-003 slice 2 item 4). Detect proptest's presence HERE,
# once, so both scripts/test.sh and scripts/test-libsodium.sh (which both
# source this file) can filter the property suites out of the list they
# actually compile, in the same self-skip register test_libsodium_interop
# already uses for the libsodium-adapter-absent case (a loud runtime
# `skip()` line rather than a compile failure -- the difference here is
# the gate has to happen in bash, before `nim c` ever runs, since a
# missing import is a compile-time failure, not a runtime branch).
skipped_property_files=()
if [[ ! -d "$(dirname "${BASH_SOURCE[0]}")/../../_deps/proptest" ]]; then
  filtered_test_files=()
  for f in "${unit_test_files[@]}"; do
    case "$f" in
      tests/unit/test_properties_*.nim) skipped_property_files+=("$f") ;;
      *) filtered_test_files+=("$f") ;;
    esac
  done
  unit_test_files=("${filtered_test_files[@]}")
fi
