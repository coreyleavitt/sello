#!/usr/bin/env bash
# scripts/lib/unit-test-files.sh — single source of truth for "which unit
# test files make up the suite" (round-2 finding 25). `source`d by both
# scripts/test.sh and scripts/test-libsodium.sh, so the two matrices read
# the same array instead of maintaining independently-typed-out copies
# that a hand edit to one could silently leave out of sync with the
# other. Not a standalone script -- has no shebang effect, only declares
# `unit_test_files` into the sourcing shell.
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
)
