# sello.nimble — package manifest for sello
# Pure-Nim Curve25519 cryptographic library (ed25519 + X25519)

version       = "0.1.0"
author        = "corey"
description   = "Pure-Nim ed25519 + X25519 (Curve25519). No FFI. RFC 8032, RFC 7748."
license        = "Apache-2.0"
srcDir         = "src"
backend        = "c"

# Keywords for discoverability
# pure-Nim ed25519 X25519 Curve25519 EdDSA RFC 8032 RFC 7748 no FFI

requires "nim >= 2.2.10"
requires "nimcrypto >= 0.4.0"

# Optional libsodium FFI signer adapter (behind -d:selloLibsodium)
# requires "libsodium"  # conditional, see ed25519.nim

# Single source of truth for "which unit test files make up the suite" --
# consumed by `test` below and, from RFC-001 slice 10 on, by
# `testLibsodium` too (same files, extra `-d:` defines). Two
# hand-maintained lists would silently drift; this is the one list.
const unitTestFiles = [
  "tests/unit/test_field.nim",
  "tests/unit/test_scalar.nim",
  "tests/unit/test_ct.nim",
  "tests/unit/test_signing.nim",
  "tests/unit/test_ed25519.nim",
  "tests/unit/test_facade.nim",
  "tests/unit/test_x25519.nim",
  "tests/unit/test_wycheproof.nim",
  "tests/unit/test_wycheproof_x25519.nim",
  "tests/unit/test_libsodium_interop.nim",
]

proc runUnitTests(extraDefines = "") =
  for f in unitTestFiles:
    exec "nim c " & extraDefines & " -r " & f

task test, "Run test suite":
  runUnitTests()

# RFC-001 slice 10: same unitTestFiles list as `test`, recompiled with
# -d:selloLibsodium so signing.nim dispatches to the libsodium FFI adapter
# (private/backend_sodium.nim) instead of the pure-Nim backend, and
# test_libsodium_interop.nim's real bidirectional interop checks compile
# in. Requires libsodium-devel -- run inside the sello-owned `Containerfile`
# image (podman build -t sello-libsodium -f Containerfile .), not the base
# Nim image. `sello/ed25519.verify` is never affected: it has no backend
# dispatch and stays pure-Nim under this flag too.
task testLibsodium, "Run test suite against the libsodium adapter backend (-d:selloLibsodium)":
  runUnitTests("-d:selloLibsodium")

# RFC-001 slice 9: dudect-style constant-time timing harness. Deliberately
# a SEPARATE task from `test` -- it is statistical and environment-
# sensitive (t-statistics, not a fixed pass/fail vector), takes much longer
# (>= 1e6 samples/class per target), and its honest interpretation belongs
# in docs/ct-results.md, not in the green/red signal of the main suite.
task ct, "Run tests/ct dudect constant-time timing harness (not part of `test`)":
  exec "nim c -d:release --outdir:build tests/ct/ct_main.nim"
  let bin = "build/ct_main"
  if findExe("taskset").len > 0:
    echo "pinning to core 0 via taskset"
    exec "taskset -c 0 " & bin
  else:
    echo "taskset not found -- running WITHOUT CPU pinning (see docs/ct-results.md)"
    exec bin
