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

task test, "Run test suite":
  exec "nim c -r tests/unit/test_field.nim"
  exec "nim c -r tests/unit/test_ed25519.nim"
  exec "nim c -r tests/unit/test_x25519.nim"
  exec "nim c -r tests/unit/test_wycheproof.nim"
  exec "nim c -r tests/unit/test_wycheproof_x25519.nim"
