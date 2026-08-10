# sello.nimble — thin ecosystem-compat manifest for sello
# Pure-Nim Curve25519 cryptographic library (ed25519 + X25519)
#
# milpa (milpa.kdl/milpa.lock) is the authoritative resolver for
# development: it pins nimcrypto to a commit SHA + content hash and drives
# the dev loop via scripts/test.sh, scripts/test-libsodium.sh, scripts/ct.sh.
# This file exists only so sello resolves normally for nimble-ecosystem
# consumers (`nimble install`, `requires "sello"` in a downstream .nimble);
# it carries no task definitions -- those live in scripts/ now.

version       = "0.3.1"
author        = "corey"
description   = "Pure-Nim ed25519 + X25519 (Curve25519). No FFI in the core; optional libsodium signer adapter. RFC 8032, RFC 7748."
license        = "Apache-2.0"
srcDir         = "src"
backend        = "c"

# Keywords for discoverability
# pure-Nim ed25519 X25519 Curve25519 EdDSA RFC 8032 RFC 7748 no FFI

requires "nim >= 2.2.10"
requires "nimcrypto >= 0.7.3"

# Optional libsodium FFI signer adapter (behind -d:selloLibsodium)
# requires "libsodium"  # conditional, see ed25519.nim
