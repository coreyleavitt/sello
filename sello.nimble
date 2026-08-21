# sello.nimble — thin ecosystem-compat manifest for sello
# Pure-Nim Curve25519 cryptographic library (ed25519 + X25519)
#
# milpa (milpa.kdl/milpa.lock) is the authoritative resolver for
# development, driving the dev loop via scripts/test.sh,
# scripts/test-libsodium.sh, scripts/ct.sh. sello has zero resolved
# dependencies on this consumption path as of RFC-006 (in-house SHA-512
# retired the nimcrypto dependency); proptest remains, optional and
# dev-only.
# This file exists only so sello resolves normally for nimble-ecosystem
# consumers (`nimble install`, `requires "sello"` in a downstream .nimble);
# it carries no task definitions -- those live in scripts/ now.

version       = "0.5.0"
author        = "corey"
description   = "Pure-Nim ed25519 + X25519 (Curve25519). No FFI in the core; optional libsodium signer adapter. RFC 8032, RFC 7748."
license        = "Apache-2.0"
srcDir         = "src"
backend        = "c"

# Keywords for discoverability
# pure-Nim ed25519 X25519 Curve25519 EdDSA RFC 8032 RFC 7748 no FFI

requires "nim >= 2.2.10"

# Optional libsodium FFI signer adapter (behind -d:selloLibsodium)
# requires "libsodium"  # conditional, see ed25519.nim
