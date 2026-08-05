## sello — pure-Nim Curve25519: ed25519 signatures (RFC 8032) and
## X25519 key exchange (RFC 7748). No FFI.
##
## This module is the supported public surface:
##
## ```nim
## import sello
## if verify(sig, message, pk): ...
## ```
##
## The submodules (`sello/field`, `sello/scalar`, `sello/ed25519`) are
## implementation layers; importing them directly works but carries no
## API-stability promise.

import sello/ed25519
import sello/x25519

export PublicKey, SecretKey, Signature, verify
export x25519.x25519, x25519Base, X25519BasePoint
