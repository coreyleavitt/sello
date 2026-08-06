## sello — pure-Nim Curve25519: ed25519 signatures (RFC 8032) and
## X25519 key exchange (RFC 7748). No FFI.
##
## This module is the supported public surface:
##
## ```nim
## import sello
##
## let kp = keypair()                    # fresh identity (std/sysrand)
## let sig = kp.sign("hello")            # deterministic, total
## doAssert verify(sig, "hello", kp.public)
## ```
##
## `sign` takes the `Keypair` first (`kp.sign(msg)`, UFCS-friendly, matching
## `x25519`'s actor-first precedent); `verify` takes the signature first
## (`verify(sig, msg, pk)`) because it shipped first and is already relied
## on -- a known, deliberate asymmetry, not an oversight (see RFC-001's
## non-goals).
##
## The submodules (`sello/field`, `sello/scalar`, `sello/ed25519`) are
## implementation layers; importing them directly works but carries no
## API-stability promise.

import sello/ed25519
import sello/x25519
import sello/signing

export PublicKey, Signature, verify
export x25519.x25519, x25519Base, X25519BasePoint
export signing.Seed, signing.Keypair, signing.toSeed
export signing.keypair, signing.sign, signing.wipe
export signing.public, signing.seed
