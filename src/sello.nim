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
## `PublicKey`, `Signature`, and X25519's `X25519Public` are nominal
## (`distinct array`) wire types, not interchangeable aliases: a
## `PublicKey` cannot be passed where an `X25519Public` is expected or vice
## versa, even though both are 32 raw bytes underneath (RFC-001 finding
## 9). X25519's other two roles, `X25519Secret` and `X25519Shared`, are
## one-field objects rather than `distinct array` (see `x25519.nim`'s
## module doc comment for why) -- role confusion between secret and
## sendable X25519 material is a compile error the same way the
## cross-algorithm mixup is (RFC-001 ledger #29, revisited: three role
## types, not one `X25519Key` covering all three).
## `toPublicKey`/`toSignature`/`toX25519Secret`/`toX25519Public`/`toBytes`
## convert to/from raw bytes at the point a value crosses the wire
## (decoding, serialization, persistence); the bare `Type(bytes)` cast
## works too for the `distinct` types (`PublicKey`, `Signature`,
## `X25519Public`). `wipe` is overloaded over `Seed` (signing.nim),
## `X25519Secret`/`X25519Shared` (x25519.nim), and a generic raw
## `array[32, byte]` (sello/types) -- the same audited volatile-store
## primitive for every secret shape the public API hands back to a
## caller (RFC-001 finding 11).
##
## The submodules (`sello/field`, `sello/scalar`, `sello/types`,
## `sello/ed25519`) are implementation layers; importing them directly
## works but carries no API-stability promise.

import sello/types
import sello/ed25519
import sello/x25519
import sello/signing

export types.PublicKey, types.Signature, verify
export types.toPublicKey, types.toSignature, types.toBytes
export types.`==`, types.`$`
export types.wipe
export x25519.x25519, x25519Base, X25519BasePoint
export x25519.toBytes
export x25519.`==`, x25519.`$`
export x25519.wipe
export x25519.X25519Secret, x25519.X25519Public, x25519.X25519Shared
export x25519.x25519Secret, x25519.toX25519Secret, x25519.toX25519Public
export signing.Seed, signing.Keypair, signing.toSeed
export signing.keypair, signing.sign
export signing.wipe
export signing.public, signing.seed
# `Seed`'s own `==` is deliberately NOT re-exported here (see
# sello/signing: vartime, tests/tooling only) -- unlike `PublicKey`/
# `Signature`/`X25519Public`, whose `==` is exported above because
# comparing two PUBLIC values is a normal, expected operation with no CT
# requirement of its own. `X25519Secret`/`X25519Shared` have no `==` at
# all (not just an unexported one): both hold secret material, so this
# library deliberately does not offer even a vartime comparison for them
# -- a caller confirming two DH parties agree compares via `toBytes`
# instead (see the X25519 example above), the same way `Seed`'s own
# vartime `==` stays test/tooling-only rather than public.
