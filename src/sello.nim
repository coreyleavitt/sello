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
## doAssert kp.public.verify("hello", sig)
## ```
##
## `sign` takes the `Keypair` first (`kp.sign(msg)`) and `verify` takes the
## public key first (`pk.verify(msg, sig)`, matching RFC 8032's own
## VERIFY(pk, M, sig) notation and ed25519-dalek's
## `VerifyingKey::verify(message, signature)`) -- both actor-first,
## UFCS-friendly, and matching `x25519`'s own actor-first argument order.
##
## Loading a PERSISTED key whose storage carries both halves (e.g.
## OpenSSH's/libsodium's `seed(32) ‖ publicKey(32)` layout) goes through
## `keypair(seed, expectedPublic): Option[Keypair]` (janus consumer
## finding 2), which re-derives the public key and returns `none` on a
## mismatch instead of silently signing under a public key the caller
## never presented -- see `signing.nim`'s doc comment on that overload,
## including the `move(loaded.get())` extraction idiom for the move-only
## `Keypair`. Plain `keypair(seed)` remains the constructor for seed-only
## storage.
##
## Effects are declared, not inferred (janus consumer finding 3): the
## whole surface is `{.raises: [], gcsafe.}` by compiler-checked
## annotation, except the five fresh-secret constructors (`keypair()`,
## `x25519StaticSecret`, `x25519EphemeralSecret`, `x25519StaticPair`,
## `x25519EphemeralPair`), which are `{.raises: [OSError].}` (fail-fast on
## a broken CSPRNG), and -- under `-d:selloLibsodium` only -- the
## sign/keygen path, which adds `SodiumInitError` (exported below on that
## backend).
##
## `PublicKey`, `Signature`, and X25519's `X25519Public` are nominal
## (`distinct array`) wire types, not interchangeable aliases: a
## `PublicKey` cannot be passed where an `X25519Public` is expected or vice
## versa, even though both are 32 raw bytes underneath (RFC-001 finding
## 9). X25519's secret-holding roles are one-field objects rather than
## `distinct array` (see `x25519.nim`'s module doc comment for why) -- role
## confusion between secret and sendable X25519 material is a compile
## error the same way the cross-algorithm mixup is (RFC-001 ledger #29:
## role-typed wrappers, not one `X25519Key` covering every role).
##
## X25519 additionally splits its SECRET role in two, mirroring
## x25519-dalek's `StaticSecret`/`EphemeralSecret` in this library's own
## vocabulary: `X25519StaticSecret` is a reusable identity (deliberately
## copyable -- unlike `Seed`/`Keypair`, there is no paired invariant a
## second live copy could violate); `X25519EphemeralSecret` is single-use
## by construction (move-only, `x25519` takes it by `sink` -- reuse is a
## compile error, verified against checked-in negative fixtures, not just
## documented). Prefer the ephemeral form unless you specifically need a
## reusable/static X25519 identity (e.g. a long-lived server key) --
## `x25519EphemeralPair()` (fresh secret plus its derived public value in
## one call) is the primary way to get one; a fresh ephemeral per exchange
## is the safer default and costs nothing but one call. `x25519StaticPair()`
## is the equivalent bundled constructor for the static role (RFC-003
## slice 1): same fresh-secret-plus-public-value shape, for the cases that
## do need a reusable identity.
##
## `toPublicKey`/`toSignature`/`toX25519StaticSecret`/`toX25519Public`/`toBytes`
## convert to/from raw bytes at the point a value crosses the wire
## (decoding, serialization, persistence); the bare `Type(bytes)` cast
## works too for the `distinct` types (`PublicKey`, `Signature`,
## `X25519Public`). `X25519EphemeralSecret` deliberately has NEITHER a
## from-bytes constructor NOR a `toBytes` overload -- freshness-by-
## construction and unpersistability are its whole contract, not gaps (see
## `x25519.nim`'s doc comment on the type). `wipe` is overloaded over
## `Seed` (signing.nim), `X25519StaticSecret`/`X25519EphemeralSecret`/
## `X25519Shared` (x25519.nim), and a generic raw `array[32, byte]`
## (sello/wipe) -- the same audited volatile-store primitive for every
## secret shape the public API hands back to a caller (RFC-001 finding
## 11).
##
## **Ristretto255** (RFC 9496, `sello/ristretto`) is a prime-order group
## quotienting Curve25519's cofactor-8 Edwards curve -- every
## `RistrettoPoint` names one group element with exactly one canonical
## 32-byte encoding, closing the cofactor-malleability class of bug a raw
## curve point invites. `ristrettoDecode`/`ristrettoEncode`/`==`/the
## one-way map (`ristrettoFromUniformBytes`) are CT by construction; the
## final accept/reject verdict is inherently caller-visible (see
## `ristretto.nim`'s module doc for the full CT-posture writeup). Scalar
## multiplication ships in both registers behind the same secret-scalar
## type gate the rest of this library uses:
## `ristrettoScalarmultVartime` accepts only a bare `array[32, byte]`
## (verify-register protocol steps, the scalar public), while
## `ristrettoScalarmultBase`/`ristrettoScalarmult` take the ristretto255
## secret-scalar role types -- `RistrettoStaticSecret` (reusable, a
## Pedersen key or OPRF server key) and `RistrettoEphemeralSecret`
## (single-use, move-only, the ElGamal/ECIES-style DH-share role) --
## mirroring X25519's static/ephemeral split. `RistrettoPoint` itself is
## freely copyable with no `wipe` overload: elements are PUBLIC-register
## values in every protocol this serves (a Pedersen commitment, an OPRF
## blinded element) -- the secret is the scalar that derived it, and that
## scalar's role type owns the hygiene. This module ships the GROUP, not
## a scalar-arithmetic API: a Schnorr response or an OPRF client's
## unblind step both need mod-L scalar operations this library
## deliberately does not expose at the facade -- see `sello/ristretto`'s
## module doc comment for the honest boundary.
##
## The submodules (`sello/field`, `sello/scalar`, `sello/wire`,
## `sello/wipe`, `sello/challenge`, `sello/ed25519`, `sello/ristretto`) are
## implementation layers; importing them directly works but carries no
## API-stability promise.

import sello/wire
import sello/wipe
import sello/ed25519
import sello/x25519
import sello/signing
import sello/ristretto

export wire.PublicKey, wire.Signature, verify
export wire.toPublicKey, wire.toSignature, wire.toBytes
export wire.`==`, wire.`$`, wire.hash
export wipe.wipe
export x25519.x25519, x25519Base, X25519BasePoint
export x25519.toBytes
export x25519.`==`, x25519.`$`, x25519.hash
export x25519.wipe
export x25519.X25519StaticSecret, x25519.X25519Public, x25519.X25519Shared
export x25519.x25519StaticSecret, x25519.toX25519StaticSecret, x25519.toX25519Public
export x25519.x25519StaticPair
export x25519.X25519EphemeralSecret, x25519.x25519EphemeralSecret
export x25519.x25519EphemeralPair
export signing.Seed, signing.Keypair, signing.toSeed
export signing.keypair, signing.sign
export signing.wipe
export signing.public, signing.toSeedBytes
# Ristretto255 (RFC 9496) -- ENUMERATED symbol-by-symbol (RFC-004 slice
# 8d), matching this file's own facade-surface precedent: a concrete list
# `test_facade.nim`'s reachability suite checks against, not a wildcard
# `export ristretto`. `ristretto.ristrettoUnchecked` (the raw-`GeP3`
# construction door) and `scalar.SecretScalar` are DELIBERATELY absent --
# both bypass invariants this facade exists to hold.
export ristretto.RistrettoPoint, ristretto.RistrettoEncoded
export ristretto.RistrettoStaticSecret, ristretto.RistrettoEphemeralSecret
export ristretto.RistrettoIdentity, ristretto.RistrettoBasePoint
export ristretto.ristrettoDecode, ristretto.ristrettoEncode
export ristretto.`+`, ristretto.`-`, ristretto.`==`
export ristretto.ristrettoScalarmultBase, ristretto.ristrettoScalarmult
export ristretto.ristrettoScalarmultVartime
export ristretto.ristrettoFromUniformBytes
export ristretto.ristrettoStaticSecret, ristretto.ristrettoStaticPair
export ristretto.toRistrettoStaticSecret, ristretto.toRistrettoStaticSecretWide
export ristretto.ristrettoEphemeralSecret, ristretto.ristrettoEphemeralPair
export ristretto.toRistrettoEncoded, ristretto.toBytes
export ristretto.wipe
export ristretto.`$`, ristretto.hash
when defined(selloLibsodium):
  # `sign`/`keypair` declare `SodiumInitError` in their `{.raises.}`
  # effects on this backend; export the type so a caller can catch it by
  # name through `import sello` alone.
  export signing.SodiumInitError
# Neither `Seed` nor `X25519StaticSecret`/`X25519EphemeralSecret`/
# `X25519Shared` has an `==` at all (RFC-002 slice 1 removed `Seed`'s old
# test/tooling-only one): all four hold secret material, so this library
# deliberately does not offer even a vartime comparison for them -- a
# caller confirming two secrets/DH parties agree compares via `toBytes`
# instead (see the X25519 example above -- for `X25519EphemeralSecret`
# specifically, `toBytes` doesn't exist either, so the shared *output* is
# what gets compared, never the ephemeral secret itself). `PublicKey`/
# `Signature`/`X25519Public` are the opposite case: their `==` (and now
# `hash`, for Table/HashSet keying) IS exported above, because comparing
# or hashing a PUBLIC value is a normal, expected operation with no CT
# requirement of its own.
#
# Ristretto255's secret role types (`RistrettoStaticSecret`/
# `RistrettoEphemeralSecret`) follow the same "no `==` on a secret" rule as
# `X25519StaticSecret`/`X25519EphemeralSecret` above -- neither has one, and
# `RistrettoEphemeralSecret` has no `toBytes` either, for the identical
# unpersistable-by-design reason. `RistrettoPoint`, by contrast, DOES have
# `==` (exported above) despite holding no secret of its own -- it is a
# PUBLIC group element (see `ristretto.nim`'s module doc), and its `==` is
# CT rather than vartime, unlike every other `==` this facade exports:
# ristretto255 elements are routinely compared in timing-sensitive
# positions (a DH-share or PAKE-style equality check on a value derived
# from a live secret) that `PublicKey`/`Signature`/`X25519Public` never
# see. `RistrettoEncoded`'s own `==` (exported above too) is the ordinary
# vartime byte-compare -- see `ristretto.nim`'s module doc and
# `RistrettoEncoded`'s own doc comment for the encode-then-compare timing
# trap this creates (an operator cannot carry a `Vartime` suffix, so the
# register switch between the two `==`s is silent at the call site).
