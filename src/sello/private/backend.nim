## sello/private/backend.nim — pure-Nim secret-math backend (RFC-001).
##
## DANGER: every export here operates on unwrapped seed bytes and bypasses
## every `Keypair` guarantee — no derive-once invariant, no auto-wipe on
## scope exit. Application code should never import this module; use
## `sello.keypair` / `sello.sign` (via `sello/signing`) instead. It lives
## under `private/` for exactly that reason, the same social-contract
## treatment `ct.nim` gets.
##
## Seed-level primitives only, no `Keypair` knowledge. Builds strictly on
## `sello/field` + `sello/scalar` + nimcrypto's SHA-512 — deliberately
## never `sello/ed25519`, which stays a verify-only module that never
## touches a secret. `derivePublic`/`signDetached` below return raw
## `array[32/64, byte]`, not `PublicKey`/`Signature` (RFC-001 finding 9):
## even though those nominal types are one leaf import away
## (`sello/types`), the public wrapping is deliberately NOT applied here. This module is `private/`
## precisely because its seed-level contract bypasses every `Keypair`
## guarantee; adding the public nominal types here would blur that
## boundary rather than sharpen it. `signing.nim` is where seed bytes
## cross into the public API, so that is where `toPublicKey`/`toSignature`
## get called (one call site each, not sprinkled through this file).
##
## The libsodium adapter is the sibling `private/backend_sodium.nim`
## (RFC-001 slice 10); `signing.nim` dispatches between the two.
##
## ## `derivePublic`/`signDetached` contract (RFC-001 ledger finding 13)
##
## `derivePublic(seed)` is the one place a public key gets derived from
## scratch (`keypair(seed)`'s constructor call). `signDetached(seed,
## publicBytes, msg)` takes the already-derived public key as a parameter
## instead of re-deriving it internally -- `signing.sign` always has one on
## hand (`kp.public`, guaranteed by the `Keypair` invariant to already
## equal `derivePublic(kp.seed.bytes)`), so recomputing it inside
## `signDetached` on every call would be a second secret-scalar fixed-base
## scalarmult purely to reconstruct a value the caller already has. Both
## backends (this module and `private/backend_sodium.nim`) share the exact
## same two-secret/one-public three-argument `signDetached` signature so
## `signing.nim`'s dispatch stays a one-line import swap.

import nimcrypto/sha2
import sello/field
import sello/scalar
import sello/private/ct

{.push checks: off.}

func derivePublic*(seed: array[32, byte]): array[32, byte] =
  ## RFC 8032 §5.1.5 public-key derivation: A = clamp(SHA-512(seed)[0..31])
  ## * B, canonically encoded. `seed` and the intermediate hash/scalar are
  ## secret; both live in fixed-size stack arrays with zero heap
  ## allocation and are wiped via `ct.wipe` (volatile stores + compiler
  ## barrier — RFC-001 slice 8) once no longer needed, including the
  ## `Sha2Context` itself, which buffers the secret seed internally.
  ##
  ## The whole body runs under one `try`/`finally` (RFC-001 ledger finding
  ## 18, defensive, currently unreachable): every secret declared below is
  ## re-wiped in `finally` regardless of how the function exits, so an
  ## unwind between a secret's creation and its explicit wipe call below
  ## cannot leave it live in this stack frame. The explicit wipes on the
  ## happy path are not redundant with this net -- they still fire as soon
  ## as each secret is no longer needed rather than waiting for function
  ## exit; `finally`'s re-wipe of already-zeroed memory is a harmless
  ## no-op there.
  var h: array[64, byte]
  var sha: sha512
  var a: array[32, byte]
  try:
    sha.init()
    sha.update(seed)
    sha.finish(h)
    ct.wipe(sha)

    for i in 0 ..< 32: a[i] = h[i]
    clampScalar(a)

    result = pointEncode(geScalarmultBase(a))

    ct.wipe(h)
    ct.wipe(a)
  finally:
    ct.wipe(sha)
    ct.wipe(h)
    ct.wipe(a)

func signDetached*(seed: array[32, byte]; publicBytes: array[32, byte];
                    msg: openArray[byte]): array[64, byte] =
  ## RFC 8032 §5.1.6 detached signature (Ed25519: no context, no prehash):
  ##   h = SHA-512(seed); a = clamp(h[0..31]); prefix = h[32..63]
  ##   A = publicBytes                      -- see below, not re-derived
  ##   r = scReduce(SHA-512(prefix || msg))
  ##   R = [r]B
  ##   k = challenge(R, A, msg)     -- the same audited formula verify() uses
  ##   S = scMulAdd(k, a, r)
  ##   signature = R || S
  ## `seed`, `a`, `prefix`, `r`, and `h` are all secret; every one lives in a
  ## fixed-size stack array with zero heap allocation.
  ##
  ## `publicBytes` (RFC-001 ledger finding 13): the caller-supplied public
  ## key, used as `A` directly instead of re-deriving
  ## `pointEncode(geScalarmultBase(a))` here. `signing.nim`'s `Keypair`
  ## invariant (`kp.public == derive(kp.seed)`, enforced by `keypair(seed)`
  ## being the only constructor) exists precisely so `sign` can pass the
  ## already-cached public key instead of paying a second secret-scalar
  ## fixed-base scalarmult per signature -- this function does not
  ## re-verify that `publicBytes` actually matches `a`'s derived public
  ## key, the same way it does not re-verify that `seed` is the caller's
  ## real secret; both trust the seed-level caller (`signing.sign`, which
  ## reaches into `Keypair`'s own already-validated fields). `A` is public
  ## data either way, so accepting it as a parameter changes no secrecy
  ## boundary. Every secret intermediate below, including both
  ## `Sha2Context`s (each buffers a secret-containing block internally:
  ## `sha` the seed, `nonceSha` the prefix), is wiped via `ct.wipe`
  ## (volatile stores + compiler barrier — RFC-001 slice 8) once no longer
  ## needed.
  ##
  ## The whole body runs under one `try`/`finally` (RFC-001 ledger finding
  ## 18, defensive, currently unreachable) covering every secret declared
  ## below -- see `derivePublic`'s doc comment for why this is not
  ## redundant with the explicit wipe-as-soon-as-unneeded calls on the
  ## happy path.
  var h: array[64, byte]
  var sha: sha512
  var a: array[32, byte]
  var prefix: array[32, byte]
  var nonceHash: array[64, byte]
  var nonceSha: sha512
  var r: array[32, byte]
  try:
    sha.init()
    sha.update(seed)
    sha.finish(h)
    ct.wipe(sha)

    for i in 0 ..< 32: a[i] = h[i]
    clampScalar(a)

    for i in 0 ..< 32: prefix[i] = h[32 + i]
    ct.wipe(h)

    let A = publicBytes

    nonceSha.init()
    nonceSha.update(prefix)
    nonceSha.update(msg)
    nonceSha.finish(nonceHash)
    ct.wipe(nonceSha)
    ct.wipe(prefix)

    scReduce(r, nonceHash)
    ct.wipe(nonceHash)

    let R = pointEncode(geScalarmultBase(r))
    let k = challenge(R, A, msg)
    let S = scMulAdd(k, a, r)

    for i in 0 ..< 32: result[i] = R[i]
    for i in 0 ..< 32: result[32 + i] = S[i]

    ct.wipe(a)
    ct.wipe(r)
  finally:
    ct.wipe(sha)
    ct.wipe(h)
    ct.wipe(a)
    ct.wipe(prefix)
    ct.wipe(nonceHash)
    ct.wipe(nonceSha)
    ct.wipe(r)

{.pop.}
