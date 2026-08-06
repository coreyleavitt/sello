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
  var h: array[64, byte]
  var sha: sha512
  sha.init()
  sha.update(seed)
  sha.finish(h)
  ct.wipe(sha)

  var a: array[32, byte]
  for i in 0 ..< 32: a[i] = h[i]
  clampScalar(a)

  result = pointEncode(geScalarmultBase(a))

  ct.wipe(h)
  ct.wipe(a)

func signDetached*(seed: array[32, byte]; msg: openArray[byte]): array[64, byte] =
  ## RFC 8032 §5.1.6 detached signature (Ed25519: no context, no prehash):
  ##   h = SHA-512(seed); a = clamp(h[0..31]); prefix = h[32..63]
  ##   A = [a]B
  ##   r = scReduce(SHA-512(prefix || msg))
  ##   R = [r]B
  ##   k = challenge(R, A, msg)     -- the same audited formula verify() uses
  ##   S = scMulAdd(k, a, r)
  ##   signature = R || S
  ## `seed`, `a`, `prefix`, `r`, and `h` are all secret; every one lives in a
  ## fixed-size stack array with zero heap allocation. `A` is derived here
  ## from `a` directly (one extra fixed-base scalarmult), not by a second
  ## SHA-512(seed) call — `signDetached` carries no `Keypair` knowledge (per
  ## the module doc comment) and the seed is re-expanded exactly once per
  ## call, matching RFC-001's "no persistent expanded-key API" design. Every
  ## secret intermediate below, including both `Sha2Context`s (each buffers
  ## a secret-containing block internally: `sha` the seed, `nonceSha` the
  ## prefix), is wiped via `ct.wipe` (volatile stores + compiler barrier —
  ## RFC-001 slice 8) once no longer needed.
  var h: array[64, byte]
  var sha: sha512
  sha.init()
  sha.update(seed)
  sha.finish(h)
  ct.wipe(sha)

  var a: array[32, byte]
  for i in 0 ..< 32: a[i] = h[i]
  clampScalar(a)

  var prefix: array[32, byte]
  for i in 0 ..< 32: prefix[i] = h[32 + i]
  ct.wipe(h)

  let A = pointEncode(geScalarmultBase(a))

  var nonceHash: array[64, byte]
  var nonceSha: sha512
  nonceSha.init()
  nonceSha.update(prefix)
  nonceSha.update(msg)
  nonceSha.finish(nonceHash)
  ct.wipe(nonceSha)
  ct.wipe(prefix)

  var r: array[32, byte]
  scReduce(r, nonceHash)
  ct.wipe(nonceHash)

  let R = pointEncode(geScalarmultBase(r))
  let k = challenge(R, A, msg)
  let S = scMulAdd(k, a, r)

  for i in 0 ..< 32: result[i] = R[i]
  for i in 0 ..< 32: result[32 + i] = S[i]

  ct.wipe(a)
  ct.wipe(r)

{.pop.}
