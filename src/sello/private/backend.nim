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
## touches a secret. `derivePublic` below returns `array[32, byte]`
## (not the `PublicKey` name) purely to avoid that import: `PublicKey` is
## a plain (non-distinct) alias for the same type, so the two are
## interchangeable at every call site without conversion.
##
## The libsodium adapter is the sibling `private/backend_sodium.nim`
## (RFC-001 slice 10); `signing.nim` dispatches between the two.

import nimcrypto/sha2
import sello/field
import sello/scalar

{.push checks: off.}

func derivePublic*(seed: array[32, byte]): array[32, byte] =
  ## RFC 8032 §5.1.5 public-key derivation: A = clamp(SHA-512(seed)[0..31])
  ## * B, canonically encoded. `seed` and the intermediate hash/scalar are
  ## secret; both live in fixed-size stack arrays with zero heap
  ## allocation. The volatile-barriered wipe of `h`/`a` below (matching
  ## x25519.nim's ladder) lands with the CT-hardening milestone
  ## (RFC-001 slice 8) — the plain scrub here is best-effort only, exactly
  ## as x25519.nim's is today.
  var h: array[64, byte]
  var sha: sha512
  sha.init()
  sha.update(seed)
  sha.finish(h)

  var a: array[32, byte]
  for i in 0 ..< 32: a[i] = h[i]
  clampScalar(a)

  result = pointEncode(geScalarmultBase(a))

  # Best-effort scrub of the expanded hash and clamped scalar.
  for i in 0 ..< 64: h[i] = 0
  for i in 0 ..< 32: a[i] = 0

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
  ## call, matching RFC-001's "no persistent expanded-key API" design. The
  ## volatile-barriered wipe of every intermediate below lands with the
  ## CT-hardening milestone (RFC-001 slice 8); the plain scrub here is
  ## best-effort only, exactly as `derivePublic` and x25519.nim's ladder are
  ## today.
  var h: array[64, byte]
  var sha: sha512
  sha.init()
  sha.update(seed)
  sha.finish(h)

  var a: array[32, byte]
  for i in 0 ..< 32: a[i] = h[i]
  clampScalar(a)

  var prefix: array[32, byte]
  for i in 0 ..< 32: prefix[i] = h[32 + i]

  let A = pointEncode(geScalarmultBase(a))

  var nonceHash: array[64, byte]
  var nonceSha: sha512
  nonceSha.init()
  nonceSha.update(prefix)
  nonceSha.update(msg)
  nonceSha.finish(nonceHash)

  var r: array[32, byte]
  scReduce(r, nonceHash)

  let R = pointEncode(geScalarmultBase(r))
  let k = challenge(R, A, msg)
  let S = scMulAdd(k, a, r)

  for i in 0 ..< 32: result[i] = R[i]
  for i in 0 ..< 32: result[32 + i] = S[i]

  # Best-effort scrub of every secret intermediate.
  for i in 0 ..< 64: h[i] = 0
  for i in 0 ..< 32: a[i] = 0
  for i in 0 ..< 32: prefix[i] = 0
  for i in 0 ..< 64: nonceHash[i] = 0
  for i in 0 ..< 32: r[i] = 0

{.pop.}
