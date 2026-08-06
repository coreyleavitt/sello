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

{.pop.}
