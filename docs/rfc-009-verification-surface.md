# RFC-009: verification surface — batch verify, Ed25519ph/ctx, cofactored semantics, and a WASM verify-only tier

Status: DRAFT (stage 1 — not yet through architect review)
Depends on: RFC-005 (gates); independent of RFC-007/008

## Why

sello's verify path is its no-asterisk half — public data only, no CT
obligation, fully testable — yet it is feature-thin against every peer:
no batch verification (the big throughput win dalek/Go-extensions ship),
no Ed25519ph/Ed25519ctx (RFC 8032 defines three variants; we ship one),
and exactly one verification semantics (strict cofactorless) in an
ecosystem that has learned — via ZIP215 and the consensus forks that
motivated it — that verifier DISAGREEMENT on edge-case signatures is
itself a vulnerability class. Finally, the VERIFY/SIGN split has an
unclaimed payoff: WASM is "unsupported for secrets" because
`private/ct.nim`'s barriers don't exist there — but the verify path has
no CT requirement AT ALL, so a verify-only WASM tier is coherent,
cheap, and turns a disclosed limitation into a scoped feature.

This RFC never touches a secret. Everything lands on the verify side of
the load-bearing split (Ed25519ph/ctx signing is composition over the
existing `signDetached` — the prehash and dom2 prefix are public data
folded into the challenge input, one audited formula change site:
`challenge.nim`).

## Load-bearing property

Batch verification agrees with serial verification on EVERY vector in
the full Wycheproof corpus plus the RFC 8032 KATs — including the
adversarial region where naive batching is unsound: a batch containing
any signature the serial verifier rejects must fail, and the
implementation must state (and test) which semantics the batch equation
uses, because batch and single verification are only guaranteed to agree
under COFACTORED semantics. That forces the semantics work (Part B) to
land with — not after — the batch work; slice 1's tracer is a batch of
Wycheproof vectors through the real facade entry point, red on one
planted forgery.

## Part A — batch verification

Random-linear-combination batch (the standard construction): needs
verifier-side randomness — design decision recorded in-slice between
`std/sysrand` (a `{.raises: [OSError].}` effect on a verify-path proc,
a first) and derandomized coefficients (hash of batch contents — no new
effect, but the security argument must be written out and reviewed).
Vartime throughout (public data); Straus/Pippenger multi-scalar mult in
`scalar.nim`'s vartime register, `Vartime`-suffixed per the standing
rule. API shape: `verifyBatch(openArray[(sig, msg, pk)]): bool` plus a
recorded decision on per-item fallback reporting (a failed batch
re-verifies serially to attribute — cost model documented).

## Part B — verification semantics, made explicit

- `verify` keeps today's RFC 8032 strict cofactorless behavior — the
  compatibility anchor; renaming it is a non-goal.
- `verifyCofactored` (ZIP215-shaped: cofactored equation, liberal on the
  edge cases ZIP215 admits) added, with the malleability/edge-case zoo
  documented in one place (small-order components, non-canonical
  encodings, mixed-order A/R) and pinned by a vector table covering the
  known divergence cases between the two semantics (the dalek/ZIP215
  test corpora are the source to vendor, provenance in NOTICE).
- The batch verifier's semantics is stated in its doc comment in as many
  words and tested for agreement against the matching serial variant.

## Part C — Ed25519ph and Ed25519ctx

RFC 8032 complete: `signPh`/`verifyPh` (SHA-512 prehash, dom2 flag 1)
and context-string variants (dom2 flag 0, 1-255 byte ctx). One audited
dom2-prefix implementation feeding `challenge.nim`'s shared formula —
sign and verify can't drift, the standing pattern. KATs from RFC 8032's
own ph/ctx vectors; property: ph/ctx signatures never cross-verify with
plain ones (domain separation pinned by test).

## Part D — WASM verify-only tier

A CI leg compiling the VERIFY-ONLY surface (`ed25519.verify`,
`pointDecode`, wire types — no signing, no x25519 secrets, no ristretto
secret roles) to wasm32 and running the KAT + Wycheproof corpus under a
wasm runtime (wasmtime/node — availability in the image is the slice's
spike). README's platform claim gains a "WASM: verification only"
row; the unsupported-for-secrets note stays for the other half, now
scoped instead of blanket.

## Slices (sketch)

1. Tracer: multi-scalar vartime mult + batch equation, a Wycheproof
   batch green / planted-forgery red through the facade.
2. Randomness/derandomization decision + the soundness property suite
   (random splits, adversarial batches, size-1 equivalence).
3. Cofactored serial variant + the divergence vector table; batch
   semantics bound to it.
4. Ed25519ph/ctx (dom2 in `challenge.nim`, KATs, cross-verify rejection
   properties).
5. WASM verify-only leg (spike first: toolchain + runtime in CI).
6. Facade/README/validation-map/CLAUDE.md; mutation batch for the new
   reject conditions (batch equation term drops, dom2 prefix flips).

## Risks / non-goals

- Randomness-in-verify is the one design fork likely to reach the
  maintainer (effect signature vs derandomization argument).
- Non-goals: renaming `verify`; precomputed-pubkey verification tables;
  signing on WASM; performance work beyond what batching inherently is
  (RFC-008 owns benchmarks — batch gets measured there once both land).
