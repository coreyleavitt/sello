# RFC-010: the scalar layer — CT mod-L inversion and a public scalar API (OPRF client / Schnorr enablement)

Status: DRAFT (stage 1 — not yet through architect review)
Depends on: RFC-005 (the five-instrument journey every new secret path
must complete: dudect target, taint target, disasm root, register entry,
mutation batch — this RFC is the first NEW secret-holding code built
under the full apparatus, and is in part a test of it); RFC-007
desirable (the audit certifying the new kernel) but not required

## Why

`ristretto.nim`'s own honesty clause names the gap: sello ships the
GROUP, not scalar arithmetic — `scMulAdd` is deliberately unexported and
mod-L inversion exists nowhere, so v1 serves commitment/DH/blinding
shapes and an OPRF SERVER, but not an OPRF client's unblind, a Schnorr
prover, or a VRF. This is the most common "wanted to use sello, could
not" shape, and the missing piece is one primitive (constant-time
inversion mod L) plus a hygienic public scalar type. It is also the
highest-CT-risk work remaining on the roadmap — which is exactly why it
should be built now, under the completed instrument suite, rather than
before it existed.

## Load-bearing property

A constant-time mod-L scalar inversion, correct across the full domain
(property: `s * inv(s) ≡ 1 (mod L)` for random and boundary scalars,
differentially checked against an independent bignum oracle; `inv(0)`'s
contract explicitly decided and pinned), that completes the ENTIRE
five-instrument journey — a dudect fixed-vs-random-secret target, a
taint target with its zero-annotation arc and register `DeclassId`s, a
`{.noinline.}` disasm root with per-backend baselines, an A7 register
entry with all four coverage cells, and a killing mutation batch — and
is then consumed end-to-end by a worked OPRF-client unblind test through
the public facade. Slice 1's tracer: the inversion primitive green on
the correctness property; the instrument journey is what the middle
slices exist for.

## Part A — the inversion primitive

Candidates, decided by an in-slice spike with the trade recorded:
- **Fermat (addition-chain exponentiation by L-2):** branch-free by
  construction from existing CT primitives (`scMulAdd`-style Montgomery
  or plain schoolbook mod-L multiplication — note sello has scReduce/
  scMulAdd but NO general scalar-scalar mod-L multiply; that primitive
  is itself new CT surface and part of this Part), fixed ~250-mult
  chain, slow but uniform. The conservative default.
- **Bernstein-Yang safegcd (divsteps):** the modern fast CT inversion;
  substantially more new arithmetic (with its own carry/bound proofs —
  `symex_reduce`-class obligations). Adopted only if the spike shows
  Fermat's cost matters for the target protocols; otherwise recorded as
  the future upgrade.
Vartime inversion (`...InvertVartime`) is NOT shipped in v1 — no
consumer in the target protocols inverts public scalars; adding it later
is additive.

## Part B — the public scalar type

`scalar.SecretScalar` stays unexported (its doc comment's reasoning
holds: it is the hygiene-free type-gate for the signer's internals). The
public face is a new role type in the established register —
`RistrettoScalar`-style (name decided in-slice): one-field object,
`secretHooks`-wiped, canonical-residue invariant, constructors mirroring
`toRistrettoStaticSecret`/`Wide`'s reject-vs-reduce split, `toBytes`,
`wipe`, and the operations the target protocols need: mul, add, invert
(all CT, all over the new mod-L multiply), plus interop with the
existing ristretto scalarmult entry points. The facade export is the
ENUMERATED list per the standing precedent; what stays unexported is
listed with rationale (the bare-array `scMulAdd` remains internal).

## Part C — worked consumers as tests (the liveness proof)

Two end-to-end suites through `import sello` only, the Pedersen-scenario
precedent: (i) a full OPRF round — client blinds with r, server
evaluates with k (existing), client unblinds with `invert(r)`, result
equals direct k·H(x); (ii) a Schnorr identification/signature response
`z = k + c·s` with verify-side check — proving the exported surface is
sufficient, not just present. (A full RFC-9497 OPRF or a Schnorr
signature SCHEME with its own wire format remains a non-goal — these are
capability proofs, not new protocol APIs.)

## Slices (sketch)

1. Tracer: mod-L multiply + Fermat inversion, correctness property vs
   bignum oracle, boundary scalars (0, 1, L-1, L, L+1, 2^255-1 inputs
   through the reduce path), `inv(0)` contract pinned.
2. Carry/bound obligations for the new multiply (`symex_reduce`
   register: per-step lemmas machine-checked, whole-chain honestly
   attempted).
3. The public scalar type + facade export + api-surface baseline update
   + negative fixtures (role-type misuse).
4. Instrument journey: taint arc + register entries + DeclassIds.
5. Instrument journey: dudect target + disasm root + baselines +
   mutation batch (chain-step drops, reduction flips, inversion
   exponent bit flips).
6. Worked consumers (OPRF round, Schnorr response) end-to-end.
7. Docs/claims: ristretto.nim's non-goal paragraph REWRITTEN (the
   honest boundary moves), README/CLAUDE.md/validation-map.

## Risks / non-goals

- New CT arithmetic is the point and the risk; the escalation rule from
  RFC-005 (an instrument finding in new code closes the slice red)
  applies with full force, and slice ordering keeps the primitive
  unexported until the journey completes — no dormant public surface.
- Non-goals: vartime inversion, safegcd (unless the spike forces it), a
  full OPRF/VOPRF protocol API, Schnorr as a signature scheme, ed25519
  scalar API exposure (ristretto-side only in v1 — the ed25519 signer
  needs none of it).
