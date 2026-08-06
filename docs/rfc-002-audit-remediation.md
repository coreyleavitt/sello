# RFC-002: Design-audit remediation

- **Status:** approved by Corey 2026-08-06 ("fix all of these to the full standard")
- **Scope source:** post-RFC-001 `/architect` compromise audit (three lenses: disclosed-exemption
  re-litigation, fresh-eyes design hunt, verification-infrastructure audit). Nine confirmed
  compromises against the PhD-CS bar; all six remediation groups approved, including mutation
  testing.
- **Handoff doc:** `docs/rfc-002-audit-remediation.handoff.md` (live progress ledger — read it
  first when resuming).
- **Standing orders:** identical to RFC-001 (PhD-CS bar; no consumers yet, breaking changes
  sanctioned; genuine forks escalate; wrong-spec assumptions escalate; no commits without
  Corey's approval — RFC-001 stage-4 precedent is per-slice commits after gates pass, which
  Corey has already endorsed for remediation work by directing "fix all of these").

## Motivation

RFC-001's review loop reached its floor, but a dedicated compromise audit (triggered by the
X25519Key precedent: a "disclosed, defensible trade-off" that collapsed into a clear best
design when pushed) found further places where the shipped library settles below the bar.
Each item below carries the audit's verdict and the decided design — there are no open forks
in this RFC; every decision was resolved at approval time.

## Slices

### Slice 1 — API coherence (breaking; the facade's own conventions, applied everywhere)

1. **`verify` goes actor-first.** New shape: `verify(pk: PublicKey; msg: openArray[byte];
   sig: Signature): bool` (+ `string` overload) — call shape `pk.verify(msg, sig)`,
   parameter order matching RFC 8032's VERIFY(pk, M, sig) notation and ed25519-dalek's
   `VerifyingKey::verify(message, signature)`. The old `verify(sig, msg, pk)` is deleted, as
   are the "known, deliberate asymmetry" notes in the facade docstring and README (their
   stated rationale — "verify shipped first and is relied on" — contradicted the standing
   no-consumers order).
2. **Keypair persistence done properly.** Add `toBytes(kp: Keypair): array[32, byte]`
   (raw seed bytes, caller-owned copy, doc-commented wipe guidance identical to
   `X25519StaticSecret.toBytes`). Delete the `seed()` accessor (it returned a `Seed` that the
   public API provided no way to extract bytes from — an unfinished corner masquerading as a
   persistence escape hatch).
3. **`Seed` becomes move-only** (`=copy {.error.}`), matching `Keypair`'s rationale now that
   nothing needs Seed copies. Negative fixture `tests/unit/fixtures/reject_seed_copy.nim`
   driven by subprocess `nim c` (the established injectdestructors-phase methodology).
   `keypair(toSeed(bytes))` remains the construction idiom (rvalue moves); destructor smoke
   tests reworked for move semantics (the copy-wipe test is superseded by the fixture).
4. **Delete `Seed.==`.** The X25519 secret family enforces "no vartime equality on secrets"
   at the type layer (no `==` at all); ed25519 enforced it only at the facade export list.
   One principle, one layer: the operator goes; tests compare via `toBytes(kp)` or a local
   helper.
5. **`hash()` for the public wire types** (`PublicKey`, `Signature`, `X25519Public`) via
   `std/hashes`, alongside the existing `==`/`$` — unblocks Table/HashSet keying (peer
   registries, session caches). Facade-exported; a small Table smoke test pins it.
6. **Paired ephemeral constructor kills the `move()` ceremony in the primary flow.**
   `x25519EphemeralPair(): tuple[secret: X25519EphemeralSecret, public: X25519Public]` —
   derives the public inside the constructor, so the caller's secret binding is referenced
   exactly once (the consuming `x25519` call) and compiles without `move()`.
   `x25519EphemeralSecret()` and the `x25519Base(ephemeral)` overload stay for callers with
   other flows; README's primary example switches to the pair.

### Slice 2 — Core hygiene

1. **Extract `challenge` into `src/sello/challenge.nim`** (imports `nimcrypto/sha2` +
   `sello/scalar` for `scReduce`; consumed by `ed25519.nim` and `private/backend.nim`).
   `scalar.nim` drops its nimcrypto import and becomes a true field-plus-curve-math leaf —
   the same disease that evicted the wire types (finding 27), final symptom.
2. **Delete `geSub`** — dead code inside the CT-audited checks-off region (zero call sites,
   zero tests, pure ref10-port residue; every unused line in that region is audit cost).
3. **Debug-only assertions** (plain `assert`, which `-d:release` strips — the dudect-measured
   build is untouched): (a) `geScalarmultBase`'s bit-255 precondition; (b) `backend.
   signDetached`'s `publicBytes == pointEncode(geScalarmultBase(a))` consistency (expensive,
   debug-only; the finding-18 defensive-posture precedent).
4. **`Fe.limbs` invariant note** — module doc states the limb ranges as a constructor-level
   invariant direct `sello/field` consumers must uphold, not merely "what decoded values look
   like".
5. **Split `types.nim`** into single-purpose leaves: `sello/wire.nim` (PublicKey/Signature +
   converters/`==`/`$`/`hash`; no `private/ct` import — it never needed one) and
   `sello/wipe.nim` (the generic `wipe(var array[32, byte])` over `private/ct`).
   `types.nim` is deleted; importers and CLAUDE.md's layering list updated. (The "two
   leftover leaf concerns, one roof" honesty note is resolved by removing the roof.)
6. **Batch verification disclosed as a considered non-goal** — one sentence in README's
   non-goals and RFC-001's non-goal list ("considered; deferred to a future RFC — random-
   weight batch verify is vartime-tier but has real small-order/cofactor subtleties").

### Slice 3 — Fuzz overhaul (make coverage guidance real)

1. **External SanitizerCoverage target.** New `tests/fuzz/fuzz_external_target.nim`: a small
   stdin-driven binary dispatching the three oracles (pointDecode / verify / x25519 peer
   input). Built per proptest's shipped external-target recipe (`docs/fuzz/` in the proptest
   repo): gcc `-fsanitize-coverage=trace-pc -fno-pie` on the target compile, vendored
   `proptest_cov.c` runtime, driven via `fuzz(strat, externalTarget(...), frontier, settings)`.
   This replaces the in-process `fuzzWith` harness whose `{.cover.}` wrappers gave a 2-edge
   universe (coverage guidance provably saturated within the first iterations — black-box
   random thereafter). Audited sello sources stay pragma-free. `scripts/fuzz.sh` reworked;
   the smoke gate is an edge count an order of magnitude above the old 1–2 (evidence of real
   guidance), plus 0 crashes.
2. **Stronger oracles, both directions:** `not feBytesCanonical(b) => pointDecode(b).isNone`;
   `not scIsCanonical(sig[32..63]) => verify == false`; determinism double-calls for verify
   and x25519. (The "accept implies canonical re-encode" direction already exists.)
3. **`Settings.coverageGuided` enabled** for the `test_properties_*` suites (cheap flag;
   value grows once instrumentation exists).

### Slice 4 — Verification deepening

1. **Random-seed backend parity property**: under `-d:selloLibsodium`, a `forAll` over random
   seeds and messages asserting `backend.derivePublic`/`signDetached` agree byte-for-byte
   with `backend_sodium`'s (the current interop suite pins exactly one seed).
2. **Ephemeral dudect target**: fifth timing target exercising the
   `x25519(sink X25519EphemeralSecret, peer)` path (constructor + consume per sample,
   identical cost both classes); docs/ct-results.md updated after a full `nimble`-era-quality
   run.
3. **Z3 whole-chain proof attempt** (outcome honestly uncertain): re-encode the recoding
   proof over 64 independent free symbolic nibbles (`symexAssume`d into [0,15], no byte-array
   extraction) chained through `oneStep`/`finalStep` in one `symexFind` — a strict
   generalization of the real function that sidesteps the byte-extraction blowup believed to
   have caused the earlier OOM. If `sxUnsat`: retire the manual-induction caveat everywhere
   it is documented. If not tractable: document the attempt and its failure mode precisely;
   the per-step-lemma + manual-induction status quo remains the honest ceiling.

### Slice 5 — Mutation testing (score the suite's sensitivity)

proptest's `mutation.nim` v1 is `int -> int` only, so sello builds its own thin harness in
the same spirit: a curated catalog of source-level mutants for `field.nim`/`scalar.nim`'s
highest-risk spots (carry-chain operator swaps `+`/`-`, shift-amount off-by-ones, boundary
constants 19/0x7FFFFF/etc., comparison flips in `feBytesCanonical`/`scIsCanonical`, digit
range constants in the recoding), applied as patches to a scratch copy, compiled and run
against the full unit suite in-container, expecting RED for every mutant. Deliverables:
`scripts/mutation.sh` + a checked-in mutant catalog (~20–40 targeted mutants, quality over
exhaustiveness), a kill-rate report in `docs/mutation-results.md`, and — for any surviving
mutant — a new test that kills it (a survivor is a coverage-gap finding, handled in-slice).

## Ordering & risks

Slices 1→2 are sequential (overlapping API files); 3→5 are largely test-side and follow.
Risks: Z3 outcome uncertain by design (honest partial acceptable); SanitizerCoverage-with-Nim
wiring is empirical (proptest's docs cover the recipe; blocker if the base image's gcc
disagrees); Seed move-only churn concentrated in the destructor smoke tests.

## Non-goals

Batch verification (disclosed, deferred — candidate RFC-003). Ristretto255, Ed25519ctx/ph
(unchanged from RFC-001). Runtime tombstones for ephemeral reuse (compile-time enforcement
already at Nim's honest ceiling).
