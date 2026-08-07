# RFC-003 audit round 2 — handoff

- **Stage:** 1 complete (RFC drafted and sliced from the round-2 compromise audit; scope
  approved by Corey 2026-08-07 "roll all of it into rfc-003"). Stage 2 (architect rounds)
  skipped on the RFC-002 precedent: this RFC *is* the output of a four-lens architect
  audit whose load-bearing claims were spot-checked against source before drafting.
- **Resume:** `/loop implement the next unimplemented RFC slice with /tdd, following the
  standing rules; after each slice report one progress line (e.g. "slice 2/6 done, 4
  remaining"); stop when every slice is implemented` — awaiting Corey to start the grind.
- **Prior RFC state:** RFC-002 fully implemented (`ecdb8e6` → `02e0005`), stage-4 review
  NOT yet run; RFC-003 records the recommendation to run ONE combined `/code-review` over
  both RFCs' scope after these slices land.

## Slices
- [ ] 1 src/ design coherence (geBasePoint in verify; feFromLimbs; feSqrtRatio;
      malleability warning onto Signature/hash/==; x25519StaticPair) — FIRST; gate
      includes scripts/mutation.sh to catch exact-string mutant bitrot from src edits
- [ ] 2 fuzz oracle identity check + encode/decode round-trip property + X25519
      DH-agreement property (new test_properties_x25519.nim, joins unit_test_files) +
      test.sh graceful proptest skip
- [ ] 3 mutation scope extension (challenge.nim ordering, pointDecode conditionals,
      ladder zero-check, pointEncode sign bit; ~10-15 mutants; strictly after slice 1)
- [ ] 4 proof completion (written telescoping-carry induction for the reconstruction
      identity; literal-function composition argument; RESOURCE WALL reframe)
- [ ] 5 CT hardening (sixth dudect target: static-secret DH fixed-vs-random; ct.sh
      environment preflight banner; full run + ct-results.md) — timing run LAST, quiet
      machine, synchronous-foreground container rule (RFC-002 ops lesson)
- [ ] 6 docs/packaging (CHANGELOG + 0.3.0 bump in sello.nimble + milpa.kdl; README/
      CLAUDE.md/x25519.nim drift fixes; F12/F14 gap note; mutation.sh estimate)

## Open forks (awaiting Corey)
- none — all decisions resolved at approval ("roll all of it into rfc-003"); the two
  borderlines are recorded as declined non-goals in the RFC

## Key decisions (from the audit/approval conversation)
- x25519 static role gets a PAIR CONSTRUCTOR, not a Keypair-style invariant type (X25519
  ops take only the secret; bundling at construction captures the whole benefit)
- coverageGuided stays a disclosed no-op (process-shaped instrumentation vs in-process
  forAll — declined)
- ct.sh preconditions: warn-and-record, never hard-fail
- one CHANGELOG 0.3.0 entry covers RFC-002 + RFC-003 (nothing released between)
- combined RFC-002+003 code review after implementation (near-total file overlap)
- Ordering: 1 → {2,4 free; 3 after 1} → 5 → 6

## Review ledger (stage 4 — empty until review)
| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
