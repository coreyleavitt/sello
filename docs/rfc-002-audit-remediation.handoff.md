# RFC-002 audit remediation — handoff

- **Stage:** 3 (implement) — slices defined in `docs/rfc-002-audit-remediation.md`; RFC
  approved by Corey 2026-08-06 with all decisions resolved (no architect rounds needed —
  the RFC *is* the output of a three-lens architect audit, and Corey approved the full scope).
- **Resume:** slice 1 is done (`bb36894`); implement slice 2 (Core hygiene — `challenge` ->
  `sello/challenge.nim`, delete `geSub`, debug-only asserts, `Fe.limbs` invariant doc, split
  `types.nim` into `wire.nim`/`wipe.nim`, batch-verify non-goal sentence) next, in a sonnet
  subagent (RED-GREEN-REFACTOR, full container suite green, per-slice commit after gates —
  Corey endorsed the RFC-001 per-batch commit pattern). Build/test: `scripts/test.sh`,
  `scripts/test-libsodium.sh` (sello-dev image), `scripts/check-readme.sh`, `scripts/fuzz.sh`,
  `scripts/bmc.sh`, `scripts/ct.sh`; single file via the podman + milpa-CAS-mount invocation
  in CLAUDE.md. `rm` is aliased interactive — use `rm -f`. proptest repo is read-only
  reference. Note slice 1 already touched `sello/types.nim` (new `hash()` overloads added)
  and `sello/signing.nim` (Seed/Keypair rework) — slice 2's `types.nim` split starts from
  that updated state, not the pre-slice-1 version.

## Slices
- [x] 1 API coherence — actor-first `pk.verify(msg, sig)`; `toBytes(kp)` + delete `seed()`;
      move-only `Seed` + reject_seed_copy fixture; delete `Seed.==`; `hash()` for
      PublicKey/Signature/X25519Public; `x25519EphemeralPair()`; README/facade doc updates
      (`bb36894`, amended with this handoff update). Judgment calls: `keypair(seed: sink
      Seed)` needed `sink` once `Seed` went move-only, and `signing.keypair()`'s own
      `result = keypair(s)` needed an explicit `move(s)` for the same reason
      `x25519(sink X25519EphemeralSecret, ...)` documents (the earlier `urandom(s.bytes)`
      field read counts as a reference under Nim's whole-scope sink-argument occurrence
      count); `x25519EphemeralPair`'s no-`move()`-needed property is proven by a plain
      top-level proc in `test_x25519.nim` rather than inside a `test:` body, since
      `unittest`'s implicit try/finally forces `move()` regardless of reference count.
- [ ] 2 Core hygiene — `challenge` → `sello/challenge.nim` (scalar.nim drops nimcrypto);
      delete `geSub`; debug `assert`s (bit-255, publicBytes consistency); `Fe.limbs`
      invariant doc; split types.nim → `wire.nim` + `wipe.nim`; batch-verify non-goal sentence
- [ ] 3 Fuzz overhaul — external SanitizerCoverage target (proptest `externalTarget`, gcc
      trace-pc + proptest_cov.c), scripts/fuzz.sh rework, edge-count gate (≫2 edges);
      differential + determinism oracles; `Settings.coverageGuided` on property suites
- [ ] 4 Verification deepening — random-seed backend↔sodium parity property; ephemeral
      dudect target + ct-results update; Z3 whole-chain attempt (64 free nibbles; honest
      outcome either way)
- [ ] 5 Mutation testing — curated mutant catalog for field/scalar hot spots,
      scripts/mutation.sh, docs/mutation-results.md, kill-rate; survivors get killing tests
      in-slice

## Open forks (awaiting Corey)
- none — all decisions resolved at RFC approval

## Key decisions (carried from the audit/approval conversation)
- verify parameter order: `verify(pk, msg, sig)` — RFC 8032 / dalek ordering, actor-first.
- Seed goes move-only BECAUSE `toBytes(kp)` removes the only copy-requiring API (`seed()`);
  the old copyability exemption was rationalizing a missing-toBytes corner.
- Fuzz in-process `{.cover.}` wrappers gave a 2-edge universe — coverage guidance was
  provably saturated/black-box; external SanitizerCoverage target is proptest's own shipped
  mechanism and keeps audited sources pragma-free.
- Z3 retry hypothesis: prior OOM blamed on 32-byte symbolic extraction, not the carry chain;
  free-nibble encoding is a strict generalization. Honest partial remains acceptable.
- Mutation testing is sello-side patch-based (proptest mutation v1 is int->int only).
- Batch verification: disclose as considered/deferred now; feature is RFC-003 candidate.

## Review ledger (stage 4 — empty until RFC-002 review)
| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
