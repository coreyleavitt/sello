# RFC-001 ed25519 signing — handoff

- **Stage:** 2 (architect review)   •   **Round:** 1 of 2 complete
- **Resume:** `/architect docs/rfc-001-signing.md round 2`

## Slices (renumbered in round 1 — now 10)
- [ ] 1 layering prep (move scReduce/pointEncode to scalar.nim, clampScalar, delete SecretKey/GePrecomp)
- [ ] 2 scMulAdd (ref10 port; edge + 1000 python3-generated vectors)
- [ ] 3 compile-time base table (GeCached z=1) + CT full-scan select
- [ ] 4 geScalarmultBase (clamped-input precondition, 0x7F boundary vector)
- [ ] 5 signing.nim types + keygen (private-field Keypair, =destroy, keypair()/sysrand; 4 RFC vectors)
- [ ] 6 sign(kp, msg) (all 4 §7.1 vectors incl. 1023-byte; backfill verify suite; nimble wiring)
- [ ] 7 secret hygiene (ct.nim; fix x25519 dead-store scrub; sha512 ctx wipe; func/proc)
- [ ] 8 tests/ct dudect harness (interleaved classes, 4.5/10 thresholds, pinning) + docs/ct-results.md
- [ ] 9 libsodium adapter (signing.nim dispatch, sodium_init, bidirectional interop, testLibsodium task)
- [ ] 10 packaging (README, LICENSE + notices, doc/CLAUDE.md updates, version 0.2.0)

Ordering: 1–6 strictly sequential; pairs (7,8) and (9,10) interleave after 6; 7<8, 9<10.

## Open forks (awaiting Corey)
- none — round 1 produced no genuine forks; all findings had clear-best fixes (applied)

## Key decisions (this session)
- All secret-touching code isolated in `src/sello/signer.nim` (seed-level backend); `ed25519.nim` stays verify-only.
- Round 1: scReduce/scIsCanonical/load3/load4/pointEncode move to scalar.nim so signer never imports ed25519.nim.
- Round 1: base table stored as GeCached(z=1) — no GePrecomp/ge_madd port; conditional negate = swap(yPlusX,yMinusX)+negate t2d.
- Round 1: compile-time table const-eval verified empirically in-container (~1s, byte-exact); generator is contingency only.
- Round 1: new `signing.nim` holds Seed/Keypair (private fields, =destroy wipe, sole constructor) + libsodium dispatch; facade stays logic-free.
- Round 1: API = `keypair(seed)` / `keypair()` (sysrand) / `sign(kp, msg)` key-first / `wipe(var Seed)`; SecretKey deleted; sign total + deterministic.
- Round 1: nonce r named first-class secret; dudect spec hardened (interleaving, 1e6 samples, 4.5 warn / 10 fail, taskset, powersave caveat).
- Round 1: libsodium adapter gains sodium_init guard + bidirectional interop tests + nimble testLibsodium.
- `verify` remains pure-Nim even under `-d:selloLibsodium`.
- Timing harness is a separate `nimble ct` task, not part of `nimble test`.

## Review ledger (stage 4)
| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
