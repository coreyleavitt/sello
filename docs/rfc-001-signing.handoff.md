# RFC-001 ed25519 signing — handoff

- **Stage:** 2 (architect review)   •   **Round:** 0 of 2 complete
- **Resume:** `/architect docs/rfc-001-signing.md round 1`

## Slices
- [ ] 1 scMulAdd (ref10 port + vectors)
- [ ] 2 compile-time base table + CT select primitives
- [ ] 3 geScalarmultBase (CT fixed-base)
- [ ] 4 keypairFromSeed (RFC 8032 §7.1 pk vectors)
- [ ] 5 sign (RFC 8032 §7.1 bit-exact + roundtrip)
- [ ] 6 secret hygiene (private/ct.nim wipe, barriers, audit)
- [ ] 7 tests/ct dudect harness + docs/ct-results.md
- [ ] 8 libsodium adapter (-d:selloLibsodium) + Containerfile dep
- [ ] 9 README + package polish

## Open forks (awaiting Corey)
- none yet

## Key decisions (this session)
- All secret-touching code isolated in new `src/sello/signer.nim`; `ed25519.nim` stays verify-only (load-bearing spec constraint).
- Base-point precomp table derived at compile time (or via checked-in generator), never hand-transcribed.
- `verify` remains pure-Nim even under `-d:selloLibsodium`; only sign/keygen dispatch to FFI.
- Timing harness is a separate `nimble ct` task, not part of `nimble test`.

## Review ledger (stage 4)
| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
