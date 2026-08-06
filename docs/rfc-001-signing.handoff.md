# RFC-001 ed25519 signing — handoff

- **Stage:** 2 (architect review) — **both rounds complete**; next is stage 3 (implement)
- **Resume:** `/loop implement the next unimplemented RFC slice with /tdd, following the standing rules; after each slice report one progress line (e.g. "slice 4/11 done, 7 remaining"); stop when every slice is implemented`

## Slices (renumbered in round 2 — now 11)
- [ ] 1 layering prep (scReduce/pointEncode → scalar.nim; challenge() extraction; clampScalar → field.nim; delete SecretKey incl. facade export, GePrecomp)
- [ ] 2 scMulAdd (ref10 port; all 27 {0,1,L−1}³ joint combos + 1000 python3-generated random vectors)
- [ ] 3 compile-time base table (GeCached z=1) + CT full-scan select (identity-initialized output)
- [ ] 4 geScalarmultBase (bit-255-clear precondition; clamped AND r-shaped vector domains; white-box digit-range test)
- [ ] 5 signing.nim types + keygen (distinct Seed + =destroy; move-only Keypair; in-place urandom; 4 RFC vectors)
- [ ] 6 sign core (backend.signDetached via shared challenge(); TEST 1–3 bit-exact + roundtrip)
- [ ] 7 sign completion (TEST-1024 multi-block, scripted vector sourcing; verify-suite backfill; string overloads; facade + nimble wiring)
- [ ] 8 secret hygiene (ct.nim volatile-store shape; x25519 scrub fix; sha512 ctx wipe; destructor smoke tests incl. reassignment)
- [ ] 9 tests/ct dudect harness (interleaved classes, 4.5/10 thresholds, pinning) + docs/ct-results.md
- [ ] 10 libsodium adapter (private/backend_sodium.nim; atomic sodium_init; bidirectional interop; sello-owned Containerfile)
- [ ] 11 packaging (README, LICENSE + notices, CHANGELOG.md, doc/CLAUDE.md updates, version 0.2.0)

Ordering: 1–7 strictly sequential; pairs (8,9) and (10,11) interleave after 7; 8<9, 10<11.

## Open forks (awaiting Corey)
- none — round 2 produced no genuine forks; all findings had clear-best fixes (applied)

## Key decisions (this session)
- All secret-touching code isolated in `src/sello/private/backend.nim` (seed-level backend); `ed25519.nim` stays verify-only.
- Round 2 (critical): `geScalarmultBase` precondition corrected to **bit 255 clear only** — the draft's "clamped shape (bit 254 set)" is violated by every reduced nonce r < L; r-shaped test domain + white-box digit-range test added.
- Round 2: pure backend renamed signer.nim → `private/backend.nim` (its seed-level API bypasses Keypair hygiene → private/ social contract; kills signer/signing near-collision); adapter is `private/backend_sodium.nim`.
- Round 2: `Seed = distinct array[32, byte]` with its own =destroy wipe — type-confusion guard vs PublicKey and auto-wipe for the copy `seed()` returns.
- Round 2: `Keypair` is move-only (`=copy` {.error.}); verified on 2.2.10/ORC that by-value params are borrows and reassignment destroys (wipes) the old value.
- Round 2: shared `challenge(R, A, msg)` extracted to scalar.nim, called by both verify and signDetached (sign/verify self-consistency).
- Round 2: `clampScalar` lands in **field.nim**, not scalar.nim, so x25519.nim stays a field-only consumer.
- Round 2: `keypair()` must use sysrand's in-place `urandom(dest)` overload — the seq-returning overload heap-allocates the seed.
- Round 2: old slice 6 split into sign core / sign completion → 11 slices total.
- Round 2: sello-owned minimal Containerfile for libsodium testing; `Containerfile.amox` is amoxtli infra and stays untouched.
- Round 2 de-risked empirically: emit-in-func passes the effect checker (func/proc question closed); Sha2Context verified stack-only; x25519 dead-store deletion AND the volatile-store fix confirmed by disassembly; =destroy/borrow semantics verified; checks-off does not alter VM const-eval.
- Round 1: scReduce/scIsCanonical/load3/load4/pointEncode move to scalar.nim so the backend never imports ed25519.nim.
- Round 1: base table stored as GeCached(z=1) — no GePrecomp/ge_madd port; conditional negate = swap(yPlusX,yMinusX)+negate t2d.
- Round 1: compile-time table const-eval verified empirically in-container (~1s, byte-exact); generator is contingency only.
- Round 1: `signing.nim` holds Seed/Keypair + libsodium dispatch; facade stays logic-free.
- Round 1: API = `keypair(seed)` / `keypair()` (sysrand) / `sign(kp, msg)` key-first / `wipe(var Seed)`; SecretKey deleted; sign total + deterministic.
- Round 1: nonce r named first-class secret; dudect spec hardened (interleaving, 1e6 samples, 4.5 warn / 10 fail, taskset, powersave caveat).
- `verify` remains pure-Nim even under `-d:selloLibsodium`.
- Timing harness is a separate `nimble ct` task, not part of `nimble test`.

## Review ledger (stage 4)
| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
