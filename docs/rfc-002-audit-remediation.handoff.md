# RFC-002 audit remediation — handoff

- **Stage:** 3 (implement) — slices defined in `docs/rfc-002-audit-remediation.md`; RFC
  approved by Corey 2026-08-06 with all decisions resolved (no architect rounds needed —
  the RFC *is* the output of a three-lens architect audit, and Corey approved the full scope).
- **Resume:** slice 1 (`02e0005`) and slice 2 (subject: "RFC-002 slice 2: core hygiene
  remediation" — identified by subject line, not hash: slice 1's amend-the-handoff-in
  pattern recorded a stale pre-amend hash, so this handoff update was written BEFORE the
  single slice-2 commit instead, and future slices should keep doing the same) are both
  done. Continue via the PHASED ORDERING below (revised 2026-08-06, supersedes plain
  2→3→4→5), now at **Phase B**:
  - **Phase A — slice 2 alone** — DONE (see the slice list below for what changed and its
    one judgment call). It relocated the modules every later slice's test code imports
    (`types.nim` → `wire.nim`/`wipe.nim`, `challenge.nim` extraction), so nothing ran
    beside it.
  - **Phase B — slices 3 and 5 in parallel** (NEXT), each in a worktree-isolated sonnet subagent
    (disjoint files: tests/fuzz/ + scripts/fuzz.sh vs. scripts/mutation.sh + catalog +
    docs/mutation-results.md; only slice 5's killing-tests-for-survivors can brush
    tests/unit/). Phase-B agents do NOT commit and do NOT touch this handoff — the
    control loop merges each finished worktree to master serially, re-runs the gates on
    the merged tree, commits, and updates this doc. Slice 3's agent must SPIKE FIRST:
    compile a trivial `-fsanitize-coverage=trace-pc` + proptest_cov.c binary in the base
    image before writing any harness; if the toolchain refuses, return that as a blocker
    immediately instead of building around it.
  - **Phase C — slice 4 alone, last, with no concurrent container load**: its dudect run
    is timing-sensitive (docs/ct-results.md already records environment caveats — don't
    add "another agent was compiling mutants on all cores" to them) and its Z3 retry
    needs the memory headroom the first attempt's OOM lacked.
  Build/test: `scripts/test.sh`, `scripts/test-libsodium.sh` (sello-dev image),
  `scripts/check-readme.sh`, `scripts/fuzz.sh`, `scripts/bmc.sh`, `scripts/ct.sh`; single
  file via the podman + milpa-CAS-mount invocation in CLAUDE.md. `rm` is aliased
  interactive — use `rm -f`. proptest repo is read-only reference.

## Slices
- [x] 1 API coherence — actor-first `pk.verify(msg, sig)`; `toBytes(kp)` + delete `seed()`;
      move-only `Seed` + reject_seed_copy fixture; delete `Seed.==`; `hash()` for
      PublicKey/Signature/X25519Public; `x25519EphemeralPair()`; README/facade doc updates
      (`02e0005`, amended with this handoff update). Judgment calls: `keypair(seed: sink
      Seed)` needed `sink` once `Seed` went move-only, and `signing.keypair()`'s own
      `result = keypair(s)` needed an explicit `move(s)` for the same reason
      `x25519(sink X25519EphemeralSecret, ...)` documents (the earlier `urandom(s.bytes)`
      field read counts as a reference under Nim's whole-scope sink-argument occurrence
      count); `x25519EphemeralPair`'s no-`move()`-needed property is proven by a plain
      top-level proc in `test_x25519.nim` rather than inside a `test:` body, since
      `unittest`'s implicit try/finally forces `move()` regardless of reference count.
- [x] 2 Core hygiene — `challenge` extracted to `sello/challenge.nim` (imports
      `nimcrypto/sha2` + `sello/scalar` for `scReduce`; consumed by `ed25519.nim` and
      `private/backend.nim`, confirmed by grep to be the only two consumers, matching the
      RFC) — `scalar.nim` now has zero nimcrypto import, a pure field-plus-curve-math leaf.
      `geSub` deleted (grepped first: zero real call sites, only two comments mentioning
      it alongside `geAdd`, both updated). Debug-only precondition/consistency checks added
      to `geScalarmultBase` (bit-255-clear of its scalar argument) and `backend.
      signDetached` (`publicBytes == pointEncode(geScalarmultBase(a))`, an intentionally
      expensive re-derivation). `Fe.limbs` invariant note added to `field.nim`'s module doc
      (constructor-level invariant direct consumers must uphold, not just a description of
      decoded values). `types.nim` split into `sello/wire.nim` (`PublicKey`/`Signature` +
      `toPublicKey`/`toSignature`/`toBytes`/`==`/`$`/`hash`, no `private/ct` import) and
      `sello/wipe.nim` (the generic `wipe*(var array[32, byte])`, over `private/ct`);
      `types.nim` deleted; every importer (`sello.nim`, `ed25519.nim`, `signing.nim`,
      `test_x25519.nim`) and every doc-comment cross-reference (`x25519.nim`,
      `private/backend.nim`) updated, plus CLAUDE.md's numbered layering list (folded
      `wire.nim`/`wipe.nim`/`challenge.nim` into slot 2, updated the `scalar.nim`,
      `ed25519.nim`, `x25519.nim`, `signing.nim`, `private/backend.nim`, `private/ct.nim`
      entries for the new module names). Batch-verification non-goal sentence added to
      README.md's "What's not here" and `docs/rfc-001-signing.md`'s non-goals list.
      (subject: "RFC-002 slice 2: core hygiene remediation".)

      **Judgment call / empirical finding surfaced mid-slice, resolved rather than
      escalated as a blocker (reasoning below):** the RFC's stated mechanism for the two
      debug-only asserts — "plain `assert`, which `-d:release` strips" — is empirically
      FALSE for this Nim 2.2.10 toolchain/config, verified with isolated scratch probes
      (same standard this project already holds itself to, e.g. `signing.Seed`'s
      distinct-array finding) before writing either assert into the real source: `-d:release`
      alone leaves `assertions` on (only `-d:danger` disables them by default here), AND
      both asserts sit inside a `checks: off` pushed region, whose `checks` umbrella
      bundles `assertions` off unconditionally — so a bare `assert` written directly there
      would have been silently compiled out in EVERY build, debug included, never firing
      at all, defeating item 3's own test coverage. Worse, had the RFC's literal
      "`-d:release` strips it" claim been trusted without checking, and the umbrella
      bundling *not* existed, the assert (and `signDetached`'s extra secret-scalar
      `geScalarmultBase` call) would have shipped inside the exact `-d:release` build
      `scripts/ct.sh` timing-measures and every downstream consumer compiles — a real
      correctness/performance regression in the shipped release artifact, not just a stale
      comment. Fix, applied at both sites: `when not defined(release): {.push assertions:
      on.} assert ...; {.pop.}`. Confirmed by grepping the generated C from both a
      `-d:release` and a plain debug `nim c --nimcache:...` build of `tests/ct/ct_main.nim`:
      the assert failure-message strings and the extra `geScalarmultBase` call in
      `signDetached` are both completely absent from the release nimcache and both present
      in the debug one. This preserves the RFC's actual INTENT (debug-only, invisible to
      the dudect-measured/shipped release build) while correcting its stated mechanism —
      the same register as `signing.Seed`'s own documented Nim-version-forced deviation
      (`signing.nim`'s module doc comment), not escalated as a blocker because the
      correct fix was unambiguous, empirically verified, and fully preserves the RFC's
      intent rather than overriding a genuine design decision.

      **Gates:** `scripts/test.sh` green (163 `[OK]`, exit 0, neither new assert fired —
      both invariants hold in practice). `scripts/test-libsodium.sh` green (168 `[OK]`,
      exit 0). `scripts/check-readme.sh` green (5/5 fences). `nim check -d:release` clean
      for both `tests/ct/ct_main.nim` and `tests/fuzz/fuzz_main.nim`. `tests/verify/
      symex_recode.nim` also `nim check`ed as an extra precaution (imports `sello/scalar`
      directly) — clean.
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
