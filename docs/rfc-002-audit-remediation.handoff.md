# RFC-002 audit remediation — handoff

- **Stage:** CLOSED — implementation complete, and the stage-4 review ran 2026-08-08 as
  the ONE combined review over RFC-002 + RFC-003 + round-3 scope (per the recorded
  near-total-file-overlap recommendation). Two fix rounds + two re-reviews to the floor;
  all actionable findings closed; remediation committed as `d1133e2`. The full review
  ledger lives in `rfc-003-audit-round-2.handoff.md`, not here.
- **Resume:** nothing — this RFC is closed. Historical record of the implementation
  below. All five slices were done and verified by the control loop 2026-08-07 —
  master history `ecdb8e6` (slice 4) → `8449b06` (3) → `1458abd` (5) → `72610d9` (2) →
  `02e0005` (1), working tree clean; see the slice list below for what each changed, its
  judgment calls, and its gate results. Nothing left to implement for this RFC; this is a
  safe `/compact` point. No open forks.
  - **Phase A — slice 2 alone** — DONE (see the slice list below for what changed and its
    one judgment call). It relocated the modules every later slice's test code imports
    (`types.nim` → `wire.nim`/`wipe.nim`, `challenge.nim` extraction), so nothing ran
    beside it.
  - **Phase B — slices 3 and 5 in parallel** — DONE. Slice 5 merged 2026-08-06 (subject:
    "RFC-002 slice 5: mutation testing"; squash-merged, test.sh re-run on merged tree,
    165 OK; mutation.sh's 36/36 clean run happened in-worktree on byte-identical content).
    Slice 3 merged 2026-08-07 (subject: "RFC-002 slice 3: fuzz overhaul"; squash-merged
    onto the post-slice-5 master — genuinely different content this time — and BOTH gates
    re-run on the merged tree by the control loop: test.sh 165 OK / 0 failures, fuzz.sh 30
    → pointDecode 351 edges / verify 333 / x25519 291, 0 crashes, gate MinEdgesGate=50
    passed). Both worktrees removed. Ops lesson recorded: subagents driving long container
    runs stalled twice by stopping to "wait" on background tasks whose completion never
    re-woke them (one container even exited unobserved overnight) — Phase C's agent must
    run every long command SYNCHRONOUSLY in the foreground.
    (disjoint files: tests/fuzz/ + scripts/fuzz.sh vs. scripts/mutation.sh + catalog +
    docs/mutation-results.md; only slice 5's killing-tests-for-survivors can brush
    tests/unit/). Phase-B agents do NOT commit and do NOT touch this handoff — the
    control loop merges each finished worktree to master serially, re-runs the gates on
    the merged tree, commits, and updates this doc. Slice 3's agent must SPIKE FIRST:
    compile a trivial `-fsanitize-coverage=trace-pc` + proptest_cov.c binary in the base
    image before writing any harness; if the toolchain refuses, return that as a blocker
    immediately instead of building around it.
  - **Phase C — slice 4 alone, last** — DONE (subject: "RFC-002 slice 4: verification
    deepening"; see the slice list below for the parity property, dudect target, and Z3
    result in full). The "no concurrent container load" precondition this phase called for
    was NOT perfectly met in practice — see slice 4's own entry below for what was
    actually observed on the host and why the results are still trusted.
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
- [x] 3 Fuzz overhaul (subject: "RFC-002 slice 3: fuzz overhaul") — coverage guidance is
      now REAL: mandated spike ran first and passed in the base image (plain-C toy: 6
      nonzero counters; Nim toy: 78 — recipe exactly as `_deps/proptest/docs/fuzz/USAGE.md`
      documents). New `tests/fuzz/fuzz_external_target.nim`: single stdin-driven binary,
      mode-byte dispatch (0=pointDecode, 1=verify, 2=x25519), carrying both new oracle
      directions (¬feBytesCanonical ⇒ pointDecode none; ¬scIsCanonical(S) ⇒ verify false)
      plus determinism double-calls; imports only sello modules, zero pragmas added to
      audited sources. `fuzz_common.nim` rewritten (retired {.cover.} wrappers; now
      strategies + mode-byte encoders + `runExternalTarget`, no sello import at all — the
      driver process never touches sello, only the instrumented subprocess does);
      `fuzz_main.nim` = three campaigns, one CoverageFrontier each; `scripts/fuzz.sh` =
      three-stage container build (proptest_cov.o, sancov-instrumented target, plain
      driver), keeps [seconds-per-target] contract + milpa-preflight. Edge gate
      `MinEdgesGate = 50`, calibrated from three independent runs (291–542 observed;
      old universe was 1–2 edges). `Settings.coverageGuided = true` wired into all 24
      properties across the three `test_properties_*` suites (honest no-op today — no
      {.cover.} anywhere — readies the surface per the RFC's own framing). proptest's
      real API matched the RFC's assumptions (cosmetic signature diffs vs INTERFACE.md
      confirmed against fuzz.nim source before use). Campaign at merge: 2108/1603/847
      iterations, 351/333/291 edges, 0 crashes, exit 0.
- [x] 4 Verification deepening (subject: "RFC-002 slice 4: verification deepening") — all
      three items landed; Z3 outcome is the PROVED branch.

      **Item 1 — random-seed backend parity property.** Added to
      `tests/unit/test_libsodium_interop.nim` (the established home for cross-backend
      coverage, already carrying the `when defined(selloLibsodium)` skip pattern): a
      `property` (via **proptest**, already a fetched optional dep — `_deps/proptest`
      present, no `milpa fetch --features proptest` needed this session) generalizing the
      suite's single pinned seed to a `forAll` over 50 random `(seed, msg)` pairs, calling
      `sello/private/backend.derivePublic`/`signDetached` and
      `sello/private/backend_sodium`'s equivalents directly (bypassing `Keypair`, matching
      RFC-001 ledger finding 13's shared seed-level contract) and asserting byte-for-byte
      agreement on both the derived public key and the signature. Compiles and runs only
      under `-d:selloLibsodium`; a plain `scripts/test.sh` run never imports `proptest` or
      `backend_sodium` from this file (the `when` branch containing both imports is
      unreached), so the skip pattern's "stays green with no libsodium installed" property
      is preserved. Passed on first real run (`scripts/test-libsodium.sh`, 171 `[OK]`).

      **Item 2 — ephemeral dudect target.** `tests/ct/ct_main.nim` gained a fifth target
      exercising `x25519(sink X25519EphemeralSecret, peer)`. **Judgment call:**
      `X25519EphemeralSecret` has, by design, no from-bytes constructor and does not export
      its scalar bytes outside `x25519.nim` (confirmed by reading the type, not assumed) —
      there is no way to build a "fixed vs. random secret" class pair for it the way the
      other four targets do. Rather than force a construction that doesn't fit or silently
      skip the target, both dudect classes do the IDENTICAL thing every sample: draw a
      fresh ephemeral secret from the OS CSPRNG and consume it against the same fixed peer
      point. This is disclosed plainly (in `ct_main.nim`'s module doc, the new target's own
      doc comment, and `docs/ct-results.md`) as a calibration/self-consistency check on the
      sink-consuming call chain's own machinery (construction, ladder, zero-check, `Option`
      wrap, `=destroy` wipe) rather than a "does this secret's value leak" test the way the
      other four targets' results are — there is no fixed secret value to ask that question
      about for this type. Full run (`scripts/ct.sh`, 1,000,000 samples/class,
      `taskset -c 0`-pinned): positive control t = 950.93 (FAIL, expected — harness
      self-test); `signDetached` t = -1.75; `geScalarmultBase` t = 1.15; `x25519Base`
      t = 1.10; ephemeral construct+consume t = -1.42 — all four real targets PASS
      comfortably inside `|t| <= 4.5`, no WARN, no FAIL, nothing to escalate.
      `docs/ct-results.md` updated with the new target's table row, its own "why this one's
      different" subsection, and both runs (RFC-001 four-target, RFC-002 five-target) kept
      side by side rather than overwriting history.

      **Judgment call / environment honesty:** Phase C's own precondition ("no concurrent
      container load") was NOT perfectly met — `podman ps`/`uptime` showed an unrelated,
      otherwise-idle `amoxtli-dev` container present on the shared host for part of the run
      window, and the 15-minute load average briefly touched 8.07 on 6 cores shortly before
      the run. Disclosed in `docs/ct-results.md`'s environment section rather than silently
      claimed away; the actual t-statistics (all real targets under |t| = 2) don't show the
      variance inflation heavy concurrent load would produce, so the result is trusted, but
      the precondition gap is recorded plainly rather than asserting a quieter environment
      than what the tools actually showed. Separately, the SAME shared host's `/tmp`
      (rootless podman's storage backend) filled to 100% mid-slice from other sessions'
      accumulated container layers — diagnosed via `podman system df -v` before touching
      anything, then reclaimed conservatively (`podman volume prune -f`, ~4.3GB, and a
      dangling-image-only `podman image prune -f`, which found nothing further to remove
      without resorting to `-a`, which would have deleted OTHER PROJECTS' tagged-but-idle
      images — not done). This was a pre-existing host condition, not something this
      session's own container runs caused (each `--rm` podman invocation cleans up its own
      layer).

      **Item 3 — Z3 whole-chain proof attempt: PROVED (`sxUnsat`).** The RFC's proposed
      encoding (64 free symbolic nibbles chained through `oneStep`/`finalStep` directly)
      does not compile/run as specified — two DISTINCT empirical symex limitations, found
      via isolated scratch probes before touching the real harness (same standard as
      `signing.Seed`'s and slice 2's `checks:off`/`assertions` findings): (1) calling an
      `int32`-typed proc as a NESTED callee (not the direct `symexFind` SUT) that does
      checked `+`/`shr` arithmetic crashes the walker outright
      (`FieldDefect: field 'bv32' is not accessible for type 'SymVal' using 'kind =
      svBV64'`, in `proptest/smt/runtime.nim`'s `lowerArith`/`overflowCond`) — neither
      `{.push overflowChecks: off.}` nor `SymexSettings.arithChecks = {}` suppresses it;
      (2) independently, a proc that RETURNS A TUPLE and is called as a nested callee hits
      `sxUnknown`/`weInternalWalkerFault: composite-typed proc return not yet wired`. Both
      reproduced on minimal (1-2 call) probes with no scalar.nim-specific content, so this
      is a symex-version limitation, not a bug in this project's encoding attempt.
      **Fix:** `oneStepChain`/`finalStepChain`, new tooling-compatible re-encodings of
      `oneStep`/`finalStep` in `tests/verify/symex_recode.nim` — plain `int` (sidesteps
      limitation 1; the value ranges involved are tiny, so `int` vs `int32` changes no
      mathematical content) and a `var` output parameter instead of a tuple return
      (sidesteps limitation 2) — checked EXHAUSTIVELY (not sampled) against `oneStep`/
      `finalStep` over their full 32+16 concrete `(nibble, carryIn)` pairs before being
      trusted, closing the "two independently-typed-out implementations could silently
      drift" risk the same way round-2 finding 31 already closed it once. `wholeChainRecode`
      (64 free `int` parameters, no array anywhere) chains 63 calls to `oneStepChain` plus
      one to `finalStepChain`; `symexFind(wholeChainRecode, tAssertionViolation())` with
      DEFAULT `SymexSettings` (no special budget needed) returned **`sxUnsat`** in ~84-100s
      wall-clock (compile + solve) inside `scripts/bmc.sh`'s 300s (or 600s, both tried)
      kill-timeout — comfortably tractable, confirming the RFC's own hypothesis that the
      first attempt's OOM was the byte-array/mutated-array encoding, not the 63-step carry
      chain itself. The full 63-step composition is therefore now machine-checked, not
      manually argued. Per the RFC's own instruction, the manual-induction caveat is
      RETIRED everywhere it was documented: `tests/verify/symex_recode.nim`'s module doc
      (rewritten with the "Z3 WHOLE-CHAIN ATTEMPT" section covering the two symex
      limitations, the fix, and the verdict), `CLAUDE.md`'s Tests section and validation-bar
      entry, and `README.md`'s Z3 paragraph. `docs/rfc-001-signing.md` does not mention this
      proof at all (grepped, confirmed) — nothing to retire there.
      `docs/rfc-002-audit-remediation.md`'s slice-4 text is left as-is per its own
      instruction (it records the plan, not the outcome).

      **Gates:** `scripts/test.sh` green (all 13 unit test files, plain backend, no
      failures). `scripts/test-libsodium.sh` green (171 `[OK]`, includes the new parity
      property). `scripts/check-readme.sh` green (5/5 fences — touched for the Z3 paragraph
      edit). `scripts/ct.sh` full run clean on all five targets (numbers above);
      `docs/ct-results.md` updated. `scripts/bmc.sh` clean `sxUnsat` on all three
      `symexFind` calls (`oneStep`, `finalStep`, `wholeChainRecode`).
- [x] 5 Mutation testing (subject: "RFC-002 slice 5: mutation testing") — patch-based
      harness: `scripts/mutation.sh` (host wrapper, one podman invocation for the whole
      campaign so nimcache carries across mutants — roughly halved wall clock) +
      `tests/mutation/run_mutation.py` (exact-string OLD/NEW mutant applier — unified
      diffs rejected because no `diff`/`patch` exists in the base image, confirmed
      empirically, and exact-match fails loudly on source drift; scratch-copy isolation,
      compile-error kills classified separately from test kills) + 36 active `.mutant`
      files (18 field.nim: carry chains, shift off-by-ones, 19/0x7FFFFF/121666/clamp
      boundary constants, feBytesCanonical comparison flips, feCMove mask break; 18
      scalar.nim: group-law sign flips, vartime/cmovCached/recode boundaries, scIsCanonical
      flips, L-constant corruption, scReduce/scMulAdd shifts) + `docs/mutation-results.md`.
      **Final kill rate: 36/36 killed by test red, 0 by compile error, 0 survivors.**
      Two initial survivors, both resolved honestly: F05 (feToBytes q-seed 19→18) proven a
      GENUINE EQUIVALENT MUTANT via ~206k-case empirical sweep (the carry refinement fully
      re-derives the seeded estimate; q ∈ {0,1} absorbs the error) — retired to
      `tests/mutation/mutants/equivalent/` with evidence, not counted, not force-tested;
      S02 (geP2Dbl X+Y feAdd→feSub) exposed a REAL coverage gap — the mutant negates a
      single doubling but every existing call site doubles an even number of times so the
      sign cancels pairwise; killed by 2 new single-call `geP2Dbl` isolation tests in
      `test_scalar.nim` (verified red under the mutant before finalizing). Suite is now
      165 OK. Merged from worktree by the control loop; gates re-run on master post-merge.

## Open forks (awaiting Corey)
- none — all decisions resolved at RFC approval

## Key decisions (carried from the audit/approval conversation)
- verify parameter order: `verify(pk, msg, sig)` — RFC 8032 / dalek ordering, actor-first.
- Seed goes move-only BECAUSE `toBytes(kp)` removes the only copy-requiring API (`seed()`);
  the old copyability exemption was rationalizing a missing-toBytes corner.
- Fuzz in-process `{.cover.}` wrappers gave a 2-edge universe — coverage guidance was
  provably saturated/black-box; external SanitizerCoverage target is proptest's own shipped
  mechanism and keeps audited sources pragma-free.
- Z3 retry hypothesis CONFIRMED: prior OOM blamed on 32-byte symbolic extraction, not the
  carry chain; the free-nibble encoding (via tooling-compatible `int`/`var`-out-param
  re-encodings, needed to work around two empirical symex interprocedural-call limitations
  — see slice 4) proved `sxUnsat` in ~90s. The manual-induction caveat is retired.
- Mutation testing is sello-side patch-based (proptest mutation v1 is int->int only).
- Batch verification: disclose as considered/deferred now; feature is RFC-003 candidate.

## Review ledger (stage 4)
The stage-4 review ran 2026-08-08 as the combined RFC-002 + RFC-003 + round-3 review;
its ledger (R1–R18, floor reached, remediation committed `d1133e2`) is maintained in
`rfc-003-audit-round-2.handoff.md` — one ledger for one review, not duplicated here.
