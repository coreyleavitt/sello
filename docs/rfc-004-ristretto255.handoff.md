# RFC-004 Ristretto255 — handoff

- **Stage:** 4 (code review) — **FLOOR REACHED, round 6 clean
  (2026-08-14)**. Six rounds total: round-1 full review (five reviewers,
  five confirmed findings) → fix mandate approved by Corey (fix through
  Medium, leave Low) → rounds 2-6 fixed-and-re-reviewed until a round
  surfaced nothing above Low. Every C/H/M finding across all rounds is
  FIXED (see ledger); all fixes COMMITTED 2026-08-14 as the five commits
  listed in the Resume bullet below (Corey: "commit and push"), pushed to
  origin/main. Remaining Lows: NONE — Corey
  directed "fix lows" after the floor was reached, so finding 6
  (double-wipe redundancy: both scalar.nim functions now finally-only)
  and the frozen-RFC staleness (additive "Stage-4 review outcome"
  ledger section appended, 13cd03c precedent) were fixed too; round-6's
  cosmetic line-wrap was already reflowed inline. ZERO open findings at
  any severity. Final verification state: test.sh green exit 0
  (11 unit + 5 property files, 0 FAILED), mutation 73/73 killed 0
  survivors, check-readme 8/8 fences, all 73 mutant anchors verified
  exactly-once by script after every source edit.
- **Stage 3 record:** COMPLETE. RFC
  APPROVED by Corey 2026-08-13 after three architect rounds; every slice
  (1a through 8d) implemented, committed, and gated. Slice 8d closed out
  2026-08-14: facade/docs/close-out commit `a93bea2`. The slice-7b dudect
  tiebreaker gate — the one open item blocking close-out — resolved case
  (b) for both anomalous targets: see the 8d slice entry and "Open forks"
  below for the full record (`docs/ct-results.md`'s "RFC-004 slice 8d"
  section plus its control-diagnostic appendix are the permanent
  evidentiary record). Version stamped 0.4.0 (`milpa.kdl`/`sello.nimble`).
- **Resume:** RFC-004 COMPLETE — all four rfc-flow stages done. Stage-4
  fixes committed 2026-08-14 as five commits on main (approved by
  Corey: "commit and push"): 88cbe76 (feSqrtRatioM1 branchless
  combines), c49761d (scIsCanonicalCT + finally-only wipes), 7fa2348
  (RistrettoShared/Option arc), 36f7e64 (coverage + doc refresh), plus
  the docs close-out commit carrying this file. Ship gate satisfied
  (round 6: 0 critical/high; all Lows also fixed on Corey's direction).
  Nothing open. Next RFC starts with /clear per rfc-flow.
- **Resume (historical — grind loop context, slices 1a-8c):** grind loop
  ran through slice 8c, then slice 8d was picked up directly (not via the
  grind loop) per the RFC-flow's own stage-3-closeout convention (slice 8c
  implemented and
  committed 4249655 — ristretto255 FFI bindings added to
  `private/backend_sodium.nim` (`crypto_core_ristretto255_is_valid_point`/
  `_from_hash`, `crypto_scalarmult_ristretto255[_base]`,
  `sodium_library_version_major`/`_minor`) plus a differential suite in
  `test_libsodium_interop.nim`: every RFC 9496 Appendix A.1 (16)/A.2 (29)/
  A.3 (7 direct + 4 convergence) vector, deterministic scalarmult boundary
  cases (incl. libsodium's identity-refusal edge cases), 20 random-secret
  scalarmult checks, and a 3-property random-input sweep (50 examples each:
  decode verdict, hash-to-group value, scalarmult value) — all run through
  both sello and libsodium, verdict-and-value agreement, ZERO mismatches.
  Guarded by a runtime `libsodium >= 1.0.18` preflight assert
  ((major, minor) >= (10, 3), empirically derived from libsodium's own
  `configure.ac` at the 1.0.17/1.0.18 tags, not assumed — see the module doc
  comments). scripts/test-libsodium.sh green (11 unit files + 5 property
  files, this build's linked libsodium 1.0.22 / ABI (26, 4)); plain
  scripts/test.sh confirmed still on the no-op skip path. See the slice-8c
  ledger entry below for the full breakdown.
  Next: 8d facade + docs + close-out (see that ledger entry for the full
  scope). Slice 8a implemented and
  committed 4026895 — ristrettoDecode joins fuzz_external_target.nim as
  mode byte 3, dispatch arm mirrors pointDecode's determinism +
  accept-implies-identity-re-encode oracle shape; fuzz_common.nim/
  fuzz_main.nim gain the strategy/encoder pair (bytes32() reused) and
  ristrettoDecodeSeeds() — all 16 RFC 9496 Appendix A.1 valid encodings
  plus one Appendix A.2 reject vector per category; doc comments across
  the fuzz files and scripts/fuzz.sh updated three oracles/targets to
  four, incl. the per-target budget multiplier. Smoke campaign
  (scripts/fuzz.sh 20) clean: 354 coverage edges, 716 iterations, all 21
  corpus seeds accepted (0 dropped), 0 crashes; scripts/test.sh green (11
  unit files + 5 property files). Slice 7b implemented and
  committed 6b1cd47 — ristrettoScalarmult and ristrettoFromUniformBytes
  clean; `` `==` ``/ristrettoEncode verdict artifact-attributed by
  control-loop recommendation under the standing fork test, deciding
  quiet-host re-run gated at 8d — see "Open forks" for the full record and
  decision rule, Corey can veto; slice 7a finished and
  committed 5a00b26; slice 6 finished and
  committed 97fd40e; slice 5b finished and
  committed 3b8a778; torsion escalation RESOLVED 2026-08-14: Corey approved; RFC
  amended to E[4]-only + order-8 negative companion + [2]E/E[4] Context
  reframe in commit 13cd03c — see the RFC's "Stage-3 amendment
  (2026-08-14)" section; slice 4 finished and committed 7eadac7). If
  resuming cold:
  `/loop implement the next unimplemented RFC slice with /tdd, following the
  standing rules; after each slice report one progress line (e.g. "slice 4/15
  done, 11 remaining"); stop when every slice is implemented`
- **Grind mechanics:** subagents run one slice per iteration (sonnet,
  run_in_background), commit per slice on main, never pause idle waiting for
  notifications (recurring failure mode — instruct explicitly: foreground
  commands, timeouts up to 600000 ms, sleep-loop polling); no Co-Authored-By
  trailer, never mention agentic tooling in commits; ScheduleWakeup fallback
  heartbeat ~1500s with the /loop prompt verbatim.

## Slices (renumbered by round 1, split further by rounds 2 and 3)
- [x] 1a CT field primitives — commit c95bb16 (feSqrtRatioM1 THREE-check dance incl. false-branch
      root test, feEqualCT/feIsZeroCT, feBytesCanonicalCT — the CT canonicity
      check; the vartime feBytesCanonical is the named trap — feAbs, FeSqrtM1
      export, RFC 9496 **A.4** KATs — standalone, verify path untouched)
- [x] 1b symex_equal.nim — commit 4d7e223 (full 32-byte chain proved sxUnsat in
      ONE query; a FOURTH empirical walker limitation found and documented:
      literal-seeded accumulator chains crash the walker — seed from the first
      pair's own xor instead)
- [x] 1c verify-path migration — pointDecode rewritten on feSqrtRatioM1 (wasSquare
      accept gate, x=0-with-sign-bit reject, plain conditional negate since the
      root is already nonnegative), feSqrtRatioVartime deleted, the slice-1a
      vartime-agreement test and the feSqrtRatioVartime unit suite removed
      (A.4 KATs + defining-equation tests carry the coverage now). F21/F22
      retired (their target deleted) and replaced by F23/F24 against
      feSqrtRatioM1's own defect class (correction-select flip; feAbs
      normalization invert); E01/E03 re-anchored/re-cut onto the reshaped
      lines, E02 survived verbatim. scripts/test.sh green (Wycheproof zero
      change), scripts/mutation.sh 50/50 killed, 0 survivors.
- [x] 2 decode + equality — commit a2983c5 (ristretto.nim born: RistrettoPoint/
      RistrettoEncoded, ristrettoUnchecked door + debug curve-identity assert,
      CT quotient `==` via bitwise-or combine, ristrettoDecode on
      feBytesCanonicalCT/feSqrtRatioM1; A.1 16/16 against independent
      geScalarmultBase oracle, A.2 29/29 rejected; test_ristretto.nim
      registered, suite 10 → 11 files)
- [x] 3 encode — commit 5e80640 (A.1 encode direction incl. i=0 identity/
      SQRT_RATIO_M1(1,0) edge, InvSqrtAMinusD via mechanical decimal→LE-bytes
      from §4.1 + defining-equation check, RistrettoIdentity/RistrettoBasePoint
      consts CTFE-verified, round-trips, rejection-sampling generator;
      test_properties_ristretto.nim born AND registered, property tier 4 → 5)
- [x] 4 group ops — commit 7eadac7 (+/-/unary - via geCachedNegate; group-axiom
      unit + property tests; E[4]-only torsion invariance per the amended RFC —
      four T's built via ristrettoUnchecked, curve-equation + annihilated-by-4
      cross-checks, two fixed points deterministic + random-P property — and
      the deterministic order-8 NEGATIVE companion (offline-Python-derived
      T8 = L·G from a full-order-8L generator, on-curve + NOT annihilated by 4
      re-verified in Nim, encode(P+T8) != encode(P)). RED discipline caught
      two test-infra bugs: quotient `==` can't check literal identity (raw
      X==0,Y==Z compare used instead), and a proc-scoped `check` silently
      swallows unittest failures (testStatusIMPL is test-block-scoped —
      helper made a template). Generator rework kept: composing .filter()ed
      draws multiplies rejection rates and hits a coverageGuided engine
      pathology, so internal-retry + coverageGuided=false, documented in the
      test file. Preceded by RFC amendment commit 13cd03c resolving the
      torsion escalation (E/E[8] folklore → [2]E/E[4], dalek issue #312).
- [x] 5a static secret role + scalarmult existing registers — commit 07154f8
      (RistrettoStaticSecret: secretHooks, canonical-residue invariant,
      staticSecret()/staticPair()/Option-returning 32-byte import with
      both-paths wipe/toRistrettoStaticSecretWide (distinct name, not an
      overload)/wipe/toBytes, constructor-internal wipes, repr-disclosure line;
      ristrettoScalarmultBase (static) + ristrettoScalarmultVartime; boundary
      scalars 0/1/L−1/L incl. s=L via the wide constructor and the unreduced
      vartime path only; reject_secretscalar_ristretto_vartime fixture,
      subprocess-verified. ristrettoStaticPair() computes its public element
      inline (toSecretScalar/geScalarmultBase) rather than calling
      ristrettoScalarmultBase, since Nim requires the callee declared
      earlier in the module — the x25519.x25519StaticPair/ladder precedent.
      scripts/test.sh green: 11 unit files + 5 property files, zero
      failures, including the new agreement property and both new suites
      in test_ristretto.nim.)
- [x] 5b ephemeral secret role — commit 3b8a778 (RistrettoEphemeralSecret:
      secretHooksMoveOnly, canonical-residue-mod-L invariant via wide
      scReduce, ristrettoEphemeralSecret()/ristrettoEphemeralPair() (fresh
      from std/sysrand, no from-bytes route, no toBytes), the ElGamal/ECIES
      borrow-then-consume rationale and the CPace two-mults-one-scalar
      boundary recorded in the type's doc comment, borrow-only
      ristrettoScalarmultBase(RistrettoEphemeralSecret) overload (plain
      non-consuming parameter, the x25519Base(X25519EphemeralSecret)
      precedent); reject_ristretto_ephemeral_copy fixture,
      subprocess-nim-c-verified (injectdestructors rejects the copy).
      Pair/base-mult round-trip + probe-pattern destructor hygiene tests in
      test_ristretto.nim. sink-consume ristrettoScalarmult overload and
      reuse fixture deferred to 7a as scoped. scripts/test.sh green: 11
      unit files + 5 property files, zero failures, 271 [OK] checks.)
- [x] 6 hash-to-group — commit 97fd40e (ristrettoMap, RFC 9496 SS4.3.4's
      MAP function, private; ristrettoFromUniformBytes, total, splits its
      64-byte input and adds the two mapped halves; OneMinusDSq/
      DMinusOneSq/SqrtAdMinusOne via compile-time feFromBytes from the
      published RFC's own decimal values, each cross-checked in-test
      against its defining field equation — InvSqrtAMinusD already landed
      in slice 3. Formula and constants pre-verified against an
      independent Python transcription of RFC 9496 SS4.3.4/SS4.1 before
      writing the Nim, fetched directly from rfc-editor.org (not
      summarized/memory) per the task's own warning about mangled KAT
      hex. All A.3 vectors bit-exact: the six direct input/output pairs
      plus the four-inputs-one-output convergence set (checked equal
      under byte encoding AND cross-checked pairwise equal under quotient
      `==`); deterministic all-zero/all-0xFF 64-byte edge inputs
      (re-decode cleanly); determinism + valid-output properties over
      random 64-byte inputs via proptest. scripts/test.sh green: 11 unit
      files + 5 property files, zero failures.)
- [x] 7a CT variable-base scalarmult — commit 5a00b26 (scalar.geScalarmultCT:
      UNIFORM 256-doubling interleaved ladder, identity start, no
      initial-load special case; runtime 8-entry GeCached table
      (1P..8P) via geAdd→geP1P1ToP3→geP3ToCached — scalarmultVartime's
      own table-build pattern, public, not CT; per-digit lookup via
      unchanged cmovCached; wipe list — sBytes, digits, acc, and the two
      per-iteration temporaries u/step, declared once outside the loop
      and wiped once after (geScalarmultBase's own pattern) — debug-only
      bit-255 assert; written loop-composition argument in the module doc
      (shape/selection/recoding, the symex_reduce decline precedent);
      geP3Identity helper added and used to consolidate the THREE inline
      identity constructions (scalarmultVartime, geScalarmultBase, and
      this function). ristrettoScalarmult: plain borrow overload
      (RistrettoStaticSecret) + sink-consuming overload
      (RistrettoEphemeralSecret, the ElGamal/ECIES borrow-then-consume
      shape); reject_ristretto_ephemeral_reuse fixture,
      subprocess-nim-c-verified. Three-way agreement (CT variable-base vs
      vartime, and at the base point vs CT fixed-base) as deterministic
      AND property tests, plus boundary scalars (0, 1, L-1, L) on the
      variable-base path, plus direct scalar.nim-level coverage of
      geScalarmultCT against scalarmultVartime over several arbitrary
      points. Side-quest finding: cross-checking geScalarmultCT against
      scalarmultVartime at s=0 via pointEncode caught a pre-existing bug
      in scalarmultVartime — for an all-zero scalar the digit loop never
      assigned its `var r: GeP3` output param, so callers got Nim's
      implicit all-zero object instead of the identity; masked in prior
      coverage because RistrettoPoint's quotient `==` degenerately treats
      the all-zero representation as equal to the identity. Fixed by
      seeding the accumulator with the identity up front; regression-
      pinned via pointEncode comparison (test_scalar.nim), which does not
      share that blind spot. scripts/test.sh green: 11 unit files + 5
      property files, zero failures, 303 [OK] checks, Wycheproof
      unchanged.)
- [x] 7b timing battery — commit 6b1cd47 (FOUR dudect targets added to
      ct_main.nim: ristrettoScalarmult, ristrettoEncode, `==` with
      (P,P)-vs-(P,Q) classes, ristrettoFromUniformBytes; inline
      rejection-sampling point generator. ristrettoScalarmult and
      ristrettoFromUniformBytes PASS cleanly and consistently across every
      run taken. ristrettoEncode and `==` do NOT have a clean standing
      verdict: `==`'s naive single-call design (the RFC's own specified
      class shape) FAILed in two full-battery runs; extensive investigation
      (three rounds of batched-measurement redesigns plus two non-shipped
      diagnostics, full writeup in docs/ct-results.md) proved the signal is
      NOT verdict-dependent (a fixed-but-always-unequal control target
      showed an equally large spurious |t|) and traced it to the harness's
      own fixed-vs-random class construction becoming visible against this
      operation's unusually small per-call cost (~800-900 cycles, 30-600x
      smaller than every other target) — not a secret-dependent branch or
      index in the implementation, which is provably straight-line CT code.
      No batched design achieved a clean full-battery pass, so the shipped
      code reverts to the simple single-call design. A final confirmation
      run showed `==` land in WARN (not FAIL) and ristrettoEncode ALSO show
      WARN for the first time, alongside an unrelated PRE-EXISTING target
      (x25519 static DH, previously always clean) failing in that same
      run — read as evidence of run-level noise beyond what the preflight
      banner captured, not a new independent finding, but this means the
      standing verdict for two of the four new targets is genuinely
      ambiguous across runs rather than a confirmed clean pass. RESOLVED BY
      CONTROL-LOOP RECOMMENDATION (2026-08-14, Corey can veto): artifact-
      not-leak per the control-target + run-level-noise evidence; grind
      proceeds to 8a; the deciding re-run is a GATE AT 8D (see 8d entry) —
      7b stays [~] until that re-run lands.
      The 8D re-run landed 2026-08-14: `` `==` `` FAILed again (t=51.45),
      cleanly within the anticipated sub-1000-cycle carve-out and
      consistent with everything above; `ristrettoEncode` was CLEAN this
      time (PASS, t=1.08); but `x25519(X25519StaticSecret, peer)` FAILed a
      SECOND time (t=-15.53, closely matching Run E's t=-16.49) — the same
      co-occurrence pattern as before, on a host with 19 unrelated
      containers present. That target sat outside the gate's sub-1000-cycle
      scope and had no dedicated non-verdict-dependence proof of its own,
      so this was reported as a BLOCKER pending a diagnostic. **RESOLVED
      (2026-08-14, same day): a dedicated standalone control diagnostic**
      (`docs/ct-results.md`'s slice-8d appendix — random-vs-random plus
      three independent fixed-vs-fixed-different secret-value pairs, five
      trials at 1e6 samples/class each, ALL PASS, worst |t| 0.680-2.652,
      an order of magnitude under the pass band) supplied for
      `x25519(X25519StaticSecret, peer)` the same class of direct evidence
      `` `==` `` already had, verdict ARTIFACT. **7b RESOLVED-WITH-CARVE-OUT:
      both anomalous targets accept under decision-rule case (b)** — see
      `docs/ct-results.md`'s "RFC-004 slice 8d" resolution paragraph and
      its control-diagnostic appendix for the full record. Neither target
      has a clean full-battery PASS on file from this 19-20-container
      shared-host era; the carve-out record (the artifact investigation
      for `` `==` ``, the standalone control diagnostic for the
      static-secret target) is the accepted evidence instead, per the same
      "not every operation fits this instrument" register `ristrettoDecode`'s
      own disclosure-only carve-out established.
- [x] 8a fuzzing — commit 4026895 (ristrettoDecode joins
      fuzz_external_target.nim as mode byte 3; dispatch arm mirrors
      handlePointDecode's shape exactly: determinism (two calls agree on
      Some/None and on the decoded value's re-encode) plus accept implies
      IDENTITY re-encode — ristrettoEncode(ristrettoDecode(e).get) == e,
      RFC 9496's own canonical-encoding contract, not an incidental
      self-consistency check. Driver side: encodeRistrettoDecode +
      bytes32() reused as the strategy (a ristretto255 encoding is a bare
      32-byte candidate like an Edwards point encoding, no new strategy
      type needed); ristrettoDecodeSeeds() in fuzz_common.nim seeds all 16
      RFC 9496 Appendix A.1 valid encodings plus one Appendix A.2 reject
      vector from each of the five categories (non-canonical, negative
      field element, non-square x^2, negative x*y, s=-1/y=0), so mutation
      explores the accept boundary from both sides. Doc comments in both
      fuzz files and scripts/fuzz.sh updated from "three oracles"/
      "x 3" to four, incl. the per-target time-budget multiplier. Smoke
      campaign (scripts/fuzz.sh 20) clean: ristretto.ristrettoDecode hit
      354 coverage edges over 716 iterations, all 21 corpus seeds
      accepted (0 dropped), 0 crashes; the pre-existing three targets
      unaffected (291-560 edges each, 0 crashes). scripts/test.sh green:
      11 unit files + 5 property files, zero failures.)
- [x] 8b mutation — commit dc42755 (20-mutant batch, catalog 50 -> 70, all
      RFC-named targets covered: geScalarmultCT (S21 doubling-count
      off-by-one, S22 table-build select flip, S23 accumulator-seed error
      -- the same defect class 7a's own side-quest caught in
      scalarmultVartime, reproduced deliberately here, S24 digit-sign
      flip), feSqrtRatioM1's three checks flipped individually (F28/F29/F30,
      distinct from F23/F24's correction-select/final-abs targets),
      feEqualCT's or-to-and accumulate (F26) plus feBytesCanonicalCT's own
      copy of the same defect (F27, in-scope judgment call: same shape,
      distinct function, decode's canonicity gate), feAbs's CT_ABS
      condition flip (F25), ristrettoDecode's five RFC 9496 SS4.3.1
      reject-condition flips (R01-R05), ristrettoEncode's rotation and
      negation condition flips (R06/R07), RistrettoPoint `==`'s top-level
      bitwise or-to-and combine flip (R08, doubling as the anchor on the
      bitwise-combine shape the RFC names), and ristrettoMap's two
      was_square select flips (R09/R10, s and c). Side-quest finding: S07
      (scalarmultVartime's pre-existing loop-bound mutant) was silently
      broken by slice 7a's unrelated addition of geScalarmultCT -- that
      function's own 'for i in countdown(63, 0):' loop (4-space indent)
      collided with S07's 2-space-indent OLD block under plain substring
      matching (run_mutation.py's Mutant.apply uses str.count, not
      line-anchored matching), so any run touching S07 would have aborted
      with a hard ">1 occurrences" RuntimeError before this slice.
      Re-anchored to a two-line OLD block scoped to scalarmultVartime's own
      loop body (the round-3 batch A re-anchoring precedent); same target,
      same defect class, no other existing mutant found affected by the
      same collision class in a full-catalog re-verification pass.
      scripts/mutation.sh: 70/70 killed (all KILLED (test), 0
      compile-error, 0 timeout), 0 survivors, 566s wall clock.
      scripts/test.sh green: 11 unit files + 5 property files, 303 [OK]
      checks.
- [x] 8c libsodium differential KATs — commit 4249655 (`private/backend_sodium.nim`
      gains four ristretto255 oracle wrappers over libsodium's own API
      (`sodiumRistrettoIsValidPoint`/`sodiumRistrettoFromHash`/
      `sodiumRistrettoScalarmult`/`sodiumRistrettoScalarmultBase`) plus
      `sodiumLibraryVersion` (the runtime `sodium_library_version_major`/
      `_minor` query) — all four oracle wrappers oracle-only, never
      `signing.nim`'s dispatch, matching `sodiumVerifyDetached`/
      `sodiumScalarmult`'s existing register. `test_libsodium_interop.nim`
      adds: an up-front module-init `doAssert` gating on
      `(major, minor) >= (10, 3)` (libsodium >= 1.0.18, the release that
      shipped `crypto_core_ristretto255_*`/`crypto_scalarmult_ristretto255`
      — confirmed directly against libsodium's own `configure.ac` at the
      1.0.17 (10, 2) and 1.0.18 (10, 3) tags, not assumed); A.1 (16
      encodings) decode-verdict agreement via
      `crypto_core_ristretto255_is_valid_point`; A.2 (29 reject vectors
      across all five categories) verdict agreement; A.3 (7 direct pairs +
      4 convergence-set inputs) value agreement via
      `crypto_core_ristretto255_from_hash`; scalarmult value agreement via
      `crypto_scalarmult_ristretto255[_base]` — deterministic scalars
      (0, 1, 2, L-1, L, L+1) against both the base point and a fixed
      non-base point, plus 20 random-`RistrettoStaticSecret` base-mult and
      variable-base-mult checks; and a 3-property random-input sweep
      (`maxExamples = 50` each, matching the round-3 B1 sweep style):
      decode verdict, hash-to-group value, and scalarmult value agreement
      on uniformly random inputs. Scalarmult agreement uses a
      probe-verified predicate, not raw byte equality: libsodium's
      `crypto_scalarmult_ristretto255[_base]` documents (and this slice's
      own C probe against the sello-dev image's libsodium 1.0.22 directly
      confirmed) that it REFUSES — returns -1, no output — whenever the
      literal scalar multiple is the identity element, including simply
      because the scalar is zero mod L; sello's scalarmult family carries
      no such carve-out and returns `RistrettoIdentity` as an ordinary
      result, so agreement is `(sodium succeeded and bytes match) or
      (sodium failed and sello's result is RistrettoIdentity)` — see
      `sodiumRistrettoScalarmult`'s doc comment for the full empirical
      writeup. Vector values transcribed independently into the test file
      (not imported from `test_ristretto.nim`'s private consts), per the
      `fuzz_common.nim` per-module-transcription precedent. Zero
      mismatches across every suite. scripts/test-libsodium.sh green: 11
      unit files + 5 property files (this run's linked libsodium 1.0.22,
      ABI (26, 4)); scripts/test.sh confirmed unaffected — plain build
      stays on `test_libsodium_interop.nim`'s existing no-op skip path (no
      `sello/ristretto`/`sello/scalar`/`backend_sodium` import reached).)
- [x] 8d facade + docs + close-out — commit `a93bea2` (2026-08-14).
      ENUMERATED facade exports (`src/sello.nim`) + `test_facade.nim`
      reachability suite + declared-effect extension (four OSError pins,
      "the five" becomes nine) + `RistrettoEncoded` into the named hash/$
      suites + nominal-typing negative-compile cases + the Pedersen
      commit/open worked-consumer scenario test (`test_ristretto.nim`,
      asserted against the facade surface only) + `ristretto.nim`'s module
      doc finalized (CT posture, Schnorr/OPRF-client boundary,
      hash-the-encoding rule, encode-then-compare timing rule) + NOTICE
      RFC 9496 attribution + README (Ristretto255 section, stale "What's
      not here" bullet replaced) + CHANGELOG 0.4.0 entry (also backfills
      the never-entered `0.3.1` tag's two changes) + CLAUDE.md
      (architecture #6, implementation status, script/test inventory,
      validation-bar entries) + version bumped to 0.4.0
      (`milpa.kdl`/`sello.nimble`). `scripts/check-readme.sh` clean (7
      fences). Full six-script matrix GREEN:
      `scripts/test.sh` (11 unit + 5 property files, 0 failures),
      `scripts/test-libsodium.sh` (same, plus ristretto255 differential
      KATs, 0 mismatches), `scripts/mutation.sh` (70/70 killed, 0
      survivors), `scripts/bmc.sh` (all four symex files `sxUnsat`,
      including the new `symex_equal.nim`), `scripts/fuzz.sh 20` (0
      crashes across 4 targets incl. `ristrettoDecode`, coverage gate
      passed), and `scripts/ct.sh` (the 7b tiebreaker — see below).
      **GATE RESOLVED (case b, both anomalous targets):** the
      `scripts/ct.sh` tiebreaker run (19 unrelated containers present on
      this shared host, load average 0.94-1.33 — the lowest load recorded
      to date but the highest container count) produced
      `` ristretto.`==` `` FAIL (t=51.45, cleanly within the
      sub-1000-cycle carve-out, consistent with the already-proven
      artifact) AND `x25519(X25519StaticSecret, peer)` FAIL (t=-15.53,
      NOT sub-1000-cycle, initially lacking a rigorous
      non-verdict-dependence diagnostic the way `` `==` `` had one). A
      dedicated standalone control diagnostic run the same day (appended
      to `docs/ct-results.md` as its slice-8d appendix: random-vs-random
      plus three fixed-vs-fixed-different secret-value pairs, five trials
      at 1e6 samples/class, ALL PASS, worst |t| 0.680-2.652) supplied that
      missing evidence, verdict ARTIFACT — closing the gap and landing
      both targets under decision-rule case (b). Neither target has a
      clean full-battery PASS on file from this shared-host era; the
      carve-out record (the artifact investigation for `` `==` ``, the
      control diagnostic for the static-secret target) is the accepted
      evidence instead, per the same "not every operation fits this
      instrument" register `ristrettoDecode`'s own disclosure-only
      carve-out established. Full numbers, environment detail, and
      analysis in `docs/ct-results.md`'s "RFC-004 slice 8d: the 7b
      tiebreaker run" section and its control-diagnostic appendix.

## Open forks (awaiting Corey)
- **Slice 7b `` ristretto.`==` ``/`ristrettoEncode` dudect standing
  verdict — RESOLVED 2026-08-14 (kept for history; superseded by the
  tiebreaker entry immediately below).** Full
  investigation in `docs/ct-results.md` ("RFC-004 slice 7b: four
  ristretto255 dudect targets"). Summary: `` ristretto.`==` ``'s naive
  single-call RFC-specified class design FAILed twice; a rigorous,
  multi-round investigation (three batched-measurement redesigns, two
  non-shipped diagnostics) proved the signal does NOT track the
  comparison's actual TRUE/FALSE verdict (a fixed-but-always-unequal
  control target showed an equally large spurious |t|), pointing instead
  at a harness resolution-floor artifact for very fast primitives
  (~800-900 cycles, 30-600x smaller than every other dudect target in this
  codebase) rather than a genuine secret-dependent leak — the source is
  provably straight-line CT code built on already machine-checked
  primitives. No batched redesign achieved a clean pass at full-battery
  scale, so the shipped code reverted to the simple design. A final
  confirmation run landed `` `==` `` in WARN (not FAIL) but also showed
  `ristrettoEncode` WARN for the first time and an UNRELATED, previously
  always-clean pre-existing target (`x25519(static) vs peer`) FAIL in that
  same run — evidence of broader run-level noise, but it means neither
  target has a clean, reproducible PASS on file yet. RESOLVED BY
  CONTROL-LOOP RECOMMENDATION under the standing fork test (2026-08-14;
  Corey can veto): the evidence is confidently artifact-not-leak (signal
  proven NOT verdict-dependent via the always-unequal control; source is
  straight-line CT on machine-checked primitives; a historically-clean
  unrelated target failed in the same run). The grind PROCEEDS to 8a-8c
  (none interact with the timing verdict); the deciding tiebreaker — one
  full battery on a verified-quiet host — is a GATE at 8d with an explicit
  decision rule (clean → done; artifact-consistent WARN/FAIL → documented
  resolution-floor carve-out per the decode precedent; verdict-dependent
  signal → STOP and escalate before 0.4.0). Slice 7b stays [~] until that
  run. Implementation commit: 6b1cd47. **Superseded by the entry
  immediately below** — the tiebreaker run has landed and the gate
  resolved case (b) for both anomalous targets.
- **Slice 8d's ct.sh tiebreaker — RESOLVED 2026-08-14 (kept for
  history).** The deferred re-run above landed on a host with 19
  unrelated, unstoppable (not this task's to kill) containers present —
  the lowest load average on file (0.94-1.33) but the highest container
  count. Results (full numbers/environment detail in
  `docs/ct-results.md`'s "RFC-004 slice 8d: the 7b tiebreaker run"
  section): `` ristretto.`==` `` FAILed again (t=51.45) — cleanly within
  the anticipated sub-1000-cycle carve-out (mean ~839 cycles) and fully
  consistent with the already-proven artifact-not-leak finding above;
  `ristrettoEncode` was CLEAN this time (PASS, t=1.08, no carve-out
  needed); `ristrettoScalarmult`/`ristrettoFromUniformBytes` clean as
  always. The open problem at the time: `x25519(X25519StaticSecret, peer)`
  — pre-existing code, untouched by RFC-004, previously clean in every run
  except the one Run E co-occurrence recorded above — FAILed a SECOND time
  (t=-15.53, closely matching Run E's t=-16.49; same direction, same
  co-occurrence-with-ristretto-anomalies pattern, same
  heaviest-shared-host-on-file circumstance), outside the gate's
  sub-1000-cycle carve-out scope and, at that point, resting only on
  circumstantial ("probably run-level noise") inference rather than a
  direct diagnostic the way `` `==` `` had one — reported as a BLOCKER
  pending option (3) below rather than resolved unilaterally.
  **RESOLUTION:** option (3) was executed the same day — a dedicated
  standalone control diagnostic (`docs/ct-results.md`'s slice-8d appendix:
  random-vs-random plus three independent fixed-vs-fixed-different
  secret-value pairs, five trials at 1e6 samples/class each, ALL PASS,
  worst |t| 0.680-2.652, an order of magnitude under the pass band and
  nowhere near the 15.53-16.49 campaign-FAIL magnitude) supplied for this
  target the same class of direct non-verdict-dependence evidence
  `` `==` `` already had. Verdict ARTIFACT. Both anomalous targets now
  resolve under decision-rule case (b); see `docs/ct-results.md`'s
  resolution paragraph and appendix for the full record. Commit
  `a93bea2`. Neither target has a clean full-battery PASS on file from
  this shared-host era — the carve-out record (this diagnostic, plus the
  `` `==` `` investigation) is the accepted evidence instead, the same
  register `ristrettoDecode`'s own disclosure-only carve-out already
  established for this document. Stage 3 is COMPLETE; resume command is
  `/code-review rfc-004`.
- The slice-4 torsion wrong-spec escalation was RESOLVED 2026-08-14:
  Corey approved the recommended amendment (E[4]-only invariance + order-8
  negative companion + [2]E/E[4] Context reframe), applied in RFC commit
  13cd03c and implemented/committed in slice-4 commit 7eadac7 — see the RFC's
  "Stage-3 amendment (2026-08-14)" section for the full record. All three rounds resolved every finding with confident recommendations
  under the standing fork test; Corey's stage-2 approval of the RFC as a whole
  is the only remaining gate and can veto any of them. Round 3's four
  reversals/renames of round-1/2-recorded details (Scalarmult stem rename,
  toRistrettoStaticSecretWide rename, wipe(RistrettoPoint) dropped, ephemeral
  rationale re-founded on the ElGamal shape) are flagged in the RFC's Round-3
  changes list specifically so the approval pass sees them.

## Round-3 changes (on top of rounds 1–2 — re-litigate none of the three lists)
- BLOCKING sequencing bug fixed: InvSqrtAMinusD moved into the encode slice
  (slice 3) — the slice list built all four constants in slice 6, strictly
  after encode needs this one.
- feBytesCanonicalCT specified (slice 1a): the vartime feBytesCanonical named
  as the trap; CT construction = re-encode round-trip + or-accumulate; decode's
  dudect carve-out means nothing measured would have caught the silent
  violation of the CT-by-construction headline.
- A.3 corrected against the published RFC: six direct pairs + the
  four-inputs-one-output convergence set ("both labeled inputs" undercounted a
  zero-tolerance gate).
- Effects convention (previously silent): standard push on ristretto.nim, four
  sysrand constructors get {.raises: [OSError].}, test_facade effect pins grow
  accordingly (new Effects subsection in the RFC).
- RENAMED: ristrettoScalarmult/ScalarmultBase/ScalarmultVartime (round 2's bare
  Mult stem failed the audit-grep test the ristretto prefix is justified by);
  toRistrettoStaticSecretWide (reject-vs-reduce must be call-site visible —
  dalek's separate-name discipline, not array-length overload resolution).
- DROPPED: wipe(RistrettoPoint) (X25519Public public-role precedent; no
  destructor net = silently weaker contract than every sibling wipe; the
  commitment/blinded-element consumers are hiding by construction).
- RistrettoEphemeralSecret KEPT with a proof-spiked rationale: ElGamal/ECIES
  encryption over the group fits borrow-then-consume exactly; CPace-style PAKE
  (two variable-base mults, same scalar) provably cannot use a move-only type
  and routes to RistrettoStaticSecret + wipe, documented as the honest
  boundary.
- Dual `==` timing registers confronted: encoding `==` is vartime, point `==`
  is CT, operators can't carry Vartime — doc/README must state
  "timing-sensitive equality compares points, never encodings."
- OPRF honesty: client unblinding needs mod-L scalar inversion, which exists
  nowhere in sello; v1 serves the OPRF server role only (Context qualified,
  Non-goals extended). Pedersen commit/open worked-consumer scenario test
  added to 8d (proof-spike register — asserted, not just compile-checked).
- Slices resized: 1a split (symex → 1b, verify migration → 1c), 5 split
  (5a/5b), 8a split (fuzz/mutation), close-out now 8d.
- Feasibility pins: 7a table-build conversion chain stated
  (geAdd→geP1P1ToP3→geP3ToCached); cmovCached's built-in signed-digit negation
  confirmed (no new CT negate helper for the ladder); libsodium ≥ 1.0.18
  assert; fixture wall-clock budgeted; 32-byte import none-path wipe stated;
  RistrettoEncoded into the named hash/$ suites; README stale-bullet removal;
  array[64] checked-copy idiom doc obligation; unary-minus whitespace pinned;
  repr-disclosure line on the secret role types.

## Round-2 changes (on top of round 1 — re-litigate neither list)
- RFC 9496 Appendix **A.4** (SQRT_RATIO_M1 KATs) added to slice 1a — round 1's
  battery cited only A.1–A.3 (verified against the published RFC, not memory).
- "test_properties_ristretto.nim picked up by the existing glob" was FALSE
  (unit-test-files.sh is a hand-maintained array; its one pattern-match is a
  proptest skip-filter). Registered in slice 3, plus a deterministic
  non-proptest torsion spot-check in slice 4 so the quotient construction can
  never silently go unverified.
- Secret role SPLIT: RistrettoStaticSecret + RistrettoEphemeralSecret
  (move-only, fresh-only) — the X25519 ledger-#29 lesson applied while free;
  32-byte import now REJECTS non-canonical (Option/scIsCanonical, dalek
  from_canonical_bytes register), 64-byte wide stays total;
  ristrettoStaticPair() added; ristrettoBaseMult renamed ristrettoMultBase
  (modifier-after-stem).
- geScalarmultCT pinned to the UNIFORM loop: 256 doublings + 64 adds, identity
  start, no initial-load special case (round 1's "~252" assumed an unstated
  idiom); wipe list extended to the per-iteration cmovCached output and
  completed-point temp (R15 class).
- `==` dudect classes redesigned: (P,P)-fixed vs (P,Q)-random — round 1's shape
  could pass without ever timing the match path.
- pointDecode composition recipe regained RFC 8032's x=0-with-sign-bit reject.
- symex register explicit: symex_equal.nim (feEqualCT accumulate, slice 1a) +
  recorded declines with rationale (feSqrtRatioM1 — A.4 vectors are the right
  instrument; geScalarmultCT whole loop — written argument, symex_reduce
  resource-wall precedent).
- Mutation catalog extended to the new primitives themselves; fuzz wiring
  mechanics named; facade surface enumerated symbol-by-symbol; nominal-typing
  negative-compile fixtures; NOTICE + inline RFC 9496 attribution ritual;
  ristrettoUnchecked debug curve-identity assert; wipe(RistrettoPoint)
  copy-escape doc; hash-the-encoding rule (no hash(RistrettoPoint)); vartime
  `==` considered-and-declined; module-doc obligations assigned;
  constructor-internal wipes specified; ct_main inline point generator
  sanctioned (pre-measurement); slice 8 split into 8a/8b/8c; ordering corrected
  to 4-before-5 (L−1 → −P needs unary `-`).

## Round-1 changes (kept for context)
- Slice-7 ladder REDESIGNED: geScalarmultBase's odds/×16/evens shape is wrong
  for a single unscaled runtime table (it depends on per-row 16^(2j)
  pre-scaling); now interleaved 4-doublings-per-digit, living in scalar.nim as
  geScalarmultCT (keeps geP3Double private, ristretto.nim stays a pure wrapper).
- feSqrtRatioM1 corrected to the spec's THREE-check structure; the false-branch
  root (consumed only by slice 6's MAP, invisible to every RFC 8032/Wycheproof
  vector) gets a direct slice-1a test against root² == SQRT_M1·u/v.
- RistrettoSecret role type (secretHooks, always reduced mod L) replaced
  "callers use scalar.SecretScalar" — facade-unreachable, hygiene-free, and an
  unreduced scalar would SILENTLY compute a wrong multiple (out-of-range
  radix-16 digit → cmovCached contributes identity). (Split into
  static/ephemeral by round 2.)
- feEqualCT/feIsZeroCT primitive (field.nim had no CT equality); `==` combine
  specified as bitwise or (Nim's boolean or/and are short-circuit).
- ristrettoUnchecked door added (feFromLimbs-style) — without it slice 2 could
  only test accept/reject and slice 4's torsion property was unwritable.
- Constants mechanism switched to compile-time feFromBytes from RFC 9496's own
  bytes (no hand limb conversion; GeBaseTable proves the VM handles it).
- dudect: four targets not one; decode disclosure-only (attacker-public input).
- Identity/basepoint became consts; `*` operator declined (can't carry Vartime
  suffix); prefix naming kept with recorded rationale; CT `==` default confirmed
  with documented threat model.
- Slices split 1→1a/1b and 7→7a/7b; `==` moved into slice 2 as decode's oracle;
  random-element generator pinned (rejection-sampled decode); boundary scalars,
  map edge inputs, identity-encode edge named.
- Rituals wired in: unit-test-files.sh registration (slice 2), check-readme.sh,
  E01–E03 blast radius, libsodium differential KATs, ristrettoMultVartime
  return type pinned, Option/std-options convention stated, scMulAdd/Schnorr
  boundary documented honestly in non-goals (declined export).

## Key decisions (pre-round-1, still standing)
- CT posture: decode/encode/equality/map CT by construction (feCMove selects);
  verdicts caller-visible by design (stated at the headline claim)
- One sqrt-ratio implementation: pointDecode migrates, feSqrtRatioVartime deleted
- ristretto.nim sits on field.nim + scalar.nim only, no nimcrypto (caller
  hashes), types stay in-module per the x25519.nim precedent
- No Wycheproof corpus exists for Ristretto — A.2 + A.4 + fuzz + libsodium
  differential carry the adversarial weight, disclosed honestly

## Review ledger (stage 4)
Round 1 complete (2026-08-14): five reviewers (crypto correctness,
security, design & ergonomics, test coverage, Nim semantics) over
`8b9ed64..a93bea2`; all five significant findings adversarially verified
CONFIRMED (none refuted). Presented to Corey 2026-08-14; mandate
approved: fix 1-5, leave 6. Statuses below track the fix loop.

| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| 1 | H | `feSqrtRatioM1` combines secret-derived bools with Nim's short-circuit `or` at `field.nim:834` (`flippedSignSqrt or flippedSignSqrtI` into `feCMove`) and `field.nim:838` (`wasSquare`) — a secret-dependent branch inside a function whose doc claims none. Verifier CONFIRMED at machine-code level: under the project's exact release flags (gcc -O3), both sites survive as real conditional jumps in `feSqrtRatioM1`'s disassembly. Reaches measured secret paths (`ristrettoEncode`, `ristrettoFromUniformBytes` via `ristrettoMap`). Magnitude likely below dudect's resolution floor (function dominated by `fePow22523`), but the project bar is branchless-by-construction. Only instance of the class (grep-verified). Fix: the `==` idiom — `bool(uint8(a) or uint8(b))` at both sites. | fixed (committed) | both sites rewritten + doc note; F23 mutant re-anchored (only collision); test.sh green, mutation 70/70 killed |
| 2 | H | `toRistrettoStaticSecret` (`ristretto.nim:678`) validates imported SECRET key bytes with vartime early-exit `scIsCanonical` (`scalar.nim:997`, MSB-first byte loop, returns at first divergence from L) — leaks prefix-match-length of the secret against L via timing on every import of a persisted key. Same hazard class this RFC fixed on the field side (`feBytesCanonicalCT`, whose doc says "never on secret-derived data"); no CT scalar sibling exists; dalek's `from_canonical_bytes` is CT. Practical per-query yield small (loop exits on byte 31 with p=255/256) but it is the codebase's hard-rule class, and the path has zero dudect coverage. Fix: add CT `scIsCanonicalCT` (or-accumulate/CT-borrow, `feBytesCanonicalCT`'s shape) + route import through it; `ed25519.verify`'s vartime call stays (public data, correct). | fixed (committed) | `scIsCanonicalCT` added (32-byte CT subtract-with-borrow, uint32, no data branch), import rerouted, vartime warning doc added; RED/GREEN verified; boundary+500-random agreement suite in test_scalar.nim; new mutant S25, mutation 71/71 killed; test.sh green; symex coverage DECLINED with recorded rationale (symex_reduce composition resource-wall precedent) |
| 3 | M | DH-shared-secret hygiene gap: `ristrettoScalarmult` returns bare `RistrettoPoint` — no `=destroy`, no `wipe` path — yet in the module's OWN ElGamal/ECIES flow (the `RistrettoEphemeralSecret` sink-consume doc) that return value S = k·P IS the shared secret, the exact role `X25519Shared` (secretHooks + wipe overload) exists to protect. The "no wipe on RistrettoPoint" rationale (`ristretto.nim:128-144`) covers commitments/blinded elements only and is silent on the DH case; none of the three architect rounds caught it (round-3 finding 7 and finding 8 never cross-referenced). Caller workaround today wipes only a copy, not the original. Fix direction (Corey may prefer either): a wiped `RistrettoShared`-style return for the consuming overload mirroring `X25519Shared`, or an explicit documented post-processing idiom + doc-comment carve-out naming the trap. | fixed (committed) | `RistrettoShared` added (bytes-holding, secretHooks/toBytes/wipe, exact X25519Shared mirror); sink-ephemeral `ristrettoScalarmult` returns it, intermediate GeP3 product now wiped in `finally`; static overload deliberately unchanged (publish-register consumers) with CPace/static-DH encode-and-wipe idiom documented; recorded design rationale: module promises ECIES-style KDF flow, ElGamal point-add is outside Non-goals, point-needing callers route to static role. Facade export + effect pins + 3 new suites (DH agreement, hygiene probe, toBytes roundtrip), RED/GREEN verified; README ECIES example (check-readme.sh 8/8 fences), CLAUDE.md updated; test.sh green; mutation audit: no anchored text touched, no run needed |
| 4 | M | RFC-promised property never implemented: `docs/rfc-004-ristretto255.md:544` lists "equality-operator consistency with encoding equality" among `test_properties_ristretto.nim`'s required properties; no such test exists (file never touches `RistrettoEncoded`). Only a fixed four-point deterministic analog exists (`test_ristretto.nim:760-765`). Fix: add the property — random p, q: `(p == q) == (encode(p) == encode(q))`. | fixed (committed) | new suite in test_properties_ristretto.nim: random-pair consistency + equal-case via (a+b)G vs aG+bG distinct derivations; RED-verified (inverted assertion produced a genuine counterexample); test.sh green |
| 5 | M | `geCachedNegate` (`ristretto.nim:531-551`, backs both `-` operators — new RFC-004 arithmetic) has NO mutation-catalog entry; no mutant touches it (grep of all 70). Behavioral inverse tests (`P + (-P) == identity` on non-degenerate points) would likely kill a real defect, so a catalog gap, not an unguarded blind spot — but the validation bar's mutation register names exactly this class of new arithmetic. Fix: one swap-omission mutant (e.g. `result.yPlusX = q.yPlusX`), verified red-then-killed. | fixed (committed) | R11_gecachednegate_yplusx_noop added (unique-match verified against post-fix-3 source); mutation 72/72 killed, 0 survivors; R11 KILLED (test) by test_facade.nim |
| 6 | L | `geScalarmultCT` double-wipes `digits`/`acc`/`u`/`step` on the normal-return path (end of `try` + unconditionally in `finally`) — harmless redundancy copied verbatim from `geScalarmultBase`'s pre-existing shape; fixing it means touching the established pattern in both functions or accepting the asymmetry. | fixed (committed) | Corey directed "fix lows" post-floor: BOTH functions converted to finally-only wipes (early sBytes wipe kept — genuine lifetime reduction), doc comments reworded to record the retirement; all 73 mutant anchors re-verified exactly-once; test.sh green exit 0, 0 FAILED, 11+5 files |
| L-rfc | L | The frozen RFC doc's body still describes pre-review designs (vartime scIsCanonical in the import path; bare RistrettoPoint DH return). Convention keeps RFC bodies frozen at approval. | fixed (committed) | additive "Stage-4 review outcome (2026-08-14)" ledger section appended to the RFC (13cd03c amendment precedent — no silent body rewrite) enumerating all five supersessions; status header updated to stages 3+4 COMPLETE |
| R2-1 | M | Round-2 security: fix 3 incomplete — the consuming `ristrettoScalarmult` overload routes the secret DH product through `ristrettoEncode`, which copies the point's coordinates into ~20 named `Fe` locals (x0/y0/z0/t0, zPlusY, u1/u2, zInv, ...) and has NO wipe path — encode's no-wipe design assumed to-be-published points. Stack-residue disclosure class (core dump/OOB-read/cold-boot), not timing. x25519 A1 precedent: each secret-holding path wipes its OWN named locals (field-primitive internals like feInvert's are the accepted boundary — same treatment in the x25519 ladder). Fix: `ristrettoEncode` wipes its own named locals unconditionally (negligible vs its feInvert-dominated cost; no dual path, no drift-prone duplicate). | fixed (committed) | all 25 named Fe locals hoisted above `try`, ct.wipe'd in `finally` (A1 ladder precedent); doc paragraph records why + the dudect uniform-work note; R06/R07 re-anchored (indent shift), mutation 72/72 killed; test.sh green 334 OK |
| R2-2 | M | Round-2 design: `scIsCanonicalCT`'s symex-decline rationale lives only in this ledger — the project's validation-bar register puts such disclosures in the code/`tests/verify/` docs (symex_mask/symex_reduce precedent), so the next implementer reading scalar.nim sees an undisclosed gap. Fix: one-sentence recorded-decline note in `scIsCanonicalCT`'s doc comment (cross-referencing symex_reduce's resource-wall precedent). | fixed (committed) | 4-sentence considered-and-declined paragraph added citing symex_reduce's resource wall + the empirical suite carrying the weight |
| R2-3 | M | Round-2 design+security (found independently by both reviewers): README's new ECIES example wipes `shared` BEFORE any use (comment says feed toBytes to a KDF; code never does) and never demonstrates cross-role DH agreement — a reader copying it destroys the secret unused, and the static-role recipient side never shows the encode-and-wipe idiom the surrounding prose recommends. Fix: reorder — compute both sides, doAssert `toBytes(shared) == toBytes(ristrettoEncode(recipientShared))`, then wipe both per role-appropriate idiom; re-run check-readme.sh. | fixed (committed) | fence reworked: both sides computed, doAssert agreement, role-appropriate cleanup both sides; check-readme.sh 8/8 fences clean |

Round 2 (2026-08-14): three reviewers (security, design, correctness) over
the uncommitted fix diff. Correctness: fully clean (borrow chain proved
correct by construction; both feSqrtRatioM1 sites verified; byte-identical
overload return; property falsifiable; mutants unique). Security + design:
the three NEW findings above (R2-1/R2-2/R2-3), all Medium, all within the
approved mandate — fixed, see statuses.

| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| R3-1 | M | Round-3 design (escalated from a round-2 minor): the consuming DH overload returns bare `RistrettoShared` with no degenerate-peer rejection — a peer sending `RistrettoIdentity` (or k ≡ 0 mod L, negligible for fresh ephemerals) yields S = identity, fully predictable without knowing k. sello's own `x25519` rejects the analogous case (`Option`/`none` on all-zero output) and libsodium's `crypto_scalarmult_ristretto255` refuses identity results outright; nothing in code or docs said whether this was accepted risk or oversight. In-codebase precedent unambiguous → fix: `Option[RistrettoShared]`, `none` iff S = identity, x25519's register; document why here and not on the publish-register overloads (Pedersen/OPRF results may legitimately be identity). | fixed (committed) | Option[RistrettoShared] + or-accumulate identity check (ladder zero-check register); RED twice (type mismatch; inverted check cascaded failures — load-bearing, not vacuous); identity-peer isNone test + none-path wipe-hygiene probe test; docs updated at overload/type/module/facade; test.sh + check-readme green |
| R3-2 | L | Round-3 design: README fence's `doAssert sharedBytes == recipientSharedBytes` compares raw arrays instead of demonstrating the documented vartime `RistrettoEncoded ==` idiom the very next section teaches — missed teaching opportunity, not wrong. Folded into R3-1's fence rework. | fixed (committed) | fence now compares via `ristrettoEncode(recipientShared) == toRistrettoEncoded(sharedBytes)` + isSome/get + std/options import; check-readme 8/8 |
| R3-3 | M | Round-3 coherence: CLAUDE.md still says "70/70"/"70 mutants" in four places (implementation-status bullet, mutation.sh inline comment, tests/mutation/ section, validation-bar bullet); actual catalog is 72 (S25 + R11 added by this review). Genuine drift in the authoritative doc. | fixed (committed) | all four locations updated to 72 + terse S25/R11 mentions; repo-wide grep found no other stale counts (handoff historical entries correctly left) |

Round 3 (2026-08-14): security (wipe completeness name-by-name, hoisting
init semantics, .root change, CT posture, whole-diff regression sweep) —
CLEAN, no new findings. Design — the three findings above, all fixed.

| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| R4-1 | M | Round-4 security: `ristrettoEncode(ristrettoUnchecked(s))` inside the consuming overload creates an anonymous `RistrettoPoint` temporary — a ~160-byte copy of the secret GeP3 DH product with NO wipe path (not a named local in either scope; `ristrettoEncode` deliberately doesn't wipe `pt`), contradicting the overload's own "every secret-derived local wiped" claim. Whether it persists on the stack is compiler-dependent — exactly the assumption class this codebase refuses to trust unverified. Fix: bind `let sPoint = ristrettoUnchecked(s)` hoisted + added to the `finally` wipe list. | fixed (committed) | sPoint hoisted var + ct.wipe(sPoint) in finally (generic wipe handles the plain object); doc paragraph re-enumerates wiped set truthfully; all R01-R11 anchors re-verified intact; test.sh green |
| R4-2 | M | Round-4 security: the new identity-rejection branch (`acc == 0`) has no curated mutant — its x25519 sibling zero-check carries two (X01/X02); covered by hand-written tests but a hole in the systematic validation-bar artifact. Fix: one mutant flipping the verdict, verified killed; CLAUDE.md counts 72→73. | fixed (committed) | R12_ristrettoscalarmult_ephemeral_zerocheck_flip added (unique match, harness-verified); mutation 73/73 killed, 0 survivors, 657s; CLAUDE.md four locations updated to 73 + R12 mention |

Round-4 design: three doc-only Lows (wipe() doc vs the new Option check;
CLAUDE.md facade enumeration and ct.nim secretHooks list missing
RistrettoShared) — all three fixed INLINE by the control loop same day
(doc text only, no executable code). Round-4 security: items 2/3 clean
(sink consumption on none path probe-tested; prime-order doc claims
hold); the two findings above fixed (see statuses).

| id | sev | finding | status | proof / reason |
|----|-----|---------|--------|----------------|
| R5-1 | M | Round-5 security: R4-1's twin on the encode OUTPUT side — `toBytes(ristrettoEncode(sPoint))` creates an anonymous `RistrettoEncoded` temporary (byte-identical copy of the still-secret DH encoding) with no name and no wipe path; `ristrettoEncode` deliberately leaves its return value unwiped (publish-bound at every other call site). Only production site combining the two on secret data (grep-verified). Also the doc clause "and encoded (already CT)" conflated a timing property with a wipe property. | fixed (committed) | fixed INLINE by control loop (executable but a mechanical 6-line mirror of R4-1): hoisted `var reTmp: RistrettoEncoded`, assigned in try, `encoded = toBytes(reTmp)`, `ct.wipe(reTmp)` in finally; doc paragraph rewritten to name it; all 73 mutant anchors re-verified exactly-once by script; test.sh green (11 unit + 5 property) |

Round 5 (2026-08-14): design lens CLEAN (counts/enumerations/doc edits
all verified accurate); security lens found R5-1 above — fixed inline
same day.

Round 6 (2026-08-14): FLOOR. Combined security+design pass over the
R5-1 delta — security CLEAN (full secret-holding-value inventory of the
overload body: sc/s/sPoint/reTmp/encoded all wiped; `acc` justified as
caller-visible-verdict register, x25519 zero-check precedent; no new
anonymous temporary; doc paragraph exactly true), design CLEAN except
one cosmetic line-wrap Low, reflowed inline same day. **0 Critical / 0
High / 0 Medium — review loop complete; rfc-flow ship gate (0 C/H)
satisfied.**

Verified correct (round 1, for the record): all five RFC 9496 §4.3.1
decode rejects + §4.3.2 encode (independently re-implemented in Python,
byte-identical); quotient `==` formula + bitwise combine; MAP
line-for-line; `geScalarmultCT` Horner composition (hand-verified s=0,
s=1); all four new constants algebraically against d = -121665/121666;
`RistrettoBasePoint` = A.1 i=1 byte-for-byte; `pointDecode` rewrite
semantically equivalent to the old vartime decoder; effect contracts,
facade export list (all 27 symbols), checks-off scoping, ORC hooks,
sink semantics, FFI declarations all clean; wipe discipline correct on
both accept/reject paths; type gates hold (no SecretScalar/role-type
route to any vartime path); A.1/A.2/A.3/A.4 vector coverage complete;
all 20 new mutants unique-match verified; fixtures fail for the
intended reasons; layering clean (import-list verified).
