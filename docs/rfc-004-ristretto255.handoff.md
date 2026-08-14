# RFC-004 Ristretto255 — handoff

- **Stage:** 3 (implementation grind) — RFC APPROVED by Corey 2026-08-13 after
  three architect rounds. Slices implemented by sonnet subagents under the
  rfc-flow grind loop, one per iteration, per-slice commits on `main`.
- **Resume:** grind loop RUNNING at slice 8a (slice 7b implemented and
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
- [~] 7b timing battery — commit 6b1cd47 (FOUR dudect targets added to
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
- [ ] 8a fuzzing (mode byte/dispatch arm/strategy-encoder/A.1 seeds/
      "three oracles" doc-comment updates; smoke campaign)
- [ ] 8b mutation (new-mutant batch incl. geScalarmultCT, feSqrtRatioM1-check,
      feEqualCT/feAbs mutants; 0 survivors)
- [ ] 8c libsodium differential KATs (A.1/A.2/A.3 + random sweep through both
      backends, verdict-and-value agreement, libsodium ≥ 1.0.18 version assert,
      via test-libsodium.sh)
- [ ] 8d facade + docs + close-out (ENUMERATED facade exports, test_facade
      reachability + declared-effect extension (four OSError pins, "the five"
      becomes nine) + RistrettoEncoded into the named hash/$ suites +
      nominal-typing negative-compile cases + the Pedersen commit/open
      worked-consumer scenario test, module doc finalized — CT posture,
      Schnorr/OPRF-client boundary, hash-the-encoding rule,
      encode-then-compare timing rule — NOTICE + RFC 9496 attributions,
      README (incl. stale "What's not here" bullet removal)/CHANGELOG/
      CLAUDE.md, version 0.4.0, final full-matrix run. GATE (slice-7b
      deferred verdict): the full-matrix run INCLUDES one complete ct.sh
      battery on a verified-quiet host — nothing else running, preflight
      banner confirming — as the `==`/`ristrettoEncode` tiebreaker.
      Decision rule: clean pass → mark 7b done; still WARN/FAIL on the
      sub-1000-cycle targets with the control-target evidence standing
      (signal not verdict-dependent) → accept via the documented
      resolution-floor register (the decode carve-out's "not every
      operation fits this instrument" precedent), recorded honestly in
      ct-results.md; any verdict-DEPENDENT signal → STOP, escalate to
      Corey before 0.4.0 is stamped.)

## Open forks (awaiting Corey)
- **Slice 7b `` ristretto.`==` ``/`ristrettoEncode` dudect standing
  verdict — OPEN, awaiting Corey's decision (2026-08-14).** Full
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
  run. Implementation commit: 6b1cd47.
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
Empty — review happens after implementation (stage 4); architect-round findings
are applied directly to the RFC text in stage 2, not ledgered here.
