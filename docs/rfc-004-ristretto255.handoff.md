# RFC-004 Ristretto255 — handoff

- **Stage:** 3 (implementation grind) — RFC APPROVED by Corey 2026-08-13 after
  three architect rounds. Slices implemented by sonnet subagents under the
  rfc-flow grind loop, one per iteration, per-slice commits on `main`.
- **Resume:** re-enter the grind with:
  `/loop implement the next unimplemented RFC slice with /tdd, following the
  standing rules; after each slice report one progress line (e.g. "slice 4/15
  done, 11 remaining"); stop when every slice is implemented`

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
- [ ] 3 encode (A.1 encode direction incl. i=0 identity/SQRT_RATIO_M1(1,0) edge,
      InvSqrtAMinusD — pulled forward from the constant batch: encode consumes
      it here — RistrettoIdentity/RistrettoBasePoint consts, round-trips,
      rejection-sampling generator; test_properties_ristretto.nim born AND
      registered — the array is hand-maintained, there is no glob)
- [ ] 4 group ops (+/-/negation, group axioms, torsion-invariance property with
      eight HARDCODED cross-checked torsion points, plus the deterministic
      plain-unittest torsion spot-check that survives proptest-less builds)
- [ ] 5a static secret role + scalarmult existing registers
      (RistrettoStaticSecret: secretHooks, canonical-residue invariant,
      staticSecret()/staticPair()/Option-returning 32-byte import with
      both-paths wipe/toRistrettoStaticSecretWide (distinct name, not an
      overload)/wipe/toBytes, constructor-internal wipes, repr-disclosure line;
      ristrettoScalarmultBase (static) + ristrettoScalarmultVartime; boundary
      scalars 0/1/L−1/L; reject_secretscalar_ristretto_vartime fixture)
- [ ] 5b ephemeral secret role (RistrettoEphemeralSecret: move-only, fresh-only,
      no toBytes, ElGamal-shape/CPace-boundary doc note, borrow-only
      ristrettoScalarmultBase overload + copy fixture — sink-consume overload
      and reuse fixture arrive in 7a)
- [ ] 6 hash-to-group (MAP, the remaining three constants via compile-time
      feFromBytes from spec bytes, ALL A.3 vectors incl. the
      four-inputs-one-output convergence set, all-zero/all-0xFF edges)
- [ ] 7a CT variable-base scalarmult (scalar.geScalarmultCT, UNIFORM 256-doubling
      interleaved ladder, table build via geAdd→geP1P1ToP3→geP3ToCached, wipe
      list incl. the two per-iteration temporaries, written loop-composition
      argument in the module doc, optional geP3Identity consolidation;
      ristrettoScalarmult plain-static + sink-ephemeral wrappers;
      reject_ristretto_ephemeral_reuse fixture; three-way agreement)
- [ ] 7b timing battery (FOUR dudect targets: ristrettoScalarmult,
      ristrettoEncode, `==` with (P,P)-vs-(P,Q) classes,
      ristrettoFromUniformBytes; inline rejection-sampling point generator in
      ct_main; quiet-host ct.sh run)
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
      CLAUDE.md, version 0.4.0, final full-matrix run)

## Open forks (awaiting Corey)
- None. All three rounds resolved every finding with confident recommendations
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
