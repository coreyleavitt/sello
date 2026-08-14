# RFC-004: Ristretto255 (RFC 9496)

- **Status:** APPROVED (Corey, 2026-08-13) — architect rounds 1, 2 AND 3 COMPLETE
  (rounds 1–2 2026-08-09, round 3 2026-08-13; all rounds' four-lens findings
  applied to this text — see "Open questions — resolved in round 1", "Round-2
  changes", and "Round-3 changes"). Stage 3 (implementation grind) in progress;
  one wrong-spec escalation amended mid-grind — see "Stage-3 amendment
  (2026-08-14)". Unlike RFC-002/003 this is a fresh feature RFC, not an
  audit output, so the architect rounds were NOT waived.
- **Handoff doc:** `docs/rfc-004-ristretto255.handoff.md` (live progress ledger — read it
  first when resuming).
- **Standing orders:** identical to RFC-001/002/003 (PhD-CS bar; no consumers yet,
  breaking changes sanctioned; genuine forks escalate; wrong-spec assumptions escalate;
  per-slice commits after gates pass).
- **Spec:** RFC 9496 (ristretto255 & decaf448) — ristretto255 only. Section references
  below are to that document. Where this RFC paraphrases a formula, the SPEC is
  authoritative and the implementing slice must transcribe from it, with the RFC 9496
  Appendix A vectors as the zero-tolerance gate — exactly the register RFC 8032/7748
  hold for the existing layers.

## Context

Ristretto255 is the brief's last undelivered chapter (`prompt.md` step 7: "leave a clean
extension point, do not build yet" — the extension point has since been built:
RFC-003 slice 1 extracted the sqrt-ratio dance into `field.nim` precisely so a Ristretto
decode would not have to import the verify-only module). It constructs a **prime-order
group** of order L as the quotient [2]E/E[4] (the image of doubling, modulo the
4-torsion — NOT E/E[8], a common misstatement this RFC itself carried until round 3's
implementation caught it; dalek issue #312 is the canonical reference): within [2]E,
the four curve points differing by an E[4] point ARE one Ristretto element, every
element has exactly one valid 32-byte encoding, and non-canonical or small-order
garbage does not decode. That
is the substrate modern protocol work (Schnorr PoKs, Pedersen commitments, VRFs, OPRFs,
Bulletproofs) assumes, and the cofactor bug class it kills (Monero's key-image
double-spend being the canonical casualty) is exactly the kind sello's Wycheproof
posture exists to reject. (Substrate, not blanket protocol support: what v1 does
and does not enable per protocol class is stated honestly in Non-goals — a Schnorr
response and an OPRF client's unblind step both need scalar arithmetic this RFC
deliberately does not ship; round 3.)

Internally, Ristretto arithmetic IS the extended-Edwards arithmetic sello already has —
`GeP3` add/double/scalarmult are reused unchanged. The construction is purely an
encode/decode/equality wrapper plus a hash-to-group map, all built from field ops and
one inverse-square-root primitive. Everything it needs is already exported from
`field.nim`/`scalar.nim` except: (a) a **constant-time** sqrt-ratio (the existing
`feSqrtRatioVartime` is vartime by design), and (b) the sqrt(-1) constant (made private
in RFC-003 slice 1 on a sole-consumer rationale that this RFC obsoletes).

No new dependencies: hash-to-group takes 64 caller-provided uniform bytes (RFC 9496
§4.3.4 leaves the hash to the caller), so `ristretto.nim` never touches nimcrypto.

## Design

### Where it sits in the layering

New module `src/sello/ristretto.nim`, building on `field.nim` + `scalar.nim` only — a
sibling of `x25519.nim`, below `ed25519.nim`/`signing.nim`, above the field/curve core.
It never imports the verify-only module, `challenge.nim`, or a backend. Its types live
in `ristretto.nim` itself, not `wire.nim`, per the `x25519.nim` precedent (RFC 7748's
types stayed home because no second module consumes them; same holds here).

### The CT posture (the load-bearing decision of this RFC)

Ristretto does not fit the existing sign/verify split cleanly: its consumers run
protocols where group elements are routinely *derived from* secrets (a Pedersen
commitment before publication, an OPRF blinded element, a DH share), even when the
encoding eventually goes on the wire. RFC 9496 §4.2 specifies every operation to be
implementable in constant time, and the reference implementations (curve25519-dalek,
libsodium's ristretto255 API) are CT throughout. Proposal:

- **Decode, encode, equality, and the one-way map are CT by construction**: straight-line
  field arithmetic plus `feCMove`-based selects (whose mask algebra is already
  machine-checked in `tests/verify/symex_mask.nim`), no secret-dependent branch or
  index anywhere. This costs essentially nothing — the operations are naturally
  branch-free once sqrt-ratio is. Scope of the claim, stated here at the headline
  rather than buried per-operation: final accept/reject VERDICTS (decode's `none`,
  `wasSquare`, `==`'s result) are inherently caller-visible and carry no CT
  obligation — what is branch-free is everything up to the verdict.
- **Scalar multiplication ships in both registers, gated by the existing `SecretScalar`
  type boundary** (round-3 finding A3, reused verbatim):
  - vartime variable-base: a thin wrapper over `scalarmultVartime` (bare
    `array[32, byte]` only — a secret scalar cannot reach it, compile-enforced),
    `Vartime` suffix per convention, for verification-register protocol steps.
  - CT fixed-base: a wrapper over `geScalarmultBase(SecretScalar)` — already CT,
    already dudect-covered, already R1-wipe-disciplined.
  - **CT variable-base (secret scalar × arbitrary point): NEW CT surface, slice 7.**
    This is the operation that makes Ristretto actually usable for its headline
    protocols (OPRF evaluation, DH over the group, blinding). Without it the library
    would ship a prime-order group whose only safe secret-scalar operation is
    fixed-base — an honest but hollow v1. Design: signed radix-16 digits via the
    existing (Z3-proven) `recodeScalarRadix16`, a **runtime** 8-entry `GeCached` table
    [1P..8P] built by repeated `geAdd`, each build step routed through the standard
    `geAdd` → `geP1P1ToP3` → `geP3ToCached` conversion chain — `scalarmultVartime`'s
    own table-build pattern, stated explicitly since round 3 (the point is public —
    table construction need not be CT; the *lookup* must be and reuses `cmovCached`
    unchanged, including its built-in arithmetic-masked handling of the signed
    [-8,7] digits: conditional negation already lives inside `cmovCached`, verified
    against the source in round 3, so no new CT negate helper is needed for the
    ladder — only the unrelated `-` group operator in slice 4 needs a cached
    negation of its own). The digit
    loop is NOT `geScalarmultBase`'s odds-pass/×16/evens-pass shape — that shape is
    only correct because `GeBaseTable`'s 32 rows are each pre-scaled by 16^(2j), a
    factoring unavailable to a single unscaled runtime table; cloning it here would
    compute the wrong multiple. It is the standard interleaved high-to-low form
    instead, with the loop shape pinned exactly (round 2: round 1's "~252
    doublings" silently assumed an initial-load idiom it never stated): the
    accumulator starts at the identity, and for each of the 64 digits, high to
    low, four doublings of the accumulator then one CT table select + add — a
    uniform 256 doublings + 64 adds per call. The first iteration's four doublings
    act on the identity and are deliberately NOT special-cased away: an
    initial-load idiom would need a `GeCached`→`GeP3` reconstruction plus a
    non-uniform first iteration in CT code to save ~1.5%, and the exact-string
    mutation catalog and the cost claim both want one canonical shape (the cost
    model is materially heavier than fixed-base, stated up front). The ladder
    itself lives in
    `scalar.nim` as `geScalarmultCT*(s: SecretScalar; p: GeP3): GeP3`, a sibling of
    `geScalarmultBase` — that keeps every secret-scalar curve op in the one audited
    file, reuses the private `geP3Double`/doubling chain with no new exports, and
    leaves `ristretto.nim` a pure wrapper. Secret-derived locals (digit array,
    accumulators, raw scalar copy, AND the two per-iteration temporaries — the
    `cmovCached`-selected `GeCached` and the completed-point temp — which
    `geScalarmultBase`'s own doc comment enumerates and whose stale values would
    each reveal a single digit's value and sign: the round-3 R15 mistake class,
    round 2 caught round 1's list omitting them) get the full R1 wipe discipline;
    the table is
    public and is not wiped. Its bit-255-clear `recodeScalarRadix16` precondition is
    guaranteed by construction — the secret role types (see Types) only ever hold
    reduced-mod-L bytes — and `geScalarmultCT` carries the same debug-only assert
    `geScalarmultBase` does. New dudect target (fixed-vs-random secret scalar, fixed
    peer point) joins the battery.

The slice-7 scope fork (defer to a follow-up RFC vs. include) is RESOLVED — round 1
confirmed include, per the RFC's own argument: the group is decorative without a CT
secret-scalar × arbitrary-point operation, and the redesigned ladder above reuses
proven components end to end. Corey's stage-2 approval still gates the RFC as a whole.

### Field-level groundwork (slice 1)

1. **`feSqrtRatioM1*(u, v: Fe): tuple[wasSquare: bool, root: Fe]`** — RFC 9496 §4.2's
   `SQRT_RATIO_M1`, constant-time. NOT a branch→cmov transliteration of
   `feSqrtRatioVartime`'s two-case check: the spec primitive is a THREE-check dance —
   `correct_sign_sqrt` (v·r² == u), `flipped_sign_sqrt` (v·r² == −u), and
   `flipped_sign_sqrt_i` (v·r² == −u·sqrt(−1)) — with
   `wasSquare = correct_sign_sqrt or flipped_sign_sqrt` and the root corrected by a
   sqrt(−1) multiply when either `flipped` check fires. The third check exists
   because the FALSE-branch root is load-bearing: the spec requires
   `(false, sqrt(SQRT_M1·u/v))`, and slice 6's MAP consumes that value
   unconditionally — an implementation carrying only the two checks the old vartime
   code had would pass every RFC 8032/Wycheproof vector (`pointDecode` never reads
   the root on reject) and fail only in slice 6, far from the defect. Slice 1a
   therefore tests the false branch DIRECTLY: for known non-square (u, v), assert
   `root² == SQRT_M1·u/v`; pins the degenerate cases
   (`SQRT_RATIO_M1(0, v) = (true, 0)`, `SQRT_RATIO_M1(u, 0) = (false, 0)` — the
   latter is exactly what encode-of-the-identity hits); and is gated bit-exact
   against **RFC 9496 Appendix A.4** — the spec ships KAT vectors for exactly
   this primitive, and round 2 caught the battery citing only A.1–A.3 (derived
   properties are not the spec's own zero-tolerance vectors). Candidate root via the
   existing `fePow22523` chain (already a fixed sequence), all three checks via the
   new `feEqualCT` (below), selects via `feCMove`, result normalized non-negative
   via `feAbs`. Returns a tuple, not `Option[Fe]` like its vartime predecessor,
   deliberately: `Option` discards the failure-branch payload, which here is
   consumed downstream — the doc comment states this so the divergence from
   `field.nim`'s Option register reads as designed, not accidental.
2. **`feEqualCT*(a, b: Fe): bool` / `feIsZeroCT*(f: Fe): bool`** — the constant-time
   field-equality primitive `field.nim` currently lacks (`feIsNonZeroVartime` and
   `feBytesCanonical` are both early-exit verify-path code). Byte-compare of
   `feToBytes` outputs accumulated with bitwise `or` into one word, no early exit,
   no short-circuit boolean anywhere. One audited home (the
   `challenge.nim`/`feFromLimbs` register), consumed by `feSqrtRatioM1`'s three
   checks and ristretto's `==` — without a named primitive, both consumers would
   hand-roll it in prose, the drift mode this codebase exists to kill. Alongside
   them, **`feBytesCanonicalCT*(bytes: array[32, byte]): bool`** — the CT
   canonicity check `ristrettoDecode` needs (round 3): the existing
   `feBytesCanonical` is explicitly vartime ("not constant-time; verify-path
   only" — an early-exit per-byte loop that leaks WHICH byte diverges), and it is
   the same-shaped, adjacent, WRONG-register helper an implementer following the
   `pointDecode` precedent-pattern would naturally reach for — with decode carved
   out of the dudect battery as disclosure-only, nothing measured would ever
   catch the resulting silent violation of the headline CT-by-construction
   claim, so naming the trap here IS the mitigation. Construction:
   `feToBytes(feFromBytes(bytes))` compared against the input with the same
   or-accumulate, no early exit (`feToBytes` always fully reduces mod p, so a
   non-canonical input round-trips to different bytes). The shared or-accumulate
   shape gets one machine-checked lemma covering all three consumers
   (`tests/verify/symex_equal.nim` — see the Validation battery's symex bullet).
3. **`ed25519.pointDecode` is rewritten on top of it and `feSqrtRatioVartime` is
   DELETED.** Two independently-maintained sqrt-ratio implementations in one file is
   the exact drift mode `challenge.nim` exists to kill, and the CT version's cost
   delta on the verify path is one field multiply plus cmovs in an operation already
   dominated by `fePow22523` — noise. RFC 8032's decode semantics (reject on
   non-square; reject x = 0 with the sign bit set; sign chosen by the encoding's
   x-sign bit) compose over the primitive:
   take `wasSquare` as the accept gate, reject if the (guaranteed non-negative)
   root is zero while the sign bit is set (§5.1.3's third condition — round 2
   caught the round-1 composition recipe dropping it; the Wycheproof gate would
   catch a dropped check, but this recipe is what an implementer follows), then
   conditionally negate the non-negative
   root to match the sign bit. This is a REWRITE of the function's shape (two sequential branches become
   one always-executed compute + masked select), not a line-level edit — which is
   why it is its own slice (1b) and why the F21/F22 mutants are RETIRED AND
   REPLACED, not re-anchored: no `if` survives for their OLD-strings to match, and
   the round-3 batch A "re-anchoring drill" precedent covered refactors that
   preserved control flow, which this is not. Replacements target the CT
   primitive's own defect class (flip which candidate `feCMove` selects on
   `wasSquare`; invert the final `feAbs` normalization). The E01/E02/E03
   `pointDecode` mutants are the rest of the blast radius: each is re-anchored or
   re-cut against the rewritten source in-slice (E02's canonicity entry check
   should survive verbatim; E01/E03 sit on lines the recomposition reshapes).
   Behavior is pinned zero-tolerance by the full RFC 8032 + Wycheproof gates; any
   vector change is a bug in the rewrite, full stop.
4. **`feAbs*(r: var Fe)`** — CT absolute value (`feCMove` on `feIsNegative`), used by
   sqrt-ratio, encode, and the map. Trivial, but it appears four times in the spec as
   `CT_ABS` and deserves one audited home next to `feCMove`.
5. **sqrt(-1) becomes exported again** (`FeSqrtM1*: Fe`, built once via `feFromLimbs`
   from the existing private `SqrtM1Raw`). RFC-003 slice 1 privatized it on a
   sole-consumer rationale; the map (`r = SQRT_M1·t²`) and encode's rotation are new
   legitimate field-level consumers, which is the honest reversal of that call. The
   raw array stays private; the exported value is the one door.

### Types

- **`RistrettoPoint`** — the group element. One-field object wrapping a `GeP3`, field
  private: the invariant is "was produced by decode, the map, the constants, or group
  ops on the same" — never constructed from raw coordinates by application code. The
  one audited exception (the `feFromLimbs` precedent — a narrow, documented door):
  `ristrettoUnchecked*(p: GeP3): RistrettoPoint`, exported from the module but never
  from the facade, whose doc comment names its only legitimate callers — this
  module's own constructors/group ops, and `tests/unit/test_ristretto.nim`'s
  white-box oracles (slice 2's independent decode-correctness comparison against
  `scalar.nim`-computed i·B; slice 4's torsion points). Without the door, slice 2
  could only test accept/reject — not correctness — and slice 4's torsion property
  could not be written at all. The door carries a debug-only
  (`when not defined(release)`) curve-identity assert — `X·Y == Z·T` and the
  extended-coordinate curve equation — the register every other audited door
  already holds (`feFromLimbs`' bounds assert, `geScalarmultBase`'s bit-255
  assert), so a typo'd hand-built test point fails loudly instead of entering
  the layer silently. Freely copyable, no destructor: elements are
  public-register values in every protocol this serves — the published element is
  never the secret; the secret is the scalar that derived it, and CT protection
  belongs on the scalarmult, which is exactly why the secret role types below get
  the hygiene machinery while the point type deliberately does not. A
  `wipe(var RistrettoPoint)` overload was proposed (round 1),
  limitation-documented (round 2), and DROPPED (round 3), recorded here so the
  absence reads as decided: `X25519Public` — the family's public-role
  precedent — carries no `wipe`, and this type's own rationale one sentence up
  says why (elements are public-register values; the secret is the scalar). A
  `wipe` on a freely-copyable type with no destructor backstop would also carry
  a silently WEAKER contract than every sibling `wipe` — each of those is an
  early-wipe accelerant in front of a `=destroy` net that cleans up regardless,
  so a caller who has learned "forgetting wipe costs timing, not correctness"
  from the rest of the API would misapply exactly that trust here, where
  forgetting (or copying) means never-wiped. The named "unpublished
  intermediate" consumers do not need it: a Pedersen commitment and an OPRF
  blinded element are hiding/blinding by construction — the point value reveals
  nothing without the scalar, whose hygiene the role types fully own. The
  identity and base point are compile-time `const`s — `RistrettoIdentity*`,
  `RistrettoBasePoint*` — not zero-arg constructor procs: they are fixed values, the
  codebase convention for fixed group elements is `const` (`X25519BasePoint`), and
  `GeBaseTable` already proves the compile-time VM evaluates far heavier `Fe`/point
  arithmetic.
- **`RistrettoEncoded`** — the 32-byte canonical wire form, `distinct array[32, byte]`,
  with the `wire.nim`-style borrows (`toBytes`/`==`/`hash`/`$`/`toRistrettoEncoded`).
  Unlike `Signature`, `==`/`hash` here need NO malleability caveat, and the doc
  comment states the stronger fact outright: encodings are unique per element by
  construction, so on valid encodings byte-equality of `RistrettoEncoded` and
  quotient-equality of `RistrettoPoint` are provably the SAME predicate — the two
  `==` operators cannot disagree ON VALUE, which is what forecloses the
  dual-equality footgun. They DO differ in timing register (round 3):
  `RistrettoEncoded`'s `==` is the `wire.nim` vartime byte-compare, the point's
  is CT, and an operator cannot carry a `Vartime` suffix — the same naming
  limitation this RFC cites to decline `*` — so the register switch is silent at
  the call site. The mitigation is the documentation register: the doc comment on
  `RistrettoEncoded`'s `==` (and the README example) must state the rule
  outright — timing-sensitive equality compares `RistrettoPoint`s directly;
  encode-then-compare silently downgrades a CT comparison to vartime, the exact
  natural move for a caller about to serialize anyway. There is deliberately NO `hash(RistrettoPoint)`, and the rule is
  stated (module doc + README example) rather than left for a future contributor
  to "fix" (round 2): a hash must agree with `==`, and hashing any internal
  representation would diverge from quotient equality — key/dedupe on
  `RistrettoEncoded` (encode first), never on the point.
- **`RistrettoStaticSecret` / `RistrettoEphemeralSecret`** — the secret-scalar
  role types, a static/ephemeral PAIR mirroring X25519's (round 2: round 1's
  single copyable `RistrettoSecret` was repeating the exact history CLAUDE.md's
  ledger #29 records X25519 regretting — one do-everything secret role, later
  split by a breaking change. A one-time DH share's scalar is structurally
  `X25519EphemeralSecret`'s case and needs no scalar inversion, so the Schnorr
  non-goal does not defang the ephemeral argument; the machinery —
  `secretHooks`/`secretHooksMoveOnly`, the sink-consume pattern, the
  negative-fixture harness — is pure reuse, and the split is free while
  consumers don't exist. The original draft's "no new type, callers use
  `scalar.SecretScalar`" position fell in round 1: facade-unreachable,
  hygiene-free, and an unreduced scalar would silently compute a wrong
  multiple.) Both are one-field objects over `array[32, byte]` with the shared
  **invariant: always a canonical residue mod L**, load-bearing twice over:
  reduced means < L < 2^253, so `recodeScalarRadix16`'s bit-255-clear
  precondition holds by construction for every value that can reach the CT
  scalarmults — an arbitrary unreduced scalar with bit 255 set would otherwise
  SILENTLY produce a wrong multiple (`cmovCached` matches nothing for an
  out-of-range digit and contributes the identity, no diagnostic) — and it
  matches the dalek convention that a scalar IS a canonical residue.
  - **`RistrettoStaticSecret`** — the reusable key role (Pedersen key, OPRF
    server key): `secretHooks` (copyable + self-wiping, the `X25519StaticSecret`
    policy), `wipe` overload, `toBytes` for persistence. Constructors:
    `ristrettoStaticSecret()` (fresh — 64 bytes from `std/sysrand`, wide-reduced
    via `scReduce`, so sampling is uniform mod L), `ristrettoStaticPair()`
    (fresh secret plus its `ristrettoScalarmultBase` image in one call —
    `x25519StaticPair()`'s ergonomic, whose RFC-003 rationale transfers
    verbatim),
    `toRistrettoStaticSecret(bytes: array[32, byte]): Option[RistrettoStaticSecret]`
    (key IMPORT — round 2: REJECTS non-canonical input via `scIsCanonical`
    instead of silently reducing. Round 1's reduce-both semantics conflated
    dalek's two constructors: `from_bytes_mod_order` reduces, but the 32-byte
    already-a-canonical-scalar case is `from_canonical_bytes`, which rejects
    ≥ L — silent reduction would accept corrupted or cross-protocol key
    material and make `toBytes` round-trip to a DIFFERENT value than was
    imported, the silently-compute-something-plausible class this codebase
    rejects everywhere else; Option-on-suspect-input is the established
    register), and `toRistrettoStaticSecretWide(bytes: array[64, byte])` (total —
    wide reduction, the unbiased KDF/hash-derived route,
    `from_bytes_mod_order_wide`; wideness is why no canonicity expectation
    exists to violate, so reduce-not-reject is right HERE and only here. Named
    DISTINCTLY — round 3 renamed round 2's same-name overload of the 32-byte
    import: reject-vs-silently-reduce is a security-semantic difference, dalek
    separates its three constructors by NAME for exactly this reason, and
    overload-by-array-length would hide which behavior applies from a call-site
    skim — the silent-register-switch class RFC-001 finding 8 names).
    Constructor-internal secret temporaries (the sysrand buffer, reduction
    scratch) are `ct.wipe`d before return — the R15 discipline, stated so a
    reviewer expecting the wipe finds it specified. The 32-byte import's `none`
    path is stated in the same register (round 3): the `scIsCanonical` verdict
    is computed against the caller's own input, and any internal copy or scratch
    made before the verdict is `ct.wipe`d on BOTH paths before return — the
    `keypair(seed, expectedPublic)` precedent, whose doc comment makes the same
    nothing-secret-escapes promise on ITS `none` path. Both role types' doc
    comments also carry the standing residual-gap disclosure every sello secret
    type shares but none currently states (round 3): no `$` is defined (an
    `echo` fails to compile), but Nim's `repr`/reflective dumps print any
    object's raw fields — out of scope to prevent, in scope to disclose.
  - **`RistrettoEphemeralSecret`** — the SINGLE-USE role. Round 3 proof-spiked
    the consumer shape instead of inheriting X25519's by analogy (rounds 1–2
    justified this role on "a one-time DH share is structurally
    `X25519EphemeralSecret`'s case", which established the split was FREE but
    never that a Ristretto consumer actually fits it): the fitting consumer is
    ElGamal/ECIES-style hybrid encryption over the group — ephemeral k,
    `C1 = ristrettoScalarmultBase(k)` (the non-consuming borrow), then
    `S = k·P` against the recipient's element (the one consuming variable-base
    call), k dead thereafter — which lands on the borrow-then-consume shape
    EXACTLY, and needs no scalar arithmetic, so the Non-goals boundary does not
    defang it. The near-miss is recorded alongside (the honest boundary of the
    single-use guarantee, not a defect): a CPace-style PAKE's per-session
    scalar is "ephemeral" in protocol terms but needs TWO variable-base mults
    with the same scalar (once against the mapped generator, once against the
    peer's share), which a move-only consuming type cannot express BY DESIGN —
    that caller uses `RistrettoStaticSecret` plus an explicit `wipe`, and the
    module doc says so. Mechanics: `secretHooksMoveOnly` (`=copy {.error.}`),
    constructed ONLY via `ristrettoEphemeralSecret()` /
    `ristrettoEphemeralPair()` (fresh from `std/sysrand`, wide-reduced — no
    from-bytes route: freshness by construction), NO `toBytes` (unpersistable
    by design). `ristrettoScalarmultBase` borrows it non-consumingly; slice
    7a's `ristrettoScalarmult(sink ...)` CONSUMES it, making reuse a compile
    error pinned by subprocess-`nim c` negative fixtures (the
    `reject_ephemeral_reuse.nim`/`reject_ephemeral_copy.nim` pattern, same
    `compiles()`-blindness reason). `x25519.nim`'s empirically-established
    sink writeup (occurrence-count analysis, `move()` required after any
    earlier touch, the honest `move()`-override residual gap) applies verbatim
    and is cross-referenced from the doc comment, not re-derived.
  - CT ops take these role types and bridge to `scalar.SecretScalar` internally
    at the module boundary (the `signing.nim`→backend pattern);
    `scalar.SecretScalar` stays the narrow internal gate its doc comment
    describes and is never facade-exported. Vartime ops take bare
    `array[32, byte]`, exactly as before — the type gate self-flags the
    register at every call site.

### Operations (all per RFC 9496; formulas transcribed from spec at implementation time)

- **`ristrettoDecode*(e: RistrettoEncoded): Option[RistrettoPoint]`** (§4.3.1) — CT
  except the final accept/reject disposition (the *verdict* is inherently
  caller-visible; all field work is branch-free). Rejects: non-canonical field
  encoding (via the new `feBytesCanonicalCT` — NEVER the vartime
  `feBytesCanonical`, the named trap in Field groundwork item 2), negative s,
  `wasSquare = false`, negative t, y = 0. `none` on reject —
  matching `x25519`'s established Option register for "invalid peer input", and the
  same caller convention: consumers import `std/options` themselves; the facade does
  not re-export it (nothing else here does — README's x25519 examples are the
  precedent).
- **`ristrettoEncode*(p: RistrettoPoint): RistrettoEncoded`** (§4.3.2) — CT: the
  torsion-quotienting encode (invsqrt, conditional rotation by sqrt(-1), conditional
  negation, CT_ABS), all selects via `feCMove`. Needs the new constant
  `InvSqrtAMinusD`, which therefore lands WITH the encode slice (3), not with the
  hash-to-group constant batch — round 3 caught the slice list building all four
  constants in slice 6, strictly after encode needs this one (a genuine
  sequencing bug: slice 3's RED step would have had nothing to write against).
  Same mechanism (compile-time `feFromBytes` from spec bytes), same
  defining-equation cross-check, just delivered with its first consumer; the
  other three constants have no consumer before the map and stay in slice 6.
- **`==*(a, b: RistrettoPoint): bool`** (§4.3.3) — the quotient equality
  (x1·y2 == y1·x2 or y1·y2 == x1·x2), CT end to end: both `feEqualCT` comparisons
  are ALWAYS evaluated and combined with bitwise `or` on their word representation —
  never Nim's boolean `or`/`and`, which are short-circuit by definition and would
  silently reintroduce a secret-dependent branch at exactly the top-level combine
  the per-comparison discipline protects (a hazard no mutation or property test can
  see — it is timing-only — hence the dudect target below). Cheaper than two
  encodes and never touches the encoding path. CT is the right DEFAULT register
  here, diverging from `wire.nim`'s vartime `==` on purpose, and the doc comment
  states the threat model that makes it necessary here and not there: protocols
  compare Ristretto elements in timing-sensitive positions (DH-share/PAKE-style
  equality checks) in a way nobody compares two `PublicKey` wire blobs. A
  vartime `==` companion was considered and DECLINED (round 2, recorded so the
  omission reads as decided): CT equality is already cheaper than two encodes —
  there is no meaningful vartime speedup to buy, unlike the scalarmult pair
  where the cost asymmetry is real.
- **`ristrettoFromUniformBytes*(b: array[64, byte]): RistrettoPoint`** (§4.3.4) — split
  into two halves, mask the high bit, MAP each (Elligator 2 for ristretto255, §4.3.4's
  MAP function: needs constants `OneMinusDSq`, `DMinusOneSq`, `SqrtAdMinusOne`), add
  the two results. Total function — every 64-byte input yields a valid element; no
  Option. Hashing is the caller's job (spec-sanctioned), keeping nimcrypto out of
  this module. The fixed `array[64, byte]` parameter IS the length check
  (compile-time; a nimcrypto SHA-512 digest already has exactly this type) — no
  `openArray` overload, which would trade that for a runtime failure path on a
  total function; the doc comment instead shows the one-line checked-copy idiom
  for callers arriving from a `seq`-producing hash/XOF (round 3 — the module is
  deliberately nimcrypto-free, so non-nimcrypto hash sources are the expected
  case, not the exception).
- **Group ops:** `+`/`-` (point add/sub via `geAdd` over `GeCached`; sub needs the
  standard cached-negation, a private helper), unary `-`, and the
  `RistrettoIdentity`/`RistrettoBasePoint` consts (the base point = the Edwards
  base point — same underlying `GeP3`). These operators are this codebase's FIRST —
  a deliberate, recorded departure from the verb-prefixed-proc convention:
  `RistrettoPoint` is a genuine abelian-group public type (unlike `Fe`/`GeP3`,
  internal representations), and `+`/`-` are the first-principles notation for one.
  `*` for scalar mult was considered and DECLINED: an operator cannot carry a
  `Vartime` suffix, so `s * p` would resolve the CT-vs-vartime register silently by
  operand type with no call-site self-flag — the exact failure mode the RFC-001
  finding-8 naming convention exists to prevent. Scalar mult stays named procs.
  One Nim-specific note pinned for the examples (round 3): unary vs binary `-`
  on one symbol is whitespace-sensitive in Nim (`a -p` in call position parses
  as `a(-p)`), and these are the codebase's first operators — the README and
  module-doc examples pin canonical spacing (`a - b`, `-p`) so the shipped
  examples teach the right habit rather than an accidental parse.
  Naming keeps the `ristretto` prefix uniformly (the `x25519.nim` precedent, chosen
  deliberately over bare `decode`/`encode`): the scalarmult family's argument types
  are not Ristretto-specific enough to disambiguate on their own, and uniform
  prefixing keeps the surface grep-able in an audit.
- **Scalar mult:** `ristrettoScalarmultBase*(s): RistrettoPoint` (CT, fixed-base,
  over `geScalarmultBase`; overloads borrow BOTH secret role types
  non-consumingly), `ristrettoScalarmultVartime*(s: array[32, byte];
  p: RistrettoPoint): RistrettoPoint` (vartime, type-gated away from secrets — a
  value-returning wrapper; the underlying `var`-out-param shape does not leak into
  this module's API), and slice 7a's `ristrettoScalarmult*` (CT variable-base,
  over the new `scalar.geScalarmultCT`):
  `ristrettoScalarmult(s: RistrettoStaticSecret; p: RistrettoPoint)` plain,
  `ristrettoScalarmult(s: sink RistrettoEphemeralSecret; p: RistrettoPoint)`
  consuming — the `x25519Base`/`x25519` borrow-then-consume shape, reused
  exactly. The family keeps the full `Scalarmult` stem — round 3 renamed round
  2's bare `Mult` stem (`ristrettoMultBase` etc., itself round 2's
  modifier-after-stem fix of round 1's `BaseMult`; the modifier order survives
  this rename): every scalar-multiplication primitive in this codebase
  (`scalarmultVartime`, `geScalarmultBase`, the new `geScalarmultCT`) and
  libsodium's own `crypto_scalarmult_ristretto255` carry the stem, so a bare
  `Mult` would make the one natural audit grep for scalar-mult call sites
  silently miss the entire Ristretto family — failing the very grep-ability
  test the `ristretto` prefix is justified by, two sentences up.
- **Constants:** the four new field constants enter as compile-time
  `const X = feFromBytes(...)` evaluations of RFC 9496's own little-endian byte
  encodings — NOT hand-derived 10-limb `feFromLimbs` arrays. Every existing `Raw`
  limb array was copied verbatim from a reference that already stores limbs
  (ref10/orlp); RFC 9496 publishes hex, and hand radix-converting it is precisely
  the transcription risk this RFC's own risk register worries about. `feFromBytes`
  is a pure `func` and `GeBaseTable` already proves the compile-time VM handles far
  heavier field arithmetic, so the spec's bytes are the single transcribed
  artifact. Each constant is additionally cross-checked in tests against its
  defining equation (e.g. `InvSqrtAMinusD² · (a−d) == 1` up to sign) — transcribe
  once, verify algebraically.

### Effects (declared, not inferred — round 3; the convention was silent here)

`ristretto.nim` carries the standard module-level `{.push raises: [], gcsafe.}`;
the four `std/sysrand` fresh-secret constructors (`ristrettoStaticSecret()`,
`ristrettoStaticPair()`, `ristrettoEphemeralSecret()`,
`ristrettoEphemeralPair()`) override with explicit `{.raises: [OSError].}`,
joining the existing five — "the five fresh-secret constructors" in
`test_facade.nim`'s declared-effect contract suite becomes nine. Slice 8d
extends that suite accordingly: `{.raises: [OSError].}` pins for the four new
constructors and `{.raises: [], gcsafe.}` pins for
`ristrettoDecode`/`ristrettoEncode`/the scalarmult family/`==` — janus consumer
finding 3's compile-time gate, not prose review.

### Validation battery (the existing bar, extended — no new categories invented)

- **KATs:** RFC 9496 Appendix A — the generator small-multiples encodings (A.1, both
  directions: decode them to i·B and encode i·B to them), the invalid-encoding list
  (A.2: non-canonical field elements, negative components, non-square cases — every
  one must reject), the hash-to-group vectors (A.3, ALL of them — the six direct
  64-byte-input → encoding pairs AND the closing four-inputs-one-output
  convergence set; round 3 re-verified the appendix against the published RFC
  and corrected the earlier "both labeled inputs" undercount, which would have
  silently dropped the convergence set — the one vector group that exercises
  the map's many-to-one property directly), and the
  SQRT_RATIO_M1 vectors (**A.4** — round 2: the spec ships KATs for slice 1a's
  own primitive; consumed there, not left to derived properties). These
  are this RFC's RFC-8032-equivalents: zero tolerance, in `tests/unit/`.
- **Adversarial:** there is no Wycheproof Ristretto corpus; A.2 plus the fuzz target
  below carry that weight, stated honestly in the docs — plus differential testing
  against libsodium's ristretto255 API (resolving open question 5 as a slice-8
  addition, the round-3 B1 precedent): under `-d:selloLibsodium`, every A.1/A.2/A.3
  vector and a random-input sweep run through both sello and
  `crypto_core_ristretto255_*`, asserting verdict-and-value agreement. Stated
  assumption (round 3): `crypto_core_ristretto255_*` requires libsodium ≥ 1.0.18
  — the first version-sensitive API the adapter will have wrapped (everything
  `backend_sodium.nim` binds today predates it by years) — so the differential
  suite asserts the version once up front (`sodium_library_version_*`, beside
  the existing atomic `sodium_init` once-guard) instead of betting silently on
  the `sello-dev` image's package resolution.
- **Properties** (proptest, joining `test_properties_*.nim`). The random-element
  generator is specified ONCE, here, for every property below: rejection-sample
  `ristrettoDecode` over uniformly random 32-byte strings (≈1/16 acceptance —
  cheap, and available from slice 2 onward, which is what keeps the {5, 6}
  order-freedom claim below true; no property waits on the map or scalarmult for
  its point source — slice 4 precedes 5 for the unary-`-` boundary check, not
  for the generator). Properties: encode∘decode = id over all valid vectors and random
  elements; decode∘encode = id; group axioms (associativity, identity, inverse —
  including P + (−P) == RistrettoIdentity) over random elements;
  **torsion invariance** — the white-box crown jewel: for each of the FOUR E[4]
  Edwards points T (identity, (0,−1), (±sqrt(−1), 0)),
  `ristrettoEncode(P + T) == ristrettoEncode(P)` for random P — this property IS
  the quotient, tested directly. E[4]-only is the CORRECT scope, not a weakening:
  ristretto255 is [2]E/E[4], and the E[4] coset is the quotient's entire
  representative ambiguity within [2]E — the four genuine order-8 points do NOT
  preserve the encoding (verified independently in Python and against sello,
  byte-identical; dalek issue #312). Slice 4 therefore ALSO pins the [2]E
  boundary as documented behavior with a deterministic NEGATIVE companion: for
  the two fixed spot-check points, an order-8 translate must NOT encode equal
  (hardcoded verified order-8 coordinates; a deterministic spot-check, not a
  universal property). Because the invariance property is the ONLY exercise of
  the quotient construction anywhere in the plan and property files skip
  silently when proptest isn't fetched, slice 4 ALSO pins a deterministic
  plain-unittest torsion spot-check in `test_ristretto.nim` (two fixed points,
  all four E[4] T's) — quotient coverage that cannot be skipped (round 2). All
  four E[4] points' coordinates are trivial-or-`FeSqrtM1`-expressible constants,
  cross-checked in-test against their defining equations (on-curve; annihilated
  by 4) — no offline derivation machinery needed; the order-8 coordinates used
  by the negative companion are hardcoded and cross-checked the same way
  (on-curve; NOT annihilated by 4);
  equality-operator consistency with encoding equality; CT-vs-vartime scalarmult
  agreement (and, with slice 7, three-way agreement) plus boundary scalars pinned
  deterministically (s=0 and s=L → identity, s=1 → P, s=L−1 → −P — the
  additive-inverse axiom checked a second way, matching the boundary discipline
  `scReduce`'s own properties set; s=L enters through the 64-byte wide
  constructor and the bare-array vartime path, since the 32-byte import rejects
  non-canonical encodings like L by design); `ristrettoFromUniformBytes` determinism +
  valid-output (its result always re-decodes), plus the deterministic edge inputs
  all-zero and all-0xFF 64-byte arrays (the map is total; these must produce valid
  elements by test, not by random-sampling luck).
- **Fuzzing:** `ristrettoDecode` joins `fuzz_external_target.nim` (it is squarely
  attacker-controlled input surface), seeded with A.1 valid encodings per the
  round-3 B2 accept-boundary lesson. Mechanics stated so slice 8a closes the
  drift instead of discovering it (round 2): a new mode byte in the target's
  stdin wire format, a new dispatch arm, a new strategy/encoder pair in
  `fuzz_common.nim`, seeds via `FuzzSettings.initialIRCorpus` in
  `fuzz_main.nim`, and updates to the doc comments (those three files plus
  `scripts/fuzz.sh`) that currently enumerate exactly "three oracles" by name.
- **Mutation:** new exact-string mutants in the established catalog style: each decode
  reject-condition flip, encode's rotation and negation condition flips, the map's
  `wasSquare` select flip, equality's or→and (which doubles as an anchor on the
  bitwise-combine shape — a short-circuit rewrite would break the OLD-string match
  and fail loudly). Round 2 extends the catalog to the NEW arithmetic itself,
  matching the precedent of mutating primitives directly (S06–S20, F20) rather
  than only their callers: `geScalarmultCT` (doubling-count off-by-one,
  digit-sign flip, table-select index flip), `feSqrtRatioM1`'s three checks
  flipped individually (not only via `pointDecode`'s reject conditions),
  `feEqualCT`'s or→and accumulate, `feAbs`'s condition flip. Expected killers:
  the A.1/A.2/A.4 KATs and the boundary properties. Slice 1's blast radius is
  handled in-slice: F21/F22 retired and replaced, E01–E03 re-anchored or re-cut
  (see Field groundwork).
- **dudect:** FOUR new targets, not one — this resolves open question 2 with
  measurement rather than disclosure. (1) slice 7's `ristrettoScalarmult`
  (fixed-vs-random secret scalar, fixed peer point) — the headline secret-scalar
  surface. (2) `ristrettoEncode` (fixed-vs-random input point) — encode is the
  operation the RFC's own motivating protocols run on secret-DERIVED points (a
  commitment before publication), so its CT-by-construction claim gets a leak-value
  measurement, not just an argument. (3) `==` — round 2 redesigned the classes
  so the equal-vs-unequal axis is what varies: class A is `(P, P)` for a fixed P
  (both OR-terms hit their TRUE branch), class B is `(P, Q)` for random Q (FALSE
  throughout). Round 1's fixed-vs-random-operand framing would compare two
  almost-always-unequal classes and could pass without ever timing the match
  path — the same pass-while-unmeasured class round 1 itself caught in the
  two-check sqrt-ratio. The top-level combine is the one place a short-circuit
  boolean could silently
  reintroduce a branch, and no symex lemma covers that combine. (4)
  `ristrettoFromUniformBytes` (fixed-vs-random 64-byte input) — OPRF blinding maps
  a client's PRIVATE input to the group, so the map's input is secret in exactly
  the deployments that headline this RFC. `ristrettoDecode` stays disclosure-only,
  deliberately: its input is attacker-supplied wire data, public by definition —
  there is no secret class to measure. No separate `RistrettoEphemeralSecret`
  target either, rationale recorded (round 2): its consume path runs the same
  `geScalarmultCT` the static-secret target already measures with full
  fixed-vs-random leak-value power (the static role has a from-bytes
  constructor), so an x25519-style construct+consume calibration target would
  add runtime without adding information. The encode and `==` targets classify
  by point, so `ct_main.nim` grows its own small inline rejection-sampling point
  generator (it imports library modules only, never test files — a sanctioned
  third copy of the loop; `dudect.runDudect` generates inputs entirely
  pre-measurement, so the generator's variable iteration count is
  timing-irrelevant). Battery runtime roughly doubles (5 → 9
  targets); a one-off quiet-host cost, and the honest price of the claim.
- **symex (Z3):** the round-3 batch Z register extends to the new CT primitives,
  stated explicitly rather than left silent (round 2). The or-accumulate shape
  shared by `feEqualCT`/`feIsZeroCT`/`feBytesCanonicalCT` gets one `sxUnsat`
  lemma — `tests/verify/symex_equal.nim`, wired into `scripts/bmc.sh`, built in
  its own slice 1b (round 3 split it out of 1a: the `symex_mask.nim` precedent
  says a new solver file is its own unit of discovery risk — that file's
  three-way query split was forced mid-work by a walker limitation nobody
  predicted — and 1a already holds the RFC's single most intricate new
  primitive): the accumulated word is zero
  iff every byte pair is equal, full-domain over symbolic bytes (small and
  linear; if the walker hits a tooling wall, split per `symex_mask.nim`'s own
  precedent). Two recorded DECLINES with rationale, in the honest-disclosure
  register `symex_reduce.nim` established: `feSqrtRatioM1` gets no new symex
  target — its selects route through the already-proven `feCMove` lemmas, and
  its three-check control logic is pinned by the A.4 KATs plus the false-branch
  defining-equation tests (spec vectors, not solver queries, are the right
  instrument for caller-visible verdict logic); and `geScalarmultCT`'s
  whole-loop composition is a WRITTEN correctness argument in the module doc
  (the RFC-003 slice 4 register) over individually-proven components
  (`recodeScalarRadix16` via `symex_recode.nim`; the select via `cmovCached`'s
  existing mutation/dudect coverage and `symex_mask.nim`'s mask algebra), not a
  whole-loop solver query — declined up front per the `symex_reduce.nim`
  resource-wall precedent, with dudect 7b as the measured backstop.
- **Docs & wiring:** README section (what Ristretto is FOR, one protocol-flavored
  example) gated by `scripts/check-readme.sh` — and the standing "What's not
  here → Ristretto255 deferred by design" README bullet REMOVED in the same
  edit, named explicitly (round 3) because `check-readme.sh` compiles fences
  and can never catch a stale prose bullet contradicting the new section;
  CHANGELOG 0.4.0; CLAUDE.md
  architecture/status updates; version bump in `sello.nimble` + `milpa.kdl`;
  NOTICE gains an RFC 9496 entry (IETF Trust license terms) and `ristretto.nim`
  carries inline "per RFC 9496 §X" attributions at each transcription site — the
  standing per-source ritual, round 2 (the ref10/orlp/TweetNaCl precedent);
  `tests/unit/test_ristretto.nim` registered in `scripts/lib/unit-test-files.sh`
  the moment it exists (slice 2) — miss that and the suite silently never runs
  under `scripts/test.sh` and the new mutants have no killers — and
  `test_properties_ristretto.nim` registered the moment IT exists (slice 3):
  round 1's claim that the property file "is picked up by the existing glob" was
  FALSE (round 2) — `unit-test-files.sh` is a hand-maintained array whose only
  pattern-match is a skip-filter for absent proptest, not discovery, and
  `run_mutation.py`/`tier-summary.sh` consume the same array, so an unregistered
  property file silently never runs anywhere (for slice 4's torsion property
  that would mean the quotient construction going unverified while everything
  stays green; the array's own property-file doc-comment count updates too).

## Slices (each one `/tdd`-sized)

1. **(1a) CT field primitives.** `feSqrtRatioM1` (CT, §4.2, the full three-check
   dance) + `feEqualCT`/`feIsZeroCT` + `feBytesCanonicalCT` (round 3 — the CT
   canonicity check; see Field groundwork item 2 for the `feBytesCanonical`
   trap it exists to close) + `feAbs` + `FeSqrtM1` export. Gated
   standalone, BEFORE the verify path is touched: bit-exact RFC 9496 A.4
   vectors, agreement with the still-present
   `feSqrtRatioVartime` on random and boundary inputs, the false-branch root's
   defining equation (`root² == SQRT_M1·u/v`) on known non-squares, the degenerate
   u=0 / v=0 cases, and `feBytesCanonicalCT` agreement with `feBytesCanonical`
   across canonical/non-canonical boundary encodings (p−1, p, p+1, all-0xFF).
   (Round 3 moved `symex_equal.nim` out to its own slice 1b: this slice already
   holds the RFC's single most intricate new primitive, and the
   `symex_mask.nim` precedent shows a new solver file is its own unit of
   discovery risk.)
2. **(1b) feEqualCT accumulate lemma.** `tests/verify/symex_equal.nim` (the
   shared or-accumulate shape of `feEqualCT`/`feIsZeroCT`/`feBytesCanonicalCT`,
   `sxUnsat`, full-domain over symbolic bytes), wired into `scripts/bmc.sh` —
   its own slice per the `symex_mask.nim` precedent (that file's three-way
   query split was forced mid-work by an unpredicted walker limitation).
3. **(1c) Verify-path migration.** `pointDecode` rewritten on the new primitive;
   `feSqrtRatioVartime` deleted; F21/F22 retired and replaced, E01–E03
   re-anchored/re-cut. Gates: full `scripts/test.sh` including Wycheproof at zero
   change, mutation campaign green.
4. **(2) Decode + equality.** `ristretto.nim` skeleton:
   `RistrettoPoint`/`RistrettoEncoded` types, the `ristrettoUnchecked` door,
   quotient `==` (pulled forward from the draft's slice 4 — it is decode's
   correctness oracle), `ristrettoDecode` with every A.1 valid and A.2 invalid
   vector (RED first on the vector harness, then implement). A.1's valid direction
   is checked for CORRECTNESS, not mere acceptance: each decoded point is compared
   via `==` against i·B computed independently through `scalar.nim`'s existing,
   already-trusted `geScalarmultBase` and wrapped through the door — without an
   independent oracle, a self-consistent-but-wrong decoder would pass every listed
   check. `test_ristretto.nim` registered in `scripts/lib/unit-test-files.sh` in
   this slice, and `ristretto.nim`'s module doc comment is seeded here with the
   CT-posture headline (verdict carve-out included); the scalar-arithmetic
   boundary and hash-the-encoding notes join it by 8d.
5. **(3) Encode.** A.1 encode direction — including i=0 by name: encode of the
   identity exercises `SQRT_RATIO_M1(1, 0)`'s degenerate branch —
   `InvSqrtAMinusD` (round 3: pulled forward from the slice-6 constant batch —
   encode consumes it HERE; same compile-time-`feFromBytes` mechanism, same
   defining-equation cross-check, delivered with its first consumer),
   `RistrettoIdentity`/`RistrettoBasePoint` consts, encode/decode round-trip
   properties, and the rejection-sampling random-element generator the later
   property slices consume. `test_properties_ristretto.nim` is born here and
   registered in `scripts/lib/unit-test-files.sh` in the same commit (see Docs &
   wiring — the array is hand-maintained; there is no glob).
6. **(4) Group ops.** `+`/`-`/negation (the private cached-negation helper),
   group-axiom properties, the
   torsion-invariance property (the four E[4] points — identity, (0,−1),
   (±`FeSqrtM1`, 0) — defining-equation cross-checks in-test), the deterministic
   order-8 NEGATIVE companion (an order-8 translate must NOT encode equal —
   the [2]E/E[4] boundary pinned as documented behavior), plus the
   deterministic plain-unittest torsion spot-check in `test_ristretto.nim`
   (two fixed points, all four E[4] T's — quotient coverage that survives a
   proptest-less build).
7. **(5a) Static secret role + scalarmult, existing registers.**
   `RistrettoStaticSecret` (secretHooks, canonical-residue invariant,
   `ristrettoStaticSecret()`/`ristrettoStaticPair()`, the Option-returning
   32-byte import incl. its both-paths wipe statement, the total
   `toRistrettoStaticSecretWide` constructor, wipe/toBytes,
   constructor-internal wipes, the repr-disclosure doc line) +
   `ristrettoScalarmultBase` (CT fixed-base, static role) +
   `ristrettoScalarmultVartime`; agreement property + deterministic boundary
   scalars (0, 1, L−1, L — the L−1 → −P check is why slice 4 precedes this
   slice; s=L via the wide constructor and the vartime path); negative
   fixture: `reject_secretscalar_ristretto_vartime.nim` (subprocess `nim c`).
   (Round 3 split old slice 5 in two: it bundled two new role types, four-plus
   constructors, two scalarmult wrappers, and two fixtures — the same
   overpacking round 2 fixed in slice 8, and more than the X25519 precedent it
   mirrors ever landed in one slice.)
8. **(5b) Ephemeral secret role.** `RistrettoEphemeralSecret`
   (secretHooksMoveOnly, `ristrettoEphemeralSecret()`/`ristrettoEphemeralPair()`,
   no toBytes, the ElGamal-shape/CPace-boundary doc note; its consuming
   `ristrettoScalarmult(sink ...)` overload and reuse fixture arrive with slice
   7a — here it ships with the borrow-only `ristrettoScalarmultBase` overload
   and its copy fixture, subprocess `nim c`, mirroring
   `reject_ephemeral_copy.nim`).
9. **(6) Hash-to-group.** MAP + `ristrettoFromUniformBytes` + the remaining
   three constants (`OneMinusDSq`/`DMinusOneSq`/`SqrtAdMinusOne` — compile-time
   `feFromBytes` from spec bytes, each tested against its defining equation;
   `InvSqrtAMinusD` already landed with slice 3) + ALL A.3 vectors (the six
   direct pairs and the four-inputs-one-output convergence set) +
   determinism/validity properties + the all-zero/all-0xFF edge inputs.
10. **(7a) CT variable-base scalarmult.** `scalar.geScalarmultCT` (the uniform
    256-doubling interleaved ladder pinned in Design, runtime `GeCached` table
    via the `geAdd` → `geP1P1ToP3` → `geP3ToCached` build chain +
    `cmovCached` + `recodeScalarRadix16`, R1 wipe discipline throughout incl. the
    two per-iteration temporaries, debug-only bit-255 assert, the written
    loop-composition argument in the module doc, and — optional, sanctioned — a
    `geP3Identity` helper consolidating `scalar.nim`'s two existing inline
    identity constructions with this third caller) + the `ristrettoScalarmult`
    wrappers (plain static + consuming `sink` ephemeral overloads) + the
    ephemeral reuse fixture (`reject_ristretto_ephemeral_reuse.nim`) +
    three-way agreement property.
11. **(7b) Timing battery.** The four new dudect targets (`ristrettoScalarmult`,
    `ristrettoEncode`, `==` with the (P,P)-vs-(P,Q) class design,
    `ristrettoFromUniformBytes`) wired into `ct_main.nim`, including its inline
    rejection-sampling point generator (see the dudect bullet);
    full `scripts/ct.sh` run on a quiet host (the RFC-002 Phase C lesson: timing
    run last, quiet machine).
12. **(8a) Fuzzing.** The fuzz target's full wiring (new mode byte,
    dispatch arm, strategy/encoder pair, A.1 `initialIRCorpus` seeds, the
    "three oracles" doc-comment updates across the fuzz files and `fuzz.sh`),
    plus a smoke campaign. (Round 3 split fuzz from mutation — the project has
    always treated them as separate units: RFC-002 slice 3 was fuzz alone,
    slice 5 mutation alone, and a run-to-0-survivors mutant batch is
    iterative work, not an add-on.)
13. **(8b) Mutation.** The complete new-mutant batch (decode/encode/map/equality
    flips; `geScalarmultCT`, `feSqrtRatioM1`-check, `feEqualCT`/`feAbs`
    mutants) run to 0 survivors.
14. **(8c) libsodium differential KATs.** `test_libsodium_interop.nim`: every
    A.1/A.2/A.3 vector plus a random-input sweep through both sello and
    `crypto_core_ristretto255_*`, asserting verdict-and-value agreement (the
    round-3 B1 register) behind the up-front libsodium ≥ 1.0.18 version assert
    (see the Adversarial bullet), run via `scripts/test-libsodium.sh`.
15. **(8d) Facade + docs + close-out.** Facade exports ENUMERATED (round 2 —
    matching `src/sello.nim`'s symbol-by-symbol precedent so `test_facade.nim`
    has a concrete list to check: `RistrettoPoint`/`RistrettoEncoded`/
    `RistrettoStaticSecret`/`RistrettoEphemeralSecret`,
    `RistrettoIdentity`/`RistrettoBasePoint`, `ristrettoDecode`/
    `ristrettoEncode`, `+`/`-`/unary `-`/`==` (the codebase's first operators —
    explicit export lines, no muscle memory to rely on),
    `ristrettoScalarmultBase`/`ristrettoScalarmult`/`ristrettoScalarmultVartime`,
    `ristrettoFromUniformBytes`,
    `ristrettoStaticSecret`/`ristrettoStaticPair`/`toRistrettoStaticSecret`/
    `toRistrettoStaticSecretWide`/
    `ristrettoEphemeralSecret`/`ristrettoEphemeralPair`/`toRistrettoEncoded`/
    `toBytes`, the secret-role `wipe` overloads (none on `RistrettoPoint` —
    see Types) — and NOT `ristrettoUnchecked`, NOT
    `scalar.SecretScalar`; Option returns follow the existing
    caller-imports-`std/options` convention) + `test_facade.nim` reachability,
    the declared-effect contract extension (see Effects — four `OSError` pins,
    the raises-nothing pins), `RistrettoEncoded` joining the suite's existing
    NAMED "hash() for the public wire types" and "$ for the public wire types"
    cases (Table/HashSet keying, `$`-matches-`toBytes` — round 3: named so the
    close-out extends those two suites rather than trusting a generic
    reachability pass to cover them) +
    nominal-typing negative-compile cases (`RistrettoEncoded` vs
    `PublicKey`/`X25519Public`/`Signature`; the secret role types vs
    `X25519StaticSecret`/`Seed` — the standing RFC-001 finding-9 suite
    pattern) + a worked-consumer scenario test (round 3, the proof-spike
    register): a Pedersen commit/open roundtrip — `H` from
    `ristrettoFromUniformBytes`, `commit = ristrettoScalarmultBase(v) +
    ristrettoScalarmult(r, H)`, open = recompute + `==` — written against the
    FACADE surface only and asserted in `test_ristretto.nim`, so the frozen
    API is validated by one running consumer, not only by the README's
    compile-checked fence; `ristretto.nim` module doc comment finalized (CT
    posture + verdict carve-out, the scalar-arithmetic/Schnorr/OPRF-client
    boundary, the hash-the-encoding rule, the encode-then-compare timing
    rule); NOTICE + inline RFC 9496 attributions; README
    (gated by `scripts/check-readme.sh`, stale "What's not here" bullet
    removed) / CHANGELOG / CLAUDE.md; version
    0.4.0. Final full-matrix run (`test.sh`, `test-libsodium.sh`,
    `mutation.sh`, `fuzz.sh` smoke, `bmc.sh`).

## Ordering & risks

- Order: 1a → 1b → 1c → 2 → 3 → 4 → {5a→5b, 6 order-free between the families} →
  7a → 7b → 8a → 8b → 8c → 8d.
  The field slices
  first for the same reason RFC-003 put design motion first: later slices'
  exact-string mutants and the dudect targets must aim at final source. Round
  1's {4, 5, 6} any-order claim was too strong (round 2): slice 5a's L−1 → −P
  boundary check needs slice 4's unary `-`, so 4 precedes 5a; 5a precedes 5b
  (the ephemeral role's borrow overload extends 5a's `ristrettoScalarmultBase`);
  the 5-family vs 6 remain order-free — the random-element generator is
  rejection-sampled decode (built by slice 3), not the map or scalarmult. 7a/7b
  before the close-out slices so the docs document the real scalarmult story.
- Wall-clock note (round 3): the subprocess-`nim c` negative-fixture count
  roughly doubles by close-out (today's 7 plus the vartime-gate, ephemeral-copy,
  ephemeral-reuse, and 8d nominal-typing fixtures), each a fresh compile in
  `scripts/test.sh` — a real if modest cost, budgeted here the way
  `mutation.sh`/`ct.sh` runtimes already are, so it isn't a surprise at 8d.
- **Risk: 1c touches the verify path.** Mitigation is the zero-tolerance vector gate
  PLUS the 1a/1c split itself: the CT primitive is fully tested standalone —
  including the false-branch root the verify path never exercises — before
  `pointDecode` moves onto it. The rewrite is a reshape (two branches become
  always-execute + masked select), NOT a line-level mechanical edit; the split is
  what keeps each half reviewable, and `pointDecode`'s Wycheproof coverage is the
  strongest in the codebase.
- **Risk: constant transcription errors** (four new field constants). Mitigation:
  the spec's own byte encodings are the single transcribed artifact (compile-time
  `feFromBytes`, no hand radix conversion anywhere), each constant is tested
  against its defining field equation, and the A.1/A.3 KATs would catch any error
  downstream.
- **Risk: slice 7a is new CT code on the secret path.** It does not touch
  `geAdd`/`geP3Double` themselves — pure reuse; the new surface is the interleaved
  loop + table build + wipes, with the select routing through the already-proven
  `cmovCached`, the recoding through the Z3-proven `recodeScalarRadix16` (its
  bit-255 precondition discharged by the secret role types' canonical-residue
  invariant), and dudect measuring the result in 7b.

## Non-goals (considered and declined this round)

- **A public scalar-arithmetic API** (mod-L add/mul/invert on exposed scalar types).
  Protocols want it eventually; it is a separate design (its own types, its own CT
  story, scalar inversion) and nothing in RFC 9496 requires it. Stated honestly,
  because the boundary has a real consequence: a Schnorr response s = k + c·x needs
  exactly `scalar.scMulAdd` — which exists, is mutation- and dudect-covered, takes
  `SecretScalar` operands, and stays submodule-only (no stability promise).
  Facade-exporting it was considered and DECLINED this round: it would drag the
  bare, hygiene-free `scalar.SecretScalar` into the public surface, exactly what
  the `RistrettoStaticSecret`/`RistrettoEphemeralSecret` design exists to avoid.
  Round 3 sharpened the honest boundary, which is WIDER than the Schnorr case
  this paragraph originally named alone: a Schnorr response s = k + c·x needs
  `scalar.scMulAdd`, which at least EXISTS (submodule-only, covered,
  unexported); an OPRF CLIENT's unblind step needs scalar INVERSION mod L,
  which exists NOWHERE in sello at any layer (`field.feInvert` is mod-p field
  inversion, unrelated). Of the OPRF roles this RFC's framing repeatedly
  invokes, v1 therefore fully serves the SERVER (evaluation is one CT
  scalarmult) and cannot serve the client even by submodule reach-in. Until the
  scalar-arithmetic RFC lands, the stable surface supports
  commitment/DH/blinding-shaped protocols (group ops + scalarmult) but NOT ones
  needing secret scalar arithmetic — v1 ships the group with that boundary
  documented, not implied.
  `scReduce` export status stays as-is (the secret role types' constructors
  subsume the reduce-on-entry need).
- **Protocols on top** (VRF, OPRF, Pedersen, Schnorr PoK, Bulletproofs) — consumers'
  business, or a future RFC. This RFC ships the group, nothing above it.
- **decaf448** — no Curve448 core exists in sello and none is planned.
- **Batch/double-scalar operations** (`aA + bB` vartime, batch encode/decode inverse
  square roots) — real performance features, zero correctness contribution; defer
  until a consumer exists to size them.
- **Elligator inverse** (element → uniform bytes, for censorship-resistant transports)
  — niche, one-way map suffices for every named consumer class.
- **Ristretto in the libsodium backend dispatch** — libsodium HAS a ristretto255 API,
  but sello's backend split exists for the *signer's* trust story; verify-register
  group math never dispatched and Ristretto follows that precedent. What IS taken
  from libsodium (resolved this round): its ristretto255 API as a differential-test
  oracle for the KAT suites under `-d:selloLibsodium`, slice 8 (see Validation
  battery). Backend dispatch proper is worth revisiting only if slice 7's CT
  surface someday wants an audited second implementation.

## Open questions — resolved in round 1

Round 1 of the architect review answered all five; none required escalation.
Recorded here so round 2 hunts what is still weak instead of re-litigating:

1. **Slice-7 fork: INCLUDE.** The group is decorative without CT secret-scalar ×
   arbitrary-point. The ladder was redesigned in the process: interleaved
   4-doublings-per-digit living in `scalar.nim` as `geScalarmultCT` — NOT a clone
   of `geScalarmultBase`'s odds/×16/evens shape, which is only correct for a
   per-row-pre-scaled table and would compute the wrong multiple over a single
   runtime table.
2. **dudect coverage: measured, not disclosed.** Four targets (`ristrettoMult`,
   `ristrettoEncode`, `==`, `ristrettoFromUniformBytes`); `ristrettoDecode` stays
   disclosure-only (attacker-supplied public wire input by definition — no secret
   class to measure).
3. **`feSqrtRatioVartime`: DELETED.** No Ristretto-independent vartime consumer
   story surfaced; the anti-drift argument stands; the verify-path cost delta is
   noise under `fePow22523`.
4. **Naming/registers: as proposed, with rationale now recorded.** `ristretto`
   prefix kept uniformly; identity/basepoint become `const`s; CT `==` confirmed as
   the default register with its threat model documented; `*` for scalar mult
   declined (an operator cannot carry a `Vartime` suffix).
5. **libsodium differential KATs: slice 8**, per the round-3 B1 precedent.

Round 1 also made two design corrections beyond the listed questions: the slice-7
loop structure (finding above) and the scalar story — a `RistrettoSecret` role
type (since split in round 2, see below) replaced the draft's "callers use
`scalar.SecretScalar`" position, which was unreachable from the facade,
hygiene-free, and would have let an unreduced scalar silently compute a wrong
multiple via an out-of-range radix-16 digit.

## Round-2 changes (2026-08-09)

Round 2 attacked round 1's own products and the coverage seams. Every finding
resolved with a confident recommendation — zero forks escalate; Corey's stage-2
approval of the RFC as a whole remains the gate. The load-bearing corrections:

1. **RFC 9496 Appendix A.4 exists** (SQRT_RATIO_M1 KAT vectors — verified
   against the published RFC, round 1's battery cited only A.1–A.3) and now
   gates slice 1a bit-exact.
2. **The property-file "existing glob" claim was false** —
   `scripts/lib/unit-test-files.sh` is a hand-maintained array; its one
   pattern-match is a proptest skip-filter, not discovery.
   `test_properties_ristretto.nim` is registered in slice 3, and slice 4 adds a
   deterministic plain-unittest torsion spot-check so the quotient construction
   (whose ONLY other exercise is the proptest-gated property) can never
   silently go unverified.
3. **Secret role SPLIT:** `RistrettoStaticSecret` + `RistrettoEphemeralSecret`
   (move-only, fresh-only), applying the X25519 ledger-#29 lesson while it is
   free; the 32-byte import now REJECTS non-canonical input
   (`Option`/`scIsCanonical`, dalek's `from_canonical_bytes` register — round
   1's reduce-both semantics conflated dalek's two constructors), the 64-byte
   wide constructor stays total; `ristrettoStaticPair()` added
   (`x25519StaticPair()` ergonomic); `ristrettoBaseMult` renamed
   `ristrettoMultBase` (modifier-after-stem convention).
4. **`geScalarmultCT` pinned to the uniform shape** — 256 doublings + 64 adds,
   identity start, no initial-load special case (round 1's "~252" silently
   assumed an idiom it never stated) — and the wipe list extended to the two
   per-iteration temporaries whose stale values each reveal a single digit
   (the R15 mistake class).
5. **`==` dudect classes redesigned** to (P,P)-fixed vs (P,Q)-random: round 1's
   fixed-vs-random-operand shape could pass without ever timing the match path —
   the same pass-while-unmeasured class round 1 itself caught in the two-check
   sqrt-ratio.
6. **The pointDecode composition recipe regained RFC 8032's third reject**
   (x = 0 with the sign bit set).
7. **The symex register is now explicit:** `symex_equal.nim` (feEqualCT
   accumulate lemma, slice 1a, wired into `bmc.sh`) plus two recorded declines
   with rationale (feSqrtRatioM1 — A.4 vectors are the right instrument;
   `geScalarmultCT`'s whole loop — written argument per the `symex_reduce.nim`
   resource-wall precedent).
8. **Coverage and ritual closures:** mutation catalog extended to the new
   primitives themselves (`geScalarmultCT`, `feSqrtRatioM1`'s three checks,
   `feEqualCT`, `feAbs` — the S06–S20/F20 precedent); fuzz wiring mechanics
   named (mode byte, dispatch arm, strategy/encoder, seeds, "three oracles"
   doc-comment updates); facade surface enumerated symbol-by-symbol;
   nominal-typing negative-compile fixtures for the new types; NOTICE + inline
   RFC 9496 attributions; `ristrettoUnchecked` gains a debug-only
   curve-identity assert; `wipe(RistrettoPoint)`'s copy-escape limitation must
   be documented; hash-the-encoding rule stated (no `hash(RistrettoPoint)`);
   vartime `==` recorded as considered-and-declined; module-doc-comment
   obligations assigned (seeded slice 2, finalized 8c); constructor-internal
   secret temporaries' wipes specified; `ct_main.nim`'s inline point generator
   sanctioned (pre-measurement, timing-irrelevant); slice 8 split into
   8a/8b/8c (closing-slice sizing precedent); ordering corrected to 4-before-5
   (the L−1 → −P check needs unary `-`).

## Round-3 changes (2026-08-13)

Round 3 attacked what rounds 1–2 left standing, with the four lenses verifying
the RFC's claims against the published RFC 9496 and the actual source. Every
finding again resolved with a confident recommendation — zero forks escalate;
four items REVERSE or rename round-1/2-recorded details and are flagged for
Corey's approval accordingly (the approval gate can veto any of them):

1. **Sequencing bug (blocking): `InvSqrtAMinusD` moved to the encode slice.**
   Encode (slice 3) consumes it, but the slice list built all four constants in
   slice 6, strictly later — slice 3's RED step had nothing to write against.
   The other three constants stay with the map.
2. **CT canonicity check specified: `feBytesCanonicalCT` (slice 1a).** The
   existing `feBytesCanonical` is explicitly vartime (early-exit per byte), is
   the same-shaped adjacent helper the `pointDecode` precedent-pattern points
   straight at, and — with decode carved out of dudect as disclosure-only —
   nothing measured would ever catch the resulting silent violation of the
   headline CT-by-construction claim. The trap is now named and the CT
   construction (round-trip re-encode + or-accumulate compare) specified;
   `symex_equal.nim`'s lemma covers the shared accumulate shape.
3. **A.3 vector count corrected** (verified against the published RFC): six
   direct input→output pairs PLUS a four-inputs-one-output convergence set —
   "both labeled inputs" undercounted a zero-tolerance gate and silently
   dropped the one vector group exercising the map's many-to-one property.
4. **The effects convention was entirely silent** — new Effects subsection:
   `ristretto.nim` gets the standard push, the four sysrand constructors get
   `{.raises: [OSError].}` ("the five" in `test_facade.nim`'s effect-contract
   suite becomes nine), and slice 8d grows the corresponding pins.
5. **Scalarmult family RENAMED (reverses round 2's stem):**
   `ristrettoScalarmultBase`/`ristrettoScalarmult`/`ristrettoScalarmultVartime`
   — every scalar-mult primitive in the codebase and libsodium's own
   `crypto_scalarmult_ristretto255` carry the `Scalarmult` stem, so round 2's
   bare `Mult` made the natural audit grep miss the whole family, failing the
   grep-ability test the `ristretto` prefix itself is justified by.
6. **Wide constructor RENAMED (reverses round 2's overload):**
   `toRistrettoStaticSecretWide` — reject-vs-silently-reduce is a
   security-semantic difference; dalek separates these by name, and
   overload-by-array-length hid which behavior applies from a call-site skim.
7. **`wipe(RistrettoPoint)` DROPPED (reverses rounds 1–2):** `X25519Public`,
   the family's public-role precedent, carries no wipe; a wipe on a
   freely-copyable type with no destructor net is a silently weaker contract
   than every sibling `wipe` teaches callers to expect; and the named
   consumers (commitment/blinded element) are hiding/blinding by construction
   — the scalar is the secret, and it has full hygiene.
8. **`RistrettoEphemeralSecret` KEPT, but proof-spiked instead of
   analogy-justified:** the fitting consumer is ElGamal/ECIES-style encryption
   over the group (borrow `ScalarmultBase` for C1, one consuming variable-base
   mult, scalar dead) — an exact match for the borrow-then-consume shape; the
   recorded near-miss is CPace-style PAKE, whose per-session scalar needs TWO
   variable-base mults and therefore uses `RistrettoStaticSecret` + `wipe`
   (the honest boundary of the single-use guarantee, documented).
9. **The dual `==` timing registers confronted:** point `==` is CT, encoding
   `==` is vartime, and an operator cannot carry a `Vartime` suffix — the doc
   comment and README must state the rule (timing-sensitive equality compares
   points; encode-then-compare silently downgrades).
10. **OPRF honesty:** Context qualified and Non-goals extended — OPRF client
    unblinding needs mod-L scalar inversion, which exists nowhere in sello at
    any layer; v1 serves the OPRF server role only. A worked-consumer scenario
    test (Pedersen commit/open through the facade only, asserted, not just
    compile-checked) joins slice 8d — the proof-spike register.
11. **Slices resized/renumbered:** 1a split (symex_equal → new 1b; verify
    migration → 1c); slice 5 split (5a static + scalarmults / 5b ephemeral);
    slice 8a split (fuzz → 8a / mutation → 8b; libsodium → 8c, close-out →
    8d) — the same overpacking round 2 fixed in slice 8, applied to the slices
    round 2 didn't reweigh.
12. **Feasibility details pinned:** the 7a table build's
    `geAdd` → `geP1P1ToP3` → `geP3ToCached` conversion chain stated
    (`scalarmultVartime`'s own pattern); `cmovCached`'s built-in signed-digit
    negation confirmed against source (no new CT negate helper needed for the
    ladder); libsodium ≥ 1.0.18 stated + version-asserted for 8c; the
    negative-fixture wall-clock growth budgeted; the 32-byte import's
    `none`-path wipe stated (the `keypair(seed, expectedPublic)` register);
    `RistrettoEncoded` explicitly joins `test_facade.nim`'s named hash/`$`
    suites; the stale README "What's not here" bullet's removal named; the
    `array[64, byte]` map parameter's checked-copy idiom made a doc
    obligation; unary-vs-binary `-` whitespace pinned for examples; the
    secret role types carry the family's first explicit repr-disclosure line.

## Stage-3 amendment (2026-08-14): torsion property corrected to E[4]

The one wrong-spec escalation of the implementation grind, raised by slice 4's
implementer per the standing orders (STOP, never silently patch the spec) and
approved by Corey. The RFC — through all three review rounds — specified
encode-invariance under all EIGHT 8-torsion points. That premise is
mathematically wrong: ristretto255 is the quotient [2]E/E[4] (image of
doubling, modulo the 4-torsion), NOT E/E[8], and encode-invariance holds
exactly for the four E[4] points — identity, (0,−1), (±sqrt(−1), 0). The four
genuine order-8 points do NOT preserve the encoding. Verified three ways
before amending: an independent Python implementation, sello's own staged
slice-4 code (byte-identical to Python on the same points), and the upstream
record (curve25519-dalek issue #312, hdevalence). Notably, RFC 9496 itself
never states the eight-point claim — it was folklore this RFC imported, and no
document-review round could catch a claim absent from the source spec;
computation caught it, before any wrong commit. Amendments applied: (1) the
torsion-invariance property re-scoped to the four E[4] points — a scope
CORRECTION, not a weakening, since the E[4] coset is the quotient's entire
representative ambiguity within [2]E; all four points are
trivially/`FeSqrtM1`-expressible, so the offline-derivation machinery and the
torsion-provenance risk bullet (deleted) evaporate; (2) a deterministic
NEGATIVE companion added — for the two fixed spot-check points, an order-8
translate must NOT encode equal — pinning the [2]E boundary as documented
behavior; (3) the Context framing corrected from "quotient by its 8-torsion /
8 points ARE one element" to [2]E/E[4]. Library code needed NO changes — the
error lived only in the test plan's premise; decode/encode/group ops are
byte-correct against every RFC 9496 vector.
