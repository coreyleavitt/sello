# RFC-003: Compromise audit, round 2 — remediation

- **Status:** implemented — scope approved by Corey 2026-08-07 ("roll all of it into rfc-003") — every
  confirmed finding from the round-2 compromise audit; the two borderline items are
  recorded as considered-and-declined non-goals below.
- **Scope source:** post-RFC-002 `/architect` compromise audit (four lenses:
  disclosed-exemption re-litigation round 2, fresh-eyes design hunt over `src/`,
  verification-infrastructure audit round 2, docs/hygiene coherence). Load-bearing claims
  spot-checked against source by the control loop before drafting.
- **Handoff doc:** `docs/rfc-003-audit-round-2.handoff.md` (live progress ledger — read it
  first when resuming).
- **Standing orders:** identical to RFC-001/002 (PhD-CS bar; no consumers yet, breaking
  changes sanctioned; genuine forks escalate; wrong-spec assumptions escalate; per-slice
  commits after gates pass, the endorsed RFC-001/002 precedent). As with RFC-002, no
  architect review rounds: this RFC *is* the output of a multi-lens architect audit.

## Motivation

RFC-002 closed the first audit's findings, and this round confirmed most of the remaining
disclosed trade-offs genuinely sit at their ceilings (milpa-preflight warn-and-continue,
sink/`move()` residual gap, ctx/ph and key-container non-goals, fuzz signing-path
exclusion, bool/Option error-story asymmetry, Wycheproof coverage re-verified
byte-identical to upstream with zero silent skips, dudect harness internals, zero mutant
bitrot, every gate hard). But the same audit found places where "disclosed" was again
doing the work "designed" should have — most seriously in the verification story itself,
which is this library's actual product. Every decision below was resolved at approval
time; there are no open forks in this RFC.

## Slices

### Slice 1 — src/ design coherence (goes first: later slices' exact-string mutants and
### timing targets depend on the final shape of these files)

1. **`verify` uses `geBasePoint()`.** `ed25519.nim:154-158` hand-reconstructs the base
   point byte-for-byte identically to `scalar.geBasePoint()` (`scalar.nim:214`) — the
   exact "two hand-maintained copies" failure mode `challenge.nim` exists to kill.
   Replace with the constructor call; `ed25519.nim` already imports `sello/scalar`.
2. **`feFromLimbs` constructor.** `field.nim`'s module doc names the per-limb range
   invariant but exports `Fe.limbs` raw, and five call sites hand-assign it
   (`scalar.nim:83,216-217`; `ed25519.nim:38-39,79,155-156` — the last removed by item 1).
   Add `func feFromLimbs*(limbs: array[10, int32]): Fe {.inline.}` as the one audited
   construction path, with the invariant stated on it as the caller's obligation; convert
   every `Raw`-array call site. `limbs` stays public (the field/scalar internals mutate it
   legitimately in hot paths); the constructor is about giving *construction* a single
   documented door, matching the `challenge.nim`/`ct.wipe` principle.
3. **`feSqrtRatio` extracted to `field.nim`.** The sqrt-ratio dance (candidate root via
   `fePow22523`, retry with `sqrt(-1)`, sign/zero disposition) is inlined in
   `ed25519.pointDecode` (`ed25519.nim:55-89`), so the README's "clean Ristretto extension
   point" claim is aspirational: a Ristretto decode would have to duplicate it or import
   the verify-only module. Factor it into a `field.nim` primitive and rewrite
   `pointDecode` on top; behavior is pinned by RFC 8032 vectors + Wycheproof (zero
   tolerance for any change). Vartime is fine — it lives on the verify path; name/doc must
   say so per the `scalarmultVartime` convention if any branch is data-dependent.
4. **Malleability warning moves to the type.** `wire.nim` grants `hash`/`==` on
   `Signature` "for Table/HashSet keying" while the 13-line malleability warning sits only
   on `verify` (`ed25519.nim:112-124`), three files away, uncross-referenced — and a
   signature-keyed replay cache is the single most natural use of exactly those operators.
   Put the warning (condensed, with a pointer to `verify`'s full writeup) on the
   `Signature` type doc and on the `hash`/`==` overloads themselves.
5. **`x25519StaticPair()`.** The static (reusable-identity) role is the one X25519 role
   where `Keypair`'s rationale — no repeated derivation, no compiler-unenforced
   secret/public drift — actually applies, yet it's the one left as two loose values
   (the ephemeral role, which needs it less, already got a pair constructor). Add
   `x25519StaticPair(): tuple[secret: X25519StaticSecret, public: X25519Public]`
   (fresh from `std/sysrand`, mirroring `x25519EphemeralPair`'s shape and doc register).
   Considered and declined: a full `Keypair`-style invariant object — X25519 operations
   take only the secret (the public is sent once, not consulted per-op), so a bundled
   constructor captures the whole benefit without a new nominal type; the from-bytes
   reload path stays `toX25519StaticSecret` + one `x25519Base` call (one ladder at load
   time is not a repeated-derivation cost). README handshake example updates to the pair.

### Slice 2 — Fuzz oracle honesty + missing properties + fresh-clone ergonomics

1. **Round-trip identity oracle.** `fuzz_external_target.nim`'s doc claims "accept
   implies canonical re-encode" but the code checks only `feBytesCanonical(e1)` and
   determinism (`e1 == e2`), never `e1 == input` — a sign-bit-ignoring `pointDecode`
   would pass (today caught only incidentally by Wycheproof's 44 sign-bit-1 keys). Add
   the identity check for canonical inputs to `handlePointDecode`, and fix the doc
   comment to state exactly what is enforced.
2. **Encode/decode round-trip property.** In `test_properties_scalar.nim`: random valid
   points via `geScalarmultBase`, assert
   `pointEncode(pointDecode(pointEncode(p)).get) == pointEncode(p)` (and `isSome`).
3. **X25519 DH-agreement property.** In a new `test_properties_x25519.nim` (joins the
   `unit_test_files` list): `x25519(a, x25519Base(b)) == x25519(b, x25519Base(a))` over
   random static secrets, shrinking — the Montgomery-side analog of the Edwards-side
   agreement properties. (Also the natural home for future X25519 properties.)
4. **`scripts/test.sh` degrades gracefully without proptest.** Today the documented
   fresh-clone sequence (`milpa fetch` → `scripts/test.sh`) dies mid-loop with a bare
   "cannot open file: proptest" compile error because the three property suites are
   unconditionally in `unit_test_files`. Detect `_deps/proptest` in
   `scripts/lib/unit-test-files.sh` (or the callers) and skip the `test_properties_*`
   files with a loud `SKIPPED (proptest not fetched — run: milpa fetch --features
   proptest)` line — the same self-skip register as `test_libsodium_interop`. Add the
   one-line footnote next to the command in README and CLAUDE.md.

### Slice 3 — Mutation scope extension (after slice 1: exact-string mutants must target
### final source)

1. **Extend the catalog beyond field/scalar** to the boundary logic the project treats as
   highest-stakes everywhere else: `challenge.nim` hash-input ordering (swap R/A, drop a
   component — the one formula shared by sign and verify; a survivor here would be
   forgery-adjacent), `ed25519.pointDecode`'s conditionals (the
   `sign-bit-with-x=0` reject, the retry-branch condition, the `y ≥ p` canonicity
   reject), `x25519.ladder`'s all-zero small-order check (both call sites' `acc == 0`),
   and `pointEncode`'s sign-bit line (`scalar.nim:419-427` — the one comparison-flip
   family the existing S-series missed). Extend `run_mutation.py`/the catalog format as
   needed for the new files (it is already file-addressed patch-based). ~10-15 new
   mutants, same quality-over-exhaustiveness curation.
2. **Survivor protocol unchanged:** every survivor is a coverage-gap finding handled
   in-slice (new killing test, verified red under the mutant first) or proven equivalent
   with evidence and retired.
3. **Re-run the full extended campaign**; update `docs/mutation-results.md`, including a
   one-line note explaining the F12/F14 numbering gap (abandoned during authoring — say
   so explicitly so it doesn't read as a lost mutant) and reconciling `mutation.sh`'s
   wall-clock estimate with measured reality.

### Slice 4 — Proof completion (documentation-level; no new solver machinery)

1. **Written inductive proof of the reconstruction identity.** The prior framing
   ("symex's integer model tops out at machine-width ints") was the wrong frame:
   Σ digits[i]·16^i == s is a telescoping-carry identity provable by ordinary paper
   induction over exactly the `oneStep`/`finalStep` decomposition the range proof already
   isolates. Write the full inductive argument into `symex_recode.nim`'s module doc
   (invariant: after step k, Σ_{i<k} digits[i]·16^i + carry·16^k == Σ_{i<k} nibbles[i]·16^i;
   base, step, final-step cases), cross-referenced from the sampled property in
   `test_properties_scalar.nim` (which stays — belt and suspenders).
2. **Close the literal-function gap by composition.** The successful free-nibble
   whole-chain proof plus the observation that the byte→nibble decode
   (`s[i] and 0xF` / `(s[i] shr 4) and 0xF`) is mask-bounded to [0,15] *by construction*
   together imply the range invariant for the literal function — a one-paragraph
   composition argument, not a solver run. Add it to the module doc; update the
   "RESOURCE WALL" section's framing (the OOM was the byte-array encoding, as the
   successful run proved — the doc should stop implying "wait for more RAM" is the path);
   the `-d:selloBmcFullUnroll` code stays, relabeled as the historical single-query
   attempt the composition supersedes. Update CLAUDE.md/README validation-bar wording
   accordingly.

### Slice 5 — CT hardening (timing run last, quiet machine — RFC-002 Phase C lesson)

1. **Sixth dudect target: `x25519(X25519StaticSecret, peer)` fixed-vs-random.** Static
   and ephemeral secrets route through the identical `ladder()` (`x25519.nim:243`, called
   at both DH overloads), and `X25519StaticSecret` HAS a from-bytes constructor — so a
   real fixed-vs-random-secret leak test of the arbitrary-peer DH path (ladder +
   zero-check + Option wrap + wipe) is available for free and was never added. This
   measures the exact code-path shape the ephemeral calibration target structurally
   cannot; the ephemeral target stays, with its doc updated to note the leak question is
   now answered by target six.
2. **`ct.sh` enforces its own environment preconditions.** Preflight in the script:
   read `scaling_governor`, count running containers (`podman ps`), sample load average;
   print a loud banner and WARN (not hard-fail — environments legitimately vary) on
   `powersave`/non-zero container count/high load, and echo the observed values so they
   land in the captured output instead of relying on hand-transcription into
   `docs/ct-results.md` — the mechanism that already failed once (slice 4's admitted
   precondition gap).
3. **Full run + `docs/ct-results.md` update** (six targets + positive control), keeping
   prior runs side by side per the established convention.

### Slice 6 — Docs, packaging, version (last: documents the final state)

1. **CHANGELOG + version bump to 0.3.0** (`CHANGELOG.md`, `sello.nimble:11`,
   `milpa.kdl:5`). One 0.3.0 entry covering RFC-002's breaking changes (actor-first
   `verify`, `seed()` deleted / `toBytes(kp)` added, move-only `Seed`, `Seed.==` deleted,
   `hash()` on wire types, `x25519EphemeralPair`, module reorg wire/wipe/challenge) AND
   this RFC's additions (`x25519StaticPair`, `feFromLimbs`, `feSqrtRatio`, sixth dudect
   target, mutation-scope extension) — nothing was released between, so one entry is
   honest. Include a correction note superseding the 0.2.0 entry's now-false "manual
   induction, not Z3-checked" sentence (RFC-002 slice 4 retired it).
2. **Drift fixes:** README's "three secret-holding code paths" → current count, dudect
   paragraph gains the new targets + the shared-host caveat pointer; `x25519.nim:14-15`'s
   stale "dudect harness is tracked with the ed25519 signing milestone" sentence deleted;
   CLAUDE.md gains the mutation-testing subsystem (scripts table, Tests list,
   validation-bar entry, implementation-status line) and "all five scripts" → six;
   `scripts/mutation.sh` header estimate reconciled (item covered in slice 3 if touched
   there first — whichever lands later reconciles).
3. **`scripts/check-readme.sh`** re-run after every README fence edit (standing rule).

## Ordering & risks

1 → (2,3,4 in any order; 3 strictly after 1) → 5 → 6. Slice 1 edits `field.nim`/
`scalar.nim`/`ed25519.nim`, so the existing 36 exact-string mutants may bitrot — run
`scripts/mutation.sh` as a slice-1 gate and fix any OLD-string drift in-slice (the
applier fails loudly by design). Slice 5's timing run needs the quiet-machine discipline
and synchronous-foreground container rule recorded in RFC-002's handoff (ops lesson).
Slice 3's multi-file catalog support is the only harness-code unknown; the applier is
already file-addressed, so this should be small. `feSqrtRatio` refactor risk is fully
caught by RFC 8032 + Wycheproof (zero-failure requirement stands).

RFC-002 is still awaiting its stage-4 `/code-review`; recommendation recorded here: run
ONE combined review over RFC-002 + RFC-003 scope after this RFC's slices land (the file
overlap is near-total; two sequential reviews would double-handle the same code).

## Non-goals (considered and declined this round)

- **Retrofitting real coverage instrumentation onto the property suites** (the inert
  `coverageGuided = true`): the external SanitizerCoverage recipe is process-shaped, the
  property suites are in-process `forAll`s whose value is shrinking counterexamples;
  heavy machinery for marginal gain. Stays a disclosed no-op; revisit if proptest grows
  in-process instrumentation.
- **Deleting the `-d:selloBmcFullUnroll` inert attempt:** kept (zero build/CI cost, real
  engineering record) — reframed by slice 4, not removed.
- **Batch verification:** still deferred, now the RFC-004 candidate.
- **Ristretto255 itself:** still deferred; slice 1 item 3 only makes the extension point
  real, per the original design brief's "leave a clean extension point, don't build it".
- **Hard-failing `ct.sh` on environment preconditions:** warn-and-record chosen —
  legitimate environments vary; the compromise being fixed was silence, not tolerance.
