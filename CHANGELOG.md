# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
sello is pre-1.0: versioning follows semver's spirit but not its letter --
a breaking change bumps the minor version (0.x.0), not the major version,
until 1.0.0.

## [0.3.0] - 2026-08-07

Nothing was released between 0.2.0 and this version, so this single entry
covers RFC-002 (design-audit remediation), RFC-003 (round-2 compromise
audit remediation), and the subsequent round-3 fix batches A (src design
and CT hygiene, `d36078b`), B (verification infrastructure, `78508a4`),
Z (machine-checked mask-algebra and carry-bound proofs, `a2f4f7e`), and
C (docs/packaging/consumer experience, this batch) in full.

### Added

- **`x25519StaticPair()`** (`x25519.nim`, RFC-003 slice 1 item 5) -- bundled
  fresh-secret-plus-derived-public constructor for the reusable X25519
  role, mirroring `x25519EphemeralPair()`'s shape (below). The from-bytes
  reload path stays `toX25519StaticSecret(bytes)` plus a manual
  `x25519Base` call; a full `Keypair`-style invariant object was
  considered and declined -- X25519 operations take only the secret, so a
  bundled constructor already captures the whole benefit without a new
  nominal type.
- **`feFromLimbs`** (`field.nim`, RFC-003 slice 1 item 2) -- the one
  audited construction door for limb-built `Fe` values, replacing five
  hand-assignment call sites across `scalar.nim`/`ed25519.nim`. `Fe.limbs`
  stays public for the arithmetic core's own hot-path mutation; only
  *construction* gets a single documented door, matching the
  `challenge.nim`/`ct.wipe` precedent.
- **`feSqrtRatioVartime`** (`field.nim`, RFC-003 slice 1 item 3) -- the RFC
  8032 SS5.1.3 sqrt-ratio dance (candidate root via `fePow22523`, retry
  with sqrt(-1), sign/zero disposition) extracted out of
  `ed25519.pointDecode` into a reusable field-layer primitive, making
  README's "clean Ristretto extension point" claim real instead of
  aspirational. Behavior is pinned unchanged by the existing RFC 8032 +
  Wycheproof vectors; the `sqrt(-1)` constant moved to `field.nim` with it.
- **`hash()` for the public wire types** (`PublicKey`, `Signature`,
  `X25519Public`) via `std/hashes`, alongside the existing `==`/`$` --
  unblocks `Table`/`HashSet` keying (peer registries, session caches).
  A condensed malleability warning (RFC 8032's cofactorless verification
  equation admits a second, distinct signature for the same message/key)
  now sits directly on `Signature`'s type doc and on its `hash`/`==`
  overloads, not only on `verify`'s doc comment three files away
  (RFC-003 slice 1 item 4) -- a signature-keyed replay cache is exactly
  the use case those operators invite, and exactly the one this warning
  protects.
- **`x25519EphemeralPair()`** (RFC-002 slice 1 item 6) --
  `tuple[secret: X25519EphemeralSecret, public: X25519Public]`, deriving
  the public value inside the constructor so the caller's secret binding
  is referenced exactly once (the consuming `x25519` call) and compiles
  without `system.move`. `x25519EphemeralSecret()` plus the non-consuming
  `x25519Base` overload remain for flows that need the two steps apart.
  README's primary X25519 example now leads with the pair.
- **`toSeedBytes(kp: Keypair): array[32, byte]`** (RFC-002 slice 1 item 2) --
  raw seed bytes for persistence, caller-owned copy, same wipe-guidance
  doc register as `X25519StaticSecret.toBytes`. Named `toBytes(kp)` when
  first added in this same unreleased cycle; renamed to `toSeedBytes`
  before shipping (round-3 fix batch A, finding A7 -- see Breaking
  changes, below, for why) -- since `toBytes(kp)` itself never appeared
  in a released version, this is a same-cycle correction, not a breaking
  change for any real consumer, though it is called out there for anyone
  who checked out sello mid-cycle under the old name.
- **Mutation-testing harness** (`tests/mutation/`, `scripts/mutation.sh`,
  RFC-002 slice 5 / RFC-003 slice 3): a curated, patch-based exact-string
  mutant catalog (proptest's own `mutation.nim` v1 is `int -> int` only and
  cannot target Nim source directly, so sello builds its own thin harness
  in the same spirit), applying each mutant to a disposable scratch copy
  of the source tree and scoring it against the full unit suite -- KILLED
  if the suite goes red or fails to compile, SURVIVED otherwise. Originally
  36 mutants over `field.nim`/`scalar.nim`'s highest-risk carry chains,
  boundary constants, and comparison flips (RFC-002 slice 5); extended to
  46 in RFC-003 slice 3 to cover `challenge.nim`'s shared sign/verify
  hash-input ordering, `ed25519.pointDecode`'s RFC 8032 SS5.1.3 reject
  conditions, `x25519.ladder`'s zero-output small-order-peer check at both
  call sites, and `scalar.pointEncode`'s sign-bit condition. Current
  result: 46/46 killed, 0 survivors, 1 confirmed-equivalent mutant (`F05`)
  retired with recorded evidence rather than forced into an artificial
  test -- see `docs/mutation-results.md`.
- **External SanitizerCoverage fuzz target**
  (`tests/fuzz/fuzz_external_target.nim`, RFC-002 slice 3): replaces the
  in-process `fuzzWith` harness, whose `{.cover.}`-wrapper coverage
  universe turned out to saturate almost immediately (2 edges total --
  effectively black-box random after the first few iterations). The new
  stdin-driven external target uses proptest's shipped
  `-fsanitize-coverage=trace-pc` recipe for real edge-guided mutation, an
  order of magnitude more edges than the harness it replaces; audited
  sello sources stay pragma-free. Gains a round-trip identity oracle
  (RFC-003 slice 2 item 1: `pointEncode(pointDecode(b)) == b` for
  canonical `b`, not merely "some canonical re-encode" -- the prior oracle
  would have passed a sign-bit-ignoring `pointDecode`, today caught only
  incidentally by Wycheproof's sign-bit-1 keys) plus stronger
  both-direction oracles (`not feBytesCanonical(b) => pointDecode(b).isNone`,
  `not scIsCanonical(sig[32..63]) => verify == false`, determinism
  double-calls for `verify`/`x25519`).
- **New property coverage:** `tests/unit/test_properties_x25519.nim`
  (RFC-003 slice 2 item 3) -- `x25519(a, x25519Base(b)) ==
  x25519(b, x25519Base(a))` Diffie-Hellman agreement over random static
  secrets, the Montgomery-side analog of the existing Edwards-side
  agreement properties; a `pointEncode`/`pointDecode` round-trip property
  added to `test_properties_scalar.nim` (RFC-003 slice 2 item 2); and,
  under `-d:selloLibsodium`, a random-seed-and-message backend-parity
  property in `test_libsodium_interop.nim` asserting the pure-Nim and
  libsodium backends' `derivePublic`/`signDetached` agree byte-for-byte
  (RFC-002 slice 4 item 1 -- the prior interop suite pinned exactly one
  RFC 8032 seed).
- **Graceful proptest skip:** a fresh clone's plain `milpa fetch` (no
  `--features proptest`) is now enough to run `scripts/test.sh` green --
  the `test_properties_*.nim` files are detected as unavailable and print
  a loud `SKIPPED (proptest not fetched -- run: milpa fetch --features
  proptest)` line instead of dying mid-loop on a bare "cannot open file:
  proptest" compile error (RFC-003 slice 2 item 4).
- **Sixth dudect target:** `x25519(X25519StaticSecret, peer)`
  fixed-vs-random (RFC-003 slice 5 item 1) -- a genuine fixed-vs-random-
  secret leak test of the arbitrary-peer DH path, closing the gap the
  fifth target (ephemeral construct+consume, RFC-002 slice 4 item 2)
  structurally could not answer, since `X25519EphemeralSecret` has no
  from-bytes constructor to hold a secret fixed across a class.
  `scripts/ct.sh` also gained an unconditional environment preflight
  banner (CPU scaling governor, running-container count via `podman ps`,
  `/proc/loadavg` -- RFC-003 slice 5 item 2), so a run's environment
  caveats are captured from the run itself instead of depending on an
  agent to hand-transcribe `podman ps`/`uptime` afterward. Full seven-row
  (positive control plus six real targets) results in
  `docs/ct-results.md`.
- **Debug-only consistency assertions** (RFC-002 slice 2 item 3):
  `geScalarmultBase`'s bit-255-clear precondition, and
  `backend.signDetached`'s re-derivation check of the caller-supplied
  public key against the secret scalar -- both wrapped in
  `when not defined(release)` (not a bare `assert`, which this Nim
  2.2.10 config does NOT strip under `-d:release`) so the dudect-measured
  release build is untouched. Plus a `Fe.limbs` invariant note stating the
  per-limb ranges as a constructor-level obligation for direct
  `sello/field` consumers (RFC-002 slice 2 item 4).

### Changed

- Internal module layering split further: `sello/types.nim` is gone,
  replaced by `sello/wire.nim` (`PublicKey`/`Signature` plus their
  converters/`==`/`$`/`hash`; no `private/ct` import -- these types hold
  no secret) and `sello/wipe.nim` (the generic `wipe(var array[32, byte])`
  over `private/ct`) -- RFC-002 slice 2 item 5. `sello/challenge.nim` now
  holds the shared `challenge(R, A, msg)` hash extracted out of
  `sello/scalar`, which drops its nimcrypto import entirely and becomes a
  pure field-plus-curve-math leaf (RFC-002 slice 2 item 1). `ed25519.nim`'s
  `verify` now calls `scalar.geBasePoint()` instead of hand-reconstructing
  the base point byte-for-byte (RFC-003 slice 1 item 1) -- the same
  "one audited copy, not two hand-maintained ones" principle
  `challenge.nim` exists to enforce. Dead code (`geSub`, zero call sites)
  deleted in the same pass (RFC-002 slice 2 item 2).
- The Z3 proof of `recodeScalarRadix16`'s digit-range invariant is
  materially stronger: RFC-002 slice 4 machine-checked the full 63-step
  composition in one `sxUnsat` query over 64 free symbolic nibbles
  (previously a manual induction argument -- see the correction note
  below), and RFC-003 slice 4 closed the remaining gap between that
  free-nibble generalization and the literal byte-array-in function with
  a written composition argument (the real byte-to-nibble decode is
  mask-bounded by construction into the domain the free-nibble proof
  already covers universally). The separate reconstruction identity
  (`sum(digits[i]*16^i) == s`) now also has a written, paper-checked
  inductive proof (RFC-003 slice 4 item 1), on top of the pre-existing
  sampled property test, which stays as belt-and-suspenders. See
  `tests/verify/symex_recode.nim`'s module doc comment for the full
  writeup.
- `docs/ct-results.md` and `docs/mutation-results.md` regenerated for the
  fifth/sixth dudect targets and the 46-mutant catalog respectively (see
  Added, above); both timing runs disclose a shared, not exclusively
  quiet, host (RFC-002 slice 4 and RFC-003 slice 5).
- **X25519 wipe parity with the ed25519 signing backend** (round-3 fix
  batch A): the Montgomery ladder's temporaries (`x2`/`z2`/`x3`/`z3`, its
  per-iteration scratch, and `zInv`) are now hoisted and wiped alongside
  the clamped scalar, not left to fall out of scope unwiped; the raw
  ladder output is wiped in both `x25519` overloads on both the `Some`
  and `None` result paths; a defensive `try`/`finally` net was added so a
  wipe still fires if an exception unwinds through the call.
- **Purity casts removed from both signing backends** (round-3 fix batch
  A, finding A4): `backend.nim`'s and `backend_sodium.nim`'s
  `derivePublic`/`signDetached`, and the sodium verify adapter, are now
  honest `proc`s instead of `func`s wrapped in a
  `{.cast(noSideEffect).}` lie -- the sodium adapter genuinely has FFI/
  global-state side effects (`ensureSodiumInit`'s atomic guard) it can no
  longer hide. `signing.nim`'s backend dispatch is unaffected (still one
  local name, still call-site agnostic); `keypair`/`sign` were already
  `proc`, so this is not visible at the public facade.
- **`secretHooks`/`secretHooksMoveOnly` templates** (round-3 fix batch A,
  finding A5, `sello/private/secret_hooks.nim`) consolidate the
  `=destroy`-wipe/`=copy {.error.}` boilerplate previously hand-written
  once per secret type (`Seed` plus the three X25519 secret types) into
  one audited `{.dirty.}` template pair, so ORC still recognizes the
  hooks at each type's own declaration site. No behavior change --
  same wipe, same move-only restriction, one fewer hand-copied
  implementation to keep in sync.
- **`feFromLimbs` gains the established debug-only per-limb range
  assert** (round-3 fix batch A), matching the precondition-checking
  pattern already used elsewhere (`geScalarmultBase`'s bit-255-clear
  assert, `signDetached`'s re-derivation check) -- `when not
  defined(release)`, absent from the dudect-measured release build.
- **Bool-vs-`Option` return-shape rationale documented** on the `x25519`
  overloads (round-3 fix batch A): why the peer-key-rejection path
  returns `Option[X25519Shared]` rather than raising or returning a
  sentinel value.
- **Differential adversarial testing against libsodium**, under
  `-d:selloLibsodium` (round-3 fix batch B): the full Wycheproof ed25519
  corpus run through both sello's own `verify` and libsodium's
  `crypto_sign_verify_detached` (138/150 vectors comparable; 12 excluded
  because libsodium's C API rejects non-64-byte signatures outright,
  which the excluded vectors specifically probe), and all 518 Wycheproof
  X25519 vectors run through both sello's ladder and libsodium's
  `crypto_scalarmult` via a new adapter -- zero verdict mismatches in
  either corpus. JSON vector loaders were extracted to a shared
  `wycheproof_vectors.nim` to back both the existing single-verifier
  suites and this new differential one.
- **Fuzz campaigns now seed known-good vectors into the mutation corpus**
  (round-3 fix batch B), via proptest's `initialIRCorpus` (3 seeds per
  target, 0 dropped, asserted in the harness) -- so mutation explores
  the accept boundary around a valid input instead of starting cold.
- **`tests/mutation/` gains four new `private/backend.nim` mutants**
  (round-3 fix batch B, finding B3 -- the signing backend's first
  mutation coverage): `scMulAdd`'s secret-operand swap, the SHA-512
  seed-expansion upper/lower-half confusion, the nonce-hash update-order
  swap, and a dropped `clampScalar` call in `derivePublic`. All four
  killed by `test_signing.nim`'s RFC 8032 SS7.1 KAT vectors. Catalog is
  now 50 mutants total (up from 46), still 0 survivors, still the one
  confirmed-equivalent retiree (`F05`) -- see `docs/mutation-results.md`.
- **`tests/ct/` dudect harness now evaluates a six-crop percentile
  battery per target** (round-3 fix batch B) instead of a single
  threshold, keying its pass/fail verdict off the worst-case `|t|` across
  the battery; `tests/ct/ct_main.nim` now wraps its scalar via
  `toSecretScalar` to match `geScalarmultBase`'s new `SecretScalar`
  parameter (see Breaking changes, below). Results regenerated in
  `docs/ct-results.md`, which also newly discloses a high-load
  environment for this particular run (load average 23.97, three
  concurrent containers) -- worst-case `|t| <= 1.85` across all five real
  targets even so.
- **`geAdd` gains explicit P+P and P+(-P) edge-case tests** (round-3 fix
  batch B) -- verified red under a deliberate local perturbation during
  authoring, then reverted, confirming the tests actually exercise the
  code path they claim to.
- **`scripts/test.sh`/`scripts/test-libsodium.sh` print a shared
  end-of-run tier summary** (round-3 fix batch B, `scripts/lib/
  tier-summary.sh`) -- a one-screen rollup of which validation tiers
  (RFC vectors, Wycheproof, differential, property tests, mutation) ran
  and their headline results, rather than requiring a reader to scroll
  the full test log.
- **Machine-checked (Z3) proof of the mask-construction/masked-select
  algebra** underlying `feCMove`/`feCSwap` (round-3 fix batch Z,
  `tests/verify/symex_mask.nim`): mask construction (`-int32(b)`) is
  proved to yield exactly `0` or `-1` for both booleans, and masked
  select/swap is proved to yield exactly the selected operand, over the
  FULL `int32` domain (three `sxUnsat` lemmas, no composition needed --
  the per-limb formula has no inter-limb dependency, so one-limb
  coverage already extends to the whole 10-limb `Fe`); cross-checked
  against the real primitives on 1124 boundary-plus-random cases.
- **Machine-checked (Z3) per-step bound proof for `scReduce`/`scMulAdd`'s
  shared carry-propagation macro** (round-3 fix batch Z, `tests/verify/
  symex_reduce.nim`), both the biased and unbiased forms, `sxUnsat` over
  the full domain. The whole-body free-variable composition (the
  analogous full-chain step `symex_recode.nim` completed for
  `recodeScalarRadix16`) was attempted against real Z3 and hit a genuine
  resource wall (~515s/~550s, externally killed, across two runs) --
  reported honestly as attempted-and-inconclusive, preserved inert
  behind `-d:selloBmcReduceFullChain` (off by default), matching
  `symex_recode.nim`'s own precedent for its first unsuccessful
  whole-array attempt. `scMulAdd`'s nonlinear multiply pyramid was never
  attempted symbolically (a scoping decision, not a wall) -- its
  magnitude bound remains a written argument, cross-checked byte-exact
  against the real function on concrete vectors. `scripts/bmc.sh` now
  chains all three symex harnesses (`symex_recode`, `symex_mask`,
  `symex_reduce`) in one invocation.
- **Packaging and consumer-experience fixes** (round-3 fix batch C, this
  batch): a new "Threat model / when not to use this" section in
  `README.md` consolidates the timing/memory/malleability/audit caveats
  that were previously scattered across the trust-story prose into one
  skimmable list; a reproducibility paragraph in the Building section
  states plainly that milpa and the `ghcr.io/coreyleavitt/nim:2.2.10`
  base image are the author's own tooling with no public-availability
  claim made here, and documents the manual `--path`-flag equivalent for
  building without milpa; a tested-Nim-version note distinguishes
  `sello.nimble`'s `>= 2.2.10` compatibility floor from the single
  version (2.2.10) every claim in this document was actually gathered
  against; `X25519BasePoint` added to the X25519 API tour, which had
  omitted it; `NOTICE`'s Wycheproof paragraph reworded to state plainly
  that the vendored JSON fixtures ARE redistributed in the source tree
  (under Apache-2.0) and are simply not part of the *built library
  artifact*, replacing a sentence that had asserted both "not
  redistributed" and "beyond the checked-in fixtures" at once. New
  top-level `SECURITY.md`. Annotated retroactive tags `v0.1.0`
  (`c9b4ac9`) and `v0.2.0` (`710fbe7`) added against this document's own
  historical entries below.

### Breaking changes

- **`verify` is actor-first.** New shape:
  `verify(pk: PublicKey; msg: openArray[byte]; sig: Signature): bool`
  (+ `string` overload), call shape `pk.verify(msg, sig)` -- matches RFC
  8032's own VERIFY(pk, M, sig) notation and ed25519-dalek's
  `VerifyingKey::verify(message, signature)`, and now matches `sign`'s and
  `x25519`'s own actor-first argument order (RFC-002 slice 1 item 1). The
  old `verify(sig, msg, pk)` order, and the facade/README's "known,
  deliberate asymmetry" notes explaining it, are gone. No migration path
  beyond reordering call sites; this argument-order flip is the one
  behavioral break most likely to bite an existing caller silently (same
  three argument types, swapped positions, no compile error if a caller
  happened to have variables typed identically at both positions), which
  is why it is called out here rather than left in Changed, above.
- **`seed()` accessor on `Keypair` deleted**, replaced by `toSeedBytes(kp)`
  (see Added, above -- named `toBytes(kp)` earlier in this same
  unreleased cycle; renamed to `toSeedBytes` by round-3 fix batch A,
  finding A7, before ever shipping). `seed()` returned a `Seed` the
  public API provided no way to extract bytes from -- an unfinished
  corner masquerading as a persistence escape hatch (RFC-002 slice 1
  item 2). No migration path: construct via `toSeedBytes(kp)` instead.
- **`Seed` is now move-only** (`=copy` is a compile error), matching
  `Keypair`'s rationale now that nothing in the public API needs `Seed`
  copies; `keypair(toSeed(bytes))` remains the construction idiom
  (rvalue moves). Verified against a negative-compile fixture
  (`tests/unit/fixtures/reject_seed_copy.nim`), the same subprocess-`nim
  c` methodology as `Keypair`'s own copy restriction (RFC-002 slice 1
  item 3).
- **`Seed.==` deleted.** The X25519 secret family already enforced "no
  vartime equality on secrets" at the type layer (no `==` at all);
  ed25519's `Seed` enforced the same policy only at the facade export
  list. One principle, one layer now -- compare via `toSeedBytes(kp)` or
  a local helper in tests (RFC-002 slice 1 item 4).
- **`field.feIsNonZero` renamed `feIsNonZeroVartime`** (round-3 fix batch
  A) -- an early-return equality check is vartime, and this codebase's
  naming law (`scalarmultVartime`, see `CLAUDE.md`) requires that suffix
  on any function whose timing depends on secret data, so a caller
  cannot mistake this for a constant-time primitive. Breaking only for
  direct `sello/field` submodule importers (the facade never exported
  the old name); no migration beyond the rename itself.
- **`scalar.geScalarmultBase`/`scMulAdd` now take `SecretScalar`, not a
  bare `array[32, byte]`, in their secret-scalar positions** (round-3 fix
  batch A, finding A3, `scalar.nim`'s new `SecretScalar` distinct type).
  `scalarmultVartime` deliberately still accepts only plain bytes, so
  passing a `SecretScalar` to the vartime verify-path function, or a bare
  array to the two constant-time signing functions, is now a compile
  error either way -- proven by a negative fixture, not just documented.
  Breaking only for direct `sello/scalar` submodule importers calling
  these two functions (the facade never exposed raw scalar bytes at this
  layer); construct a `SecretScalar` via the new `toSecretScalar(bytes)`
  to migrate.

### Correction to the 0.2.0 entry

The 0.2.0 entry above states that the 63-step composition of
`recodeScalarRadix16`'s digit-range invariant "is a manual induction
argument, not itself a single Z3-checked artifact." That sentence is no
longer accurate as of RFC-002 slice 4 (retired before this 0.3.0 release
-- nothing shipped between the two, so this note lands here rather than
as a separate release): the full composition is now machine-checked in
one `sxUnsat` query over 64 free symbolic nibbles, and RFC-003 slice 4
closed the remaining literal-function gap with a written composition
argument (see Changed, above). The 0.2.0 entry itself is left as written
-- an accurate record of that release's actual state at the time -- rather
than rewritten in place; this note supersedes it going forward. See
`tests/verify/symex_recode.nim`'s module doc comment for the current
status.

## [0.2.0] - 2026-08-06

### Added

- **ed25519 signing and keygen** (RFC 8032 SS5.1.5/SS5.1.6), the half of the
  library that was previously missing. New public surface on the `sello`
  facade:
  - `Seed` -- a 32-byte private key, constructed via `toSeed(bytes)`;
    wipes itself on scope exit and on explicit `wipe(seed)`.
  - `Keypair` -- move-only (`=copy` is a compile error); `keypair(seed)`
    (deterministic) and `keypair()` (fresh identity via `std/sysrand`,
    the one function in sello's public surface that can raise).
  - `kp.public`, `kp.seed()` accessors.
  - `kp.sign(msg)` -- deterministic, total, constant-time; `openArray[byte]`
    and zero-copy `string` overloads.
  - `verify(sig, msg, pk)` gained a matching `string` overload.
- **Constant-time hardening** for all secret-holding code paths (signing
  and X25519): `{.push checks: off.}` cores, stack-only secrets, arithmetic
  masking for every secret-indexed selection, and volatile-store-plus-
  barrier wiping (`sello/private/ct`) at every point a secret goes out of
  use, including SHA-512 context scrubbing.
- **`tests/ct/` dudect-style timing harness** (`scripts/ct.sh`): interleaved
  fixed-vs-random-class measurement with Welch's t-test, run at
  1,000,000 samples/class against `signDetached`, `geScalarmultBase`, and
  `x25519Base`. Results and the honest limits of this evidence (container,
  not bare metal; `powersave`, not `performance`; single CPU/compiler) are
  recorded in `docs/ct-results.md`.
- **Optional libsodium FFI adapter** (`-d:selloLibsodium`): recompiles the
  signing backend against libsodium's `crypto_sign_seed_keypair` /
  `crypto_sign_detached` instead of the pure-Nim implementation, behind the
  same `Keypair` API. `sello/ed25519.verify` is unaffected by the flag and
  stays pure-Nim on both backends. `scripts/test-libsodium.sh` runs the full
  suite plus bidirectional interop tests (pure sign / libsodium verify and
  vice versa) against it; a sello-owned `Containerfile` provides the
  libsodium-devel build environment.
- `LICENSE` (Apache-2.0) and `NOTICE` (third-party attributions: ref10,
  orlp/ed25519, TweetNaCl -- all public domain -- and the `nimcrypto`
  dependency, MIT).
- **Property-based tests** (`tests/unit/test_properties_field.nim`,
  `test_properties_scalar.nim`, `test_properties_signing.nim`) via
  **proptest** (`github.com/coreyleavitt/proptest`), an optional milpa dev
  dep (`milpa fetch --features proptest`) so consumers of sello never
  transitively fetch it. Covers field ring axioms, `feFromBytes`/
  `feToBytes` roundtrips incl. near-p boundary stress, `feCMove`/
  `feCSwap`, `scReduce` idempotence and boundary inputs, `recodeScalarRadix16`
  reconstruction against an independent bignum oracle, `geScalarmultBase`
  vs `scalarmultVartime` agreement plus a group-law additivity check, and
  sign/verify roundtrip + single-bit-flip rejection.
- **Coverage-guided fuzzing** (`tests/fuzz/`, `scripts/fuzz.sh`) of the
  attacker-controlled-input surface -- `ed25519.pointDecode`,
  `ed25519.verify`, and `x25519` over the peer's public u-coordinate --
  via proptest's in-process `fuzzWith` (IR mutation mode). Checks
  crash/exception freedom plus two cheap self-consistency oracles
  (`pointDecode` success implies a canonical re-encode; `x25519` returning
  `Some` implies a non-zero shared secret). Deliberately excludes the
  secret-scalar signing path (`signDetached`/`geScalarmultBase`) -- that
  risk is a timing side channel, already covered by `tests/ct/`'s dudect
  harness, not something a mutation fuzzer usefully stresses.
- **Machine-checked (Z3) proof** (`tests/verify/`, `scripts/bmc.sh`) of
  `recodeScalarRadix16`'s digit-range invariant, via proptest's
  `proptest/symex`. Partial by honest necessity: the per-iteration
  inductive lemma (nibble in [0,15] + carry-in in {0,1} implies digit in
  [-8,7] + carry-out in {0,1}, plus the tighter final-digit case bounded
  by the bit-255-clear precondition) is exhaustively proved (`sxUnsat`);
  the 63-step composition into a whole-function, whole-domain guarantee is
  a manual induction argument, not itself a single Z3-checked artifact --
  a first attempt at the latter did not complete within this
  environment's resource budget. See `tests/verify/symex_recode.nim`'s
  module doc comment for the full writeup.
- New `Containerfile` layer: `z3-devel` alongside the existing
  `libsodium-devel`, so one dev image (`sello-dev`, renamed from
  `sello-libsodium`) covers both the libsodium adapter matrix
  (`scripts/test-libsodium.sh`) and the Z3 proof (`scripts/bmc.sh`).
- **`X25519EphemeralSecret`** (`x25519.nim`): a single-use X25519 secret,
  closing the static/ephemeral deferral this same 0.2.0 cycle originally
  recorded (x25519-dalek's `EphemeralSecret`, in sello's own vocabulary).
  Move-only (`=copy {.error.}`, the `Keypair` pattern); constructed ONLY
  via `x25519EphemeralSecret()` (fresh from `std/sysrand`, no from-bytes
  constructor -- freshness by construction) with no `toBytes` either
  (unpersistable by design; both absences are pinned in
  `test_facade.nim`, not just documented). `x25519Base(secret:
  X25519EphemeralSecret): X25519Public` is a non-consuming borrow (safe to
  derive and send your public key before completing the exchange);
  `x25519(secret: sink X25519EphemeralSecret; peer): Option[X25519Shared]`
  CONSUMES it -- reusing the same variable in a second `x25519` call, or
  copying it, is a compile error verified against checked-in negative
  fixtures (`tests/unit/fixtures/reject_ephemeral_reuse.nim`,
  `reject_ephemeral_copy.nim`, subprocess-`nim c`-driven in
  `test_x25519.nim`, same methodology as `Keypair`'s copy fixture),
  not merely a documented caller obligation. Empirically, whenever
  `x25519Base` (or any other reference) touches the secret before the
  consuming call, Nim's own last-use inference needs an explicit
  `system.move` at that call site (`x25519(move(secret), peer)`) -- see
  `x25519.nim`'s doc comment on the `sink` overload for the full
  writeup, including the honest residual scope of that mechanism.
  README's X25519 section now leads with the ephemeral form as the
  recommended default; `X25519StaticSecret` (below) remains for a
  reusable identity.

### Changed

- Internal layering: `scReduce`, `scIsCanonical`, `load3`/`load4`, and
  `pointEncode` moved from `sello/ed25519` into `sello/scalar`, and the
  shared `challenge(R, A, msg)` hash was extracted there too, so `verify`
  and the new `sign` call one audited copy of the RFC 8032 challenge
  formula instead of risking two hand-maintained copies. `sello/ed25519`
  remains verify-only and still never touches a secret.
- `sello.nimble` description and keyword comment updated to note the
  optional libsodium adapter alongside the pure-Nim core.
- **Dependency resolution migrated from nimble to milpa.** `nimcrypto` is
  no longer vendored under `vendor/nimcrypto/` -- it is now declared in
  `milpa.kdl` and resolved by `milpa fetch` into `_deps/nimcrypto`, pinned
  in `milpa.lock` by commit SHA (`b3dbc9c4d08e58c5b7bfad6dc7ef2ee52f2f4c08`,
  tag `v0.7.3`) plus a dag-sha256 content hash. `nim.cfg` is now
  milpa-generated (rewritten wholesale on every `milpa fetch`); the
  project-standing `--mm:orc`/`--outdir:"build"` flags moved to a new
  `config.nims`, which milpa never touches. `sello.nimble` is kept only as
  a thin ecosystem-compat manifest (version/description/`requires`) for
  nimble-based consumers; its `test`/`testLibsodium`/`ct` tasks are
  replaced by `scripts/test.sh`, `scripts/test-libsodium.sh`, and
  `scripts/ct.sh`. `NOTICE`'s nimcrypto section now cites the pinned
  commit instead of describing a vendored copy, and its copyright line
  matches upstream `LICENSE` verbatim ("Copyright (c) 2018 Eugene
  Kabanov").

### Removed (breaking)

- **`X25519Key` replaced by `X25519StaticSecret`/`X25519Public`/`X25519Shared`.**
  (RFC-001 ledger #29, revisited on Corey's direction after originally being
  recorded `wontfix`.) X25519's three roles -- a private scalar, a public
  u-coordinate, and a completed DH shared secret -- previously shared one
  nominal type; that closed the cross-algorithm mixup with `ed25519.PublicKey`
  but left same-role/wrong-argument swaps (`x25519(secret, secret)`) and
  secret/sendable role confusion (nothing stopped a shared secret from being
  passed where a public value was expected) uncaught. Three role-typed
  wrappers close both: `X25519StaticSecret` and `X25519Shared` are one-field
  objects with a `=destroy` wipe hook and eager `wipe(...)` overloads, the
  same shape as `Seed`; `X25519Public` is a plain `distinct array[32, byte]`,
  freely copyable, no destructor. `toX25519Key` is gone; `toX25519StaticSecret`/
  `toX25519Public`/`toBytes` replace it, plus a new `x25519StaticSecret()` for
  fresh generation via `std/sysrand` (mirroring `signing.keypair()`). No
  migration path for `X25519Key` itself -- construct through the new
  role-specific converters instead. A static/ephemeral secret split
  (x25519-dalek's consume-on-use `EphemeralSecret`) was considered and
  initially deferred -- since built, in this same 0.2.0 cycle, as
  `X25519EphemeralSecret` (see Added, above).
- **`X25519Secret` (this same 0.2.0 cycle's initial three-role name)
  renamed to `X25519StaticSecret`**, to make room for the new
  `X25519EphemeralSecret` above and name the reusable/single-use
  distinction explicitly at the type level rather than leaving
  `X25519Secret` ambiguous between the two. `toX25519Secret`/
  `x25519Secret()` renamed to `toX25519StaticSecret`/`x25519StaticSecret()`
  to match; semantics unchanged, name only. Since `X25519Secret` never
  shipped in a released version (0.2.0 is still unreleased as of this
  cycle), there is no external migration path to document -- this note
  exists for anyone who checked out sello mid-cycle.
- **`SecretKey` removed from the public facade.** It was an unused,
  never-implemented placeholder type predating the signing design; the
  real signing surface is `Seed`/`Keypair` above. There is no
  migration path because nothing in 0.1.0 constructed or consumed a
  `SecretKey` value -- it was dead on arrival. This is a pre-1.0 breaking
  change, per this project's versioning policy above.
- The unused `GePrecomp` scaffold (never part of the public API) was
  deleted from `sello/scalar` in the same pass; not a compatibility
  concern for consumers.

## [0.1.0]

Initial release: pure-Nim GF(2^255-19) field arithmetic and Curve25519
group operations, ed25519 verification (RFC 8032, Wycheproof-clean), and
X25519 key exchange (RFC 7748, Wycheproof-clean). No signing, no keygen,
no FFI.
