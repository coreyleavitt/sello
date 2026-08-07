# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
sello is pre-1.0: versioning follows semver's spirit but not its letter --
a breaking change bumps the minor version (0.x.0), not the major version,
until 1.0.0.

## [0.3.0] - 2026-08-07

Nothing was released between 0.2.0 and this version, so this single entry
covers both RFC-002 (design-audit remediation) and RFC-003 (round-2
compromise audit remediation) in full.

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
- **`toBytes(kp: Keypair): array[32, byte]`** (RFC-002 slice 1 item 2) --
  raw seed bytes for persistence, caller-owned copy, same wipe-guidance
  doc register as `X25519StaticSecret.toBytes`.
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

- **`verify` is actor-first.** New shape:
  `verify(pk: PublicKey; msg: openArray[byte]; sig: Signature): bool`
  (+ `string` overload), call shape `pk.verify(msg, sig)` -- matches RFC
  8032's own VERIFY(pk, M, sig) notation and ed25519-dalek's
  `VerifyingKey::verify(message, signature)`, and now matches `sign`'s and
  `x25519`'s own actor-first argument order (RFC-002 slice 1 item 1). The
  old `verify(sig, msg, pk)` order, and the facade/README's "known,
  deliberate asymmetry" notes explaining it, are gone.
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

### Removed (breaking)

- **`seed()` accessor on `Keypair` deleted**, replaced by `toBytes(kp)`
  (see Added, above). `seed()` returned a `Seed` the public API provided
  no way to extract bytes from -- an unfinished corner masquerading as a
  persistence escape hatch (RFC-002 slice 1 item 2). No migration path:
  construct via `toBytes(kp)` instead.
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
  list. One principle, one layer now -- compare via `toBytes(kp)` or a
  local helper in tests (RFC-002 slice 1 item 4).

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
