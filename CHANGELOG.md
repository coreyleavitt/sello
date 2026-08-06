# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
sello is pre-1.0: versioning follows semver's spirit but not its letter --
a breaking change bumps the minor version (0.x.0), not the major version,
until 1.0.0.

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
