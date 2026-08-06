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
- **`tests/ct/` dudect-style timing harness** (`nimble ct`): interleaved
  fixed-vs-random-class measurement with Welch's t-test, run at
  1,000,000 samples/class against `signDetached`, `geScalarmultBase`, and
  `x25519Base`. Results and the honest limits of this evidence (container,
  not bare metal; `powersave`, not `performance`; single CPU/compiler) are
  recorded in `docs/ct-results.md`.
- **Optional libsodium FFI adapter** (`-d:selloLibsodium`): recompiles the
  signing backend against libsodium's `crypto_sign_seed_keypair` /
  `crypto_sign_detached` instead of the pure-Nim implementation, behind the
  same `Keypair` API. `sello/ed25519.verify` is unaffected by the flag and
  stays pure-Nim on both backends. `nimble testLibsodium` runs the full
  suite plus bidirectional interop tests (pure sign / libsodium verify and
  vice versa) against it; a sello-owned `Containerfile` provides the
  libsodium-devel build environment.
- `LICENSE` (Apache-2.0) and `NOTICE` (third-party attributions: ref10,
  orlp/ed25519, TweetNaCl -- all public domain -- and vendored nimcrypto,
  MIT).

### Changed

- Internal layering: `scReduce`, `scIsCanonical`, `load3`/`load4`, and
  `pointEncode` moved from `sello/ed25519` into `sello/scalar`, and the
  shared `challenge(R, A, msg)` hash was extracted there too, so `verify`
  and the new `sign` call one audited copy of the RFC 8032 challenge
  formula instead of risking two hand-maintained copies. `sello/ed25519`
  remains verify-only and still never touches a secret.
- `sello.nimble` description and keyword comment updated to note the
  optional libsodium adapter alongside the pure-Nim core.

### Removed (breaking)

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
