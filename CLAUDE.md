# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`sello` is a **pure-Nim Curve25519 library** (ed25519 EdDSA + X25519 ECDH) with **no FFI** in the core. It exists because the Nim ecosystem had no production pure-Nim 25519 — every other option wraps orlp's C. SHA-512 is the one dependency we do *not* reimplement; it comes from vendored `nimcrypto`. See `prompt.md` for the full design brief and rationale — it is the authoritative spec, and current code is a partial implementation of it.

## The load-bearing design decision: VERIFY is split from SIGN

This split drives the whole API and trust story — preserve it:

- **Verification** (`ed25519.verify`) touches only public data (pubkey, message, signature). It has **no constant-time requirement**, is fully testable, and is the part that ships to everyone with no asterisks. `scalarmult` in `scalar.nim` uses plain 4-bit windows precisely because it only ever runs on the verify path — **do not add the signer's secret scalar to it.** `verify` has no backend dispatch and stays pure-Nim even under `-d:selloLibsodium`.
- **Signing / keygen** (`signing.nim` + `private/backend.nim`) holds the secret scalar → **is constant-time**: `{.push checks: off.}` cores, secrets confined to fixed-size stack arrays, every secret-dependent selection done by arithmetic masking (never a branch), and volatile-store-plus-barrier wiping (`private/ct.nim`) of every secret — including intermediate SHA-512 state — as soon as it's no longer needed. It carries the roll-your-own-crypto trust tax, backed by a dudect timing harness (`tests/ct/`, see below) and an **optional libsodium FFI adapter behind `-d:selloLibsodium`** (`private/backend_sodium.nim`) exposing the identical `Keypair` API.
- **X25519** (`x25519.nim`) also holds a secret (the caller's private scalar). Its Montgomery ladder is branchless on secret data (masked `feCSwap`, `{.push checks: off.}`, stack-only arrays, `private/ct.nim` wipe of the clamped scalar copy after use).

## Architecture (bottom-up layering)

`src/sello.nim` is the public facade — the supported API surface (`verify`, `x25519`, `x25519Base`, `keypair`, `sign`, `Seed`/`Keypair`/`toSeed`/`wipe`, key/signature types). Consumers `import sello`; submodules are importable but carry no stability promise.

Modules under `src/sello/`, each built strictly on the one(s) below:

1. **`field.nim`** — GF(2²⁵⁵−19) arithmetic. Radix 2²⁵·⁵, 10 `int32` limbs (`Fe` object). Direct ref10/orlp port (public domain). All the `fe*` primitives: mul, sq, invert, `fePow22523`, encode/decode, canonicity check (`feBytesCanonical`), constant-time `feCMove`/`feCSwap`, and `clampScalar` (shared by ed25519 and X25519 clamping — lives here so `x25519.nim` stays a `field.nim`-only consumer).
2. **`scalar.nim`** — Curve25519 group ops in extended Edwards coordinates (`GeP3`/`GeP2`/`GeP1P1`/`GeCached`). Point add/sub/double, variable-base `scalarmult` (verify-only, vartime), and fixed-base `geScalarmultBase` (signed radix-16 digits over a compile-time `GeCached` base table, CT `cmovCached` select — used by both keygen and signing, safe on secret scalars). `scReduce`/`scIsCanonical`/`scMulAdd`/`pointEncode`/the shared `challenge(R, A, msg)` hash also live here (moved down from `ed25519.nim` so the signing backend never imports the verify-only module). Curve constants (`Ed25519D_Raw`, `Ed25519Gx/Gy_Raw`, `SqrtM1_Raw`) live here too.
3. **`ed25519.nim`** — RFC 8032 layer: `pointDecode` (strict §5.1.3: rejects y ≥ p and x=0-with-sign-bit) and `verify` (`openArray[byte]` and `string` overloads). Verify-only, never touches a secret, no backend dispatch — pure-Nim always, including under `-d:selloLibsodium`.
4. **`x25519.nim`** — RFC 7748 layer on `field.nim` only (no Edwards code): Montgomery ladder (branchless on the secret scalar, `private/ct.nim`-wiped after use), `x25519` (returns `none` on all-zero shared secret, i.e. small-order peer point) and `x25519Base`.
5. **`signing.nim`** — `Seed`/`Keypair` types (fields private, move-only `Keypair`, `=destroy` wipes), the `keypair(seed)`/`keypair()` constructors, `sign`, and the `when defined(selloLibsodium)` backend dispatch (`private/backend_sodium` vs. `private/backend`, bound to one local name so every call site is backend-agnostic). The facade re-exports from here with no conditional logic of its own.
6. **`private/backend.nim`** — the pure-Nim secret-math backend: seed-level `derivePublic`/`signDetached`, no `Keypair` knowledge. Builds on `field.nim` + `scalar.nim` + nimcrypto SHA-512 only. Under `private/` because its exports bypass every `Keypair` guarantee (no invariant, no auto-wipe) — application code should use `sello.keypair`/`sello.sign`, never this module directly.
7. **`private/backend_sodium.nim`** — the libsodium FFI adapter (only compiled under `-d:selloLibsodium`), mirroring `backend.nim`'s exact seed-level contract via `crypto_sign_seed_keypair`/`crypto_sign_detached`; atomic `sodium_init` once-guard (`std/atomics`, not a plain check-then-set flag).
8. **`private/ct.nim`** — the one audited secret-wipe primitive (`wipe[T]`: volatile per-byte stores + `asm volatile("" ::: "memory")` barrier, `{.noinline.}`), called from `backend.nim`, `x25519.nim`, and `signing.nim`'s `Seed` destructor.

`tests/ct/` (`dudect.nim` + `ct_main.nim`) is the dudect-style timing harness, run via `nimble ct` — see below.

### Implementation status (verify against the code, not this list)
- ✅ field, curve ops, `scalarmult`, ed25519 `verify` (RFC 8032 + Wycheproof clean), X25519 (RFC 7748 + Wycheproof clean), ed25519 sign/keygen (RFC 8032 §7.1 vectors incl. TEST-1024, constant-time hardened), libsodium adapter (`-d:selloLibsodium`, bidirectional interop verified), dudect timing harness (`tests/ct/`, clean pass — see `docs/ct-results.md`), public facade
- ❌ Ristretto255 (deliberately deferred — leave a clean extension point, don't build it)

## Building & testing

There is **no host Nim toolchain** in this environment. `nimble test` and `nimble ct` build and run inside the base toolchain image directly — no project-specific image needed for either:

```sh
podman run --rm -v "$PWD":/workspace -w /workspace ghcr.io/coreyleavitt/nim:2.2.10 nimble test
```

`Containerfile.amox` is **amoxtli's sandbox image**, unrelated to sello (its package list — rust/go/node/openssl — belongs to a different project entirely); do not confuse the two or bolt sello-specific packages onto it. sello owns a minimal `Containerfile` of its own (`FROM ghcr.io/coreyleavitt/nim:2.2.10` + `libsodium-devel`), used **only** for `nimble testLibsodium` — the plain `test`/`ct` tasks need neither it nor network access:

```sh
podman build -t sello-libsodium -f Containerfile .
podman run --rm -v "$PWD":/workspace -w /workspace sello-libsodium nimble testLibsodium
```

`nim.cfg` sets `path="vendor"` (vendored nimcrypto), `path="src"`, `--mm:orc`, and `--outdir:"build"` (compiled binaries land in `build/`, which is gitignored — never commit binaries).

```sh
nimble test                              # full suite, pure-Nim backend
nimble testLibsodium                     # same suite + interop tests, -d:selloLibsodium (needs the sello Containerfile image)
nimble ct                                # tests/ct/ dudect timing harness, -d:release, ~1e6 samples/class (not part of `test`)
nim c -r tests/unit/test_field.nim       # one test module
```

`sello.nimble`'s `test`/`testLibsodium` tasks share one `unitTestFiles` list (`runUnitTests(extraDefines)`) so the two matrices cannot silently drift apart.

### Tests
- `tests/unit/test_field.nim`, `test_scalar.nim` — field/curve arithmetic sanity, incl. the compile-time base-table-vs-runtime-scalarmult standing guard.
- `tests/unit/test_ed25519.nim` — RFC 8032 §7.1 vectors (incl. TEST-1024) + §5.1.3 canonicity edges.
- `tests/unit/test_x25519.nim` — RFC 7748 §5.2/§6.1 vectors (incl. 1000-iteration ladder).
- `tests/unit/test_wycheproof.nim`, `test_wycheproof_x25519.nim` — Google Wycheproof adversarial vectors (vendored in `tests/vectors/`, from C2SP/wycheproof `testvectors_v1`). These must stay at zero failures.
- `tests/unit/test_signing.nim` — RFC 8032 §7.1 keygen + sign vectors (incl. TEST-1024), sign→verify roundtrips, `Seed` destructor/wipe smoke tests.
- `tests/unit/test_ct.nim` — direct coverage of `private/ct.wipe` on both array and `Sha2Context` shapes.
- `tests/unit/test_facade.nim` — the full public surface is reachable through `import sello` alone.
- `tests/unit/test_libsodium_interop.nim` — bidirectional interop (pure sign/libsodium verify and vice versa); a no-op `skip()` under plain `nimble test`, real assertions only under `-d:selloLibsodium`.
- `tests/ct/` — dudect-style timing harness (`nimble ct`, separate from `nimble test`); results in `docs/ct-results.md`.

### The validation bar (what earns trust without an audit)
This is the project's whole reason for caution — hold new code to it:
- Bit-exact pass of **RFC 8032** (ed25519) and **RFC 7748** (X25519) vectors. ✅ enforced in CI-less reality by `nimble test`.
- Pass **Google Wycheproof** adversarial vectors — the verifier must reject every malleable/non-canonical/small-order forgery. ✅ `test_wycheproof*.nim`.
- A **dudect/ctgrind-style timing harness** for the signer. ✅ `tests/ct/`, `nimble ct` — clean pass on all three secret-holding targets (`signDetached`, `geScalarmultBase`, `x25519Base`); honest environment caveats (container not bare-metal, `powersave` not `performance`) recorded in `docs/ct-results.md`.
- Consumers wanting an audited implementation rather than a statistical one: ✅ `-d:selloLibsodium`, with bidirectional interop tests against the pure-Nim backend.

## Compact Instructions
When compacting, preserve in the summary: the active RFC and its handoff-doc path, the current stage/round, slices done vs remaining, open forks awaiting me, and the exact resume command. After compacting, re-read the handoff doc and MEMORY.md before continuing.

## Conventions
- Port from permissively-licensed references (ref10/djb, TweetNaCl, orlp) and **attribute in the module header** as existing files do. Get functional correctness against vectors first, then CT-harden the signer.
- Secrets (signing, X25519 scalars): fixed-size stack `array[N, uintXX]`, never `seq`/`string`; zero allocation in the hot path.
- Scratch/diagnostic files from debugging sessions do not get committed — the maintained suite lives in `tests/unit/`, and `build/` catches binaries.
