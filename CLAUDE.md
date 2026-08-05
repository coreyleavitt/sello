# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`sello` is a **pure-Nim Curve25519 library** (ed25519 EdDSA + X25519 ECDH) with **no FFI** in the core. It exists because the Nim ecosystem had no production pure-Nim 25519 — every other option wraps orlp's C. SHA-512 is the one dependency we do *not* reimplement; it comes from vendored `nimcrypto`. See `prompt.md` for the full design brief and rationale — it is the authoritative spec, and current code is a partial implementation of it.

## The load-bearing design decision: VERIFY is split from SIGN

This split drives the whole API and trust story — preserve it:

- **Verification** (`ed25519.verify`) touches only public data (pubkey, message, signature). It has **no constant-time requirement**, is fully testable, and is the part that ships to everyone with no asterisks. `scalarmult` in `scalar.nim` uses plain 4-bit windows precisely because it only ever runs on the verify path — **do not add the signer's secret scalar to it.**
- **Signing / keygen** (not yet implemented) holds the secret scalar → **must be constant-time** and carries the roll-your-own-crypto trust tax. When built, it needs its own CT-hardened scalar mul (arithmetic masking, `{.push checks: off.}`, stack-only `array` secrets, volatile wipe, emit barriers — see `prompt.md` §"Constant-time toolkit"), plus an **optional libsodium FFI adapter behind `-d:selloLibsodium`** exposing the same API.
- **X25519** (`x25519.nim`) also holds a secret (the caller's private scalar). Its Montgomery ladder is branchless on secret data (masked `feCSwap`, `{.push checks: off.}`, stack-only arrays); the rest of the CT toolkit (volatile wipe, dudect harness) lands with the signing milestone.

## Architecture (bottom-up layering)

`src/sello.nim` is the public facade — the supported API surface (`verify`, `x25519`, `x25519Base`, key/signature types). Consumers `import sello`; submodules are importable but carry no stability promise.

Modules under `src/sello/`, each built strictly on the one below:

1. **`field.nim`** — GF(2²⁵⁵−19) arithmetic. Radix 2²⁵·⁵, 10 `int32` limbs (`Fe` object). Direct ref10/orlp port (public domain). All the `fe*` primitives: mul, sq, invert, `fePow22523`, encode/decode, canonicity check (`feBytesCanonical`), constant-time `feCMove`/`feCSwap`.
2. **`scalar.nim`** — Curve25519 group ops in extended Edwards coordinates (`GeP3`/`GeP2`/`GeP1P1`/`GeCached`). Point add/sub/double and variable-base `scalarmult`. Curve constants (`Ed25519D_Raw`, `Ed25519Gx/Gy_Raw`, `SqrtM1_Raw`) live here.
3. **`ed25519.nim`** — RFC 8032 layer: `pointEncode`/`pointDecode` (strict §5.1.3: rejects y ≥ p and x=0-with-sign-bit), `scReduce` (512→mod L, ref10 port), `scIsCanonical`, and `verify`. Pulls SHA-512 from `nimcrypto/sha2`.
4. **`x25519.nim`** — RFC 7748 layer on `field.nim` only (no Edwards code): Montgomery ladder, `x25519` (returns `none` on all-zero shared secret, i.e. small-order peer point) and `x25519Base`.

### Implementation status (verify against the code, not this list)
- ✅ field, curve ops, `scalarmult`, ed25519 `verify` (RFC 8032 + Wycheproof clean), X25519 (RFC 7748 + Wycheproof clean), public facade
- ❌ ed25519 sign/keygen, libsodium adapter, dudect/ctgrind timing harness (`tests/ct/`), Ristretto255 (deliberately deferred — leave a clean extension point, don't build it)

## Building & testing

There is **no host Nim toolchain** in this environment. The project builds inside a container image (`Containerfile.amox`, based on `ghcr.io/coreyleavitt/nim:2.2.10`):

```sh
podman run --rm -v "$PWD":/workspace -w /workspace ghcr.io/coreyleavitt/nim:2.2.10 nimble test
```

`nim.cfg` sets `path="vendor"` (vendored nimcrypto), `path="src"`, `--mm:orc`, and `--outdir:"build"` (compiled binaries land in `build/`, which is gitignored — never commit binaries).

```sh
nimble test                              # full suite
nim c -r tests/unit/test_field.nim       # one test module
```

### Tests
- `tests/unit/test_field.nim` — field arithmetic sanity.
- `tests/unit/test_ed25519.nim` — RFC 8032 §7.1 vectors + §5.1.3 canonicity edges.
- `tests/unit/test_x25519.nim` — RFC 7748 §5.2/§6.1 vectors (incl. 1000-iteration ladder).
- `tests/unit/test_wycheproof.nim`, `test_wycheproof_x25519.nim` — Google Wycheproof adversarial vectors (vendored in `tests/vectors/`, from C2SP/wycheproof `testvectors_v1`). These must stay at zero failures.

### The validation bar (what earns trust without an audit)
This is the project's whole reason for caution — hold new code to it:
- Bit-exact pass of **RFC 8032** (ed25519) and **RFC 7748** (X25519) vectors. ✅ enforced in CI-less reality by `nimble test`.
- Pass **Google Wycheproof** adversarial vectors — the verifier must reject every malleable/non-canonical/small-order forgery. ✅ `test_wycheproof*.nim`.
- A **dudect/ctgrind-style timing harness** (intended `tests/ct/`) for the signer once it exists. ❌ not yet.

## Compact Instructions
When compacting, preserve in the summary: the active RFC and its handoff-doc path, the current stage/round, slices done vs remaining, open forks awaiting me, and the exact resume command. After compacting, re-read the handoff doc and MEMORY.md before continuing.

## Conventions
- Port from permissively-licensed references (ref10/djb, TweetNaCl, orlp) and **attribute in the module header** as existing files do. Get functional correctness against vectors first, then CT-harden the signer.
- Secrets (signing, X25519 scalars): fixed-size stack `array[N, uintXX]`, never `seq`/`string`; zero allocation in the hot path.
- Scratch/diagnostic files from debugging sessions do not get committed — the maintained suite lives in `tests/unit/`, and `build/` catches binaries.
