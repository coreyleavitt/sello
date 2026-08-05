# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`sello` is a **pure-Nim Curve25519 library** (ed25519 EdDSA + X25519 ECDH) with **no FFI** in the core. It exists because the Nim ecosystem had no production pure-Nim 25519 — every other option wraps orlp's C. SHA-512 is the one dependency we do *not* reimplement; it comes from vendored `nimcrypto`. See `prompt.md` for the full design brief and rationale — it is the authoritative spec, and current code is a partial implementation of it.

## The load-bearing design decision: VERIFY is split from SIGN

This split drives the whole API and trust story — preserve it:

- **Verification** (`ed25519.verify`) touches only public data (pubkey, message, signature). It has **no constant-time requirement**, is fully testable, and is the part that ships to everyone with no asterisks. `scalarmult` in `scalar.nim` uses plain 4-bit windows precisely because it only ever runs on the verify path — **do not add the signer's secret scalar to it.**
- **Signing / keygen** (not yet implemented) holds the secret scalar → **must be constant-time** and carries the roll-your-own-crypto trust tax. When built, it needs its own CT-hardened scalar mul (arithmetic masking, `{.push checks: off.}`, stack-only `array` secrets, volatile wipe, emit barriers — see `prompt.md` §"Constant-time toolkit"), plus an **optional libsodium FFI adapter behind `-d:selloLibsodium`** exposing the same API.

## Architecture (bottom-up layering)

Three modules under `src/sello/`, each built strictly on the one below:

1. **`field.nim`** — GF(2²⁵⁵−19) arithmetic. Radix 2²⁵·⁵, 10 `int32` limbs (`Fe` object). Direct ref10/orlp port (public domain). All the `fe*` primitives: mul, sq, invert, `fePow22523`, encode/decode, constant-time `feCMove`.
2. **`scalar.nim`** — Curve25519 group ops in extended Edwards coordinates (`GeP3`/`GeP2`/`GeP1P1`/`GeCached`). Point add/sub/double and variable-base `scalarmult`. Curve constants (`Ed25519D_Raw`, `Ed25519Gx/Gy_Raw`, `SqrtM1_Raw`) live here.
3. **`ed25519.nim`** — RFC 8032 layer: `pointEncode`/`pointDecode`, `scReduce` (512→mod L, ref10 port), `scIsCanonical`, and `verify`. Pulls SHA-512 from `nimcrypto/sha2`.

### Implementation status (verify against the code, not this list)
- ✅ field, curve ops, `scalarmult`, ed25519 `verify`
- ❌ ed25519 sign/keygen, X25519 (`x25519.nim` does not exist yet), libsodium adapter, Ristretto255 (deliberately deferred — leave a clean extension point, don't build it)

X25519 is in scope and reuses this exact field/curve core (same math minus the SHA-512 wrapping). The `nimble test` task already references a `tests/unit/test_x25519.nim` that does not yet exist.

## Building & testing

There is **no host Nim toolchain** in this environment. The project builds inside a container image (`Containerfile.amox`, based on `ghcr.io/coreyleavitt/nim:2.2.10`). Run Nim commands inside that container, or wherever Nim 2.2.10+ is available.

`nim.cfg` sets `path="vendor"` (vendored nimcrypto) and `path="src"` and `--mm:orc`, so imports like `import sello/field` resolve without extra flags.

```sh
nimble test                              # full suite (see sello.nimble; references a not-yet-present test_x25519.nim)
nim c -r tests/unit/test_field.nim       # one test module
nim c -r tests/unit/test_ed25519.nim
```

### Tests
- **Real suite:** `tests/unit/test_field.nim`, `test_ed25519.nim` (RFC 8032 §7.1 vectors).
- **Scratch/diagnostic files** — `test_femul.nim`, `test_pow.nim`, `test_x2.nim`, `test_p1p1.nim` (repo root, with committed binaries), and `tests/unit/diag*.nim`, `test_basic.nim`, `test_diag.nim`. These are debugging artifacts from porting, not the maintained suite. Don't treat them as the bar; don't extend them.

### The validation bar (what earns trust without an audit)
This is the project's whole reason for caution — hold new code to it:
- Bit-exact pass of **RFC 8032** (ed25519) and **RFC 7748** (X25519) vectors.
- Pass **Google Wycheproof** adversarial vectors — the verifier must reject every malleable/non-canonical/small-order forgery.
- A **dudect/ctgrind-style timing harness** (intended `tests/ct/`) for the signer once it exists.

## Conventions
- Port from permissively-licensed references (ref10/djb, TweetNaCl, orlp) and **attribute in the module header** as existing files do. Get functional correctness against vectors first, then CT-harden the signer.
- Secrets (when signing lands): fixed-size stack `array[N, uintXX]`, never `seq`/`string`; zero allocation in the hot path.
