# sello

Pure-Nim ed25519 (EdDSA, RFC 8032) signing and verification, plus X25519
(ECDH, RFC 7748) key exchange -- the Curve25519 family. **No FFI in the
core.**

sello exists because the Nim ecosystem had no production pure-Nim
ed25519/X25519: every existing option wraps [orlp's ed25519][orlp] C.
`nimcrypto` covers hashes, HMAC, and symmetric ciphers well but has neither
25519 primitive. sello fills that gap: pure-Nim ed25519, X25519,
Curve25519, EdDSA, RFC 8032, RFC 7748.

[orlp]: https://github.com/orlp/ed25519

## The trust story

Signature **verification** and **signing** are independent implementations
of the same standard with radically different risk profiles, and sello's
API is built around that split rather than papering over it:

- **`verify` touches no secret** (its inputs -- public key, message,
  signature -- are all public data). It has no constant-time requirement,
  is fully testable, and ships with no asterisks. This is the part you can
  trust on the strength of its test suite alone: bit-exact against every
  RFC 8032 SS7.1 vector, and it rejects every one of the 668 adversarial
  cases in Google's [Wycheproof][wycheproof] EdDSA/X25519 vector sets
  (malleable signatures, non-canonical S, small-order points, invalid
  point encodings).

- **`sign`/`keygen` hold the secret scalar.** This is the roll-your-own-
  crypto half, and it carries the trust tax that implies:
  - The signer is constant-time by construction: `{.push checks: off.}`
    cores, secrets confined to fixed-size stack arrays (never `seq`/
    `string`), every secret-dependent selection done by arithmetic masking
    rather than a branch, and volatile-store-plus-barrier wiping of every
    secret (including intermediate SHA-512 hash state) as soon as it's no
    longer needed.
  - That discipline is backed by a [dudect][dudect]-style statistical
    timing harness (`tests/ct/`, run via `nimble ct`): 1,000,000
    interleaved fixed-vs-random-secret samples per target, Welch's t-test
    against dudect's published thresholds. The current run passes cleanly
    on all three secret-holding code paths, with a deliberately-leaky
    positive control confirming the harness can actually detect a timing
    leak of that size. Full methodology, numbers, and the honest limits
    of what this evidence does and doesn't prove (container vs. bare
    metal, `powersave` vs. `performance`, one CPU model, one compiler) are
    in [`docs/ct-results.md`](docs/ct-results.md).
  - If a statistical harness on unaudited Nim isn't enough assurance for
    your use case, compile with **`-d:selloLibsodium`** and every `sign`/
    `keypair` call dispatches to [libsodium][libsodium]'s audited C
    implementation instead, through the identical `Keypair` API. sello's
    own test suite (RFC vectors, plus bidirectional interop between the
    two backends) passes unmodified under the flag. `verify` is always
    pure-Nim, on both backends -- there's nothing to swap out on the side
    that was never the risk.

[wycheproof]: https://github.com/C2SP/wycheproof
[dudect]: https://eprint.iacr.org/2016/1123
[libsodium]: https://doc.libsodium.org/

**sello has not had an external security audit.** The validation bar above
(RFC vectors, Wycheproof, a timing harness) is what a project can
credibly claim without one; it is evidence toward correctness and
constant-time behavior, not proof. If your threat model requires an
audited implementation, use the `-d:selloLibsodium` backend for signing,
and treat `verify`'s Wycheproof-clean record as the strongest claim this
library makes on its own.

## Install

```
requires "sello"
```

Nim >= 2.2.10. Depends on `nimcrypto` for SHA-512 (the one primitive sello
deliberately does not reimplement); everything else is pure Nim.

## Usage

```nim
import sello

# Fresh identity. keypair() is the only function in sello's public
# surface that can raise (OSError, on a broken CSPRNG) -- let it
# propagate; failing fast on bad randomness is correct.
let kp = keypair()

let sig = kp.sign("hello")               # deterministic, total, constant-time
doAssert verify(sig, "hello", kp.public)

# openArray[byte] works the same way as the string overload above.
let msg = @[0x01'u8, 0x02, 0x03]
doAssert verify(kp.sign(msg), msg, kp.public)
```

Deriving a keypair from an existing 32-byte seed (import, tests, or a KDF
output) uses `toSeed`, not a `Seed(bytes)` cast -- `Seed` is a plain object
wrapper with its own wipe-on-scope-exit destructor, not a `distinct` alias,
so it does not get the built-in type-cast constructor syntax:

```nim
var seedBytes: array[32, byte] = ...      # from your own KDF/storage
let kp = keypair(toSeed(seedBytes))
```

Hold `Keypair`/`Seed` as stack values, never boxed in a `seq` or `ref` --
that's what lets their destructors guarantee the wipe. `Keypair` is
move-only (`=copy` is a compile error): pass it by value and let Nim move
it; a second live copy of the seed is a bug the compiler catches for you
at compile time.

`kp.sign(msg)` takes the keypair first (`sig = kp.sign(msg)`, matching
`x25519`'s actor-first argument order); `verify(sig, msg, pk)` takes the
signature first, because it shipped first, in the verify-only 0.1.0
release, and is already relied on that way. The asymmetry is a recorded,
deliberate decision (see `sello.nim`'s doc comment), not an oversight.

### X25519

```nim
import std/options
import sello

var aSecret, bSecret: array[32, byte]
# ... fill both from a CSPRNG ...

let aPublic = x25519Base(aSecret)
let bPublic = x25519Base(bSecret)

let shared = x25519(aSecret, bPublic)     # Option[array[32, byte]]
doAssert shared.isSome                    # None only for a small-order peer key
doAssert shared == x25519(bSecret, aPublic)
```

`x25519` returns `none` rather than a shared secret when the peer supplies
a small-order point (RFC 7748 SS6.1's zero-output check) -- callers need no
additional validation of the peer's public key.

### Optional libsodium backend

```
nim c -d:selloLibsodium yourprogram.nim
```

Dispatches `sign`/`keypair` to libsodium's `crypto_sign_seed_keypair` /
`crypto_sign_detached` (dynamically linked against distro
`libsodium-devel`; any libsodium >= 1.0.x resolves -- a missing library is
an ordinary linker error). `verify` is unaffected. There is no other API
change; code written against the pure-Nim backend recompiles as-is.

## Building and testing

There is no host Nim toolchain requirement beyond the container image used
in development; the commands below are what CI-less verification looks
like for this project:

```sh
podman run --rm -v "$PWD":/workspace -w /workspace \
  ghcr.io/coreyleavitt/nim:2.2.10 nimble test
```

```sh
nimble test                              # full suite, pure-Nim backend
nim c -r tests/unit/test_field.nim       # one test module
```

The libsodium backend and the timing harness need extra setup and are
separate tasks, not part of `nimble test`:

```sh
podman build -t sello-libsodium -f Containerfile .
podman run --rm -v "$PWD":/workspace -w /workspace \
  sello-libsodium nimble testLibsodium   # same suite, -d:selloLibsodium

podman run --rm -v "$PWD":/workspace -w /workspace \
  ghcr.io/coreyleavitt/nim:2.2.10 nimble ct   # dudect harness, ~1e6 samples/class
```

`nimble ct` is deliberately not part of `nimble test`: it is statistical
and environment-sensitive (a t-statistic, not a fixed pass/fail vector)
and takes considerably longer to run. See `docs/ct-results.md` for the
last recorded run and its measurement environment.

## What's not here

- **Ristretto255** -- deferred by design; the module layering leaves a
  clean extension point but nothing is built yet.
- **Ed25519ctx / Ed25519ph** (RFC 8032 SS5.1's context and prehash
  variants) and **key-container formats** (PKCS#8/JWK/OpenSSH) -- out of
  scope for now; sello speaks raw 32-byte seeds and signs full in-memory
  messages only.
- **Nonce hedging / fault-injection hardening** -- RFC 8032's deterministic
  nonce is implemented exactly as specified, with no additional
  randomization.

## License

Apache License, Version 2.0 -- see [`LICENSE`](LICENSE). Third-party
attributions (ref10, orlp/ed25519, and TweetNaCl, all public domain; the
vendored `nimcrypto` dependency, MIT) are in [`NOTICE`](NOTICE).
