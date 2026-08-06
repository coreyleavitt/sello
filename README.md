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
  point encodings). Note that RFC 8032's cofactorless verification
  equation is inherently malleable in a narrower sense Wycheproof's
  vectors don't (and can't) rule out: a second, distinct signature can
  exist for the same message and key, so signature bytes must never be
  used as a uniqueness/dedup key (see `verify`'s doc comment). The
  field/curve primitives both `verify` and `sign`
  build on (`feAdd`/`feMul`/`feInvert`, `feFromBytes`/`feToBytes`,
  `scReduce`, the fixed-base scalar multiplication table) additionally get
  property-based coverage against ring axioms, near-p boundary encodings,
  and an independent bignum reconstruction oracle -- see
  `tests/unit/test_properties_*.nim`. On top of the curated RFC/Wycheproof
  vectors, `pointDecode`/`verify`/`x25519` (the attacker-controlled-input
  surface -- raw bytes nobody proved well-formed before handing them to
  sello) also get coverage-guided fuzzing for crash/exception freedom
  (`tests/fuzz/`, run via `scripts/fuzz.sh`) -- unstructured mutation
  testing the ground the curated vectors don't cover by construction.
  Separately, `recodeScalarRadix16`'s digit-range invariant (previously
  only sampled) now has a machine-checked Z3 proof for its per-iteration
  arithmetic step (`tests/verify/`, run via `scripts/bmc.sh`) -- see that
  harness's module doc comment for the honest scope: the per-step lemma is
  exhaustively proved, but the 63-step composition is a manual induction
  argument, not itself Z3-checked, because the naive whole-function attempt
  did not complete in this environment's resource budget.

- **`sign`/`keygen` hold the secret scalar.** This is the roll-your-own-
  crypto half, and it carries the trust tax that implies:
  - The signer is constant-time by construction: `{.push checks: off.}`
    cores, secrets confined to fixed-size stack arrays (never `seq`/
    `string`), every secret-dependent selection done by arithmetic masking
    rather than a branch, and volatile-store-plus-barrier wiping of every
    secret (including intermediate SHA-512 hash state) as soon as it's no
    longer needed.
  - That discipline is backed by a [dudect][dudect]-style statistical
    timing harness (`tests/ct/`, run via `scripts/ct.sh`): 1,000,000
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
(RFC vectors, Wycheproof, a timing harness, fuzzing, and a partial machine-
checked proof) is what a project can credibly claim without one; it is
evidence toward correctness and constant-time behavior, not proof -- and
the one place this library does make a machine-checked claim
(`recodeScalarRadix16`'s digit ranges), it says exactly how far that
checking goes rather than rounding up. If your threat model requires an
audited implementation, use the `-d:selloLibsodium` backend for signing,
and treat `verify`'s Wycheproof-clean record as the strongest claim this
library makes on its own.

## Install

```
requires "sello"
```

Nim >= 2.2.10. Depends on `nimcrypto` for SHA-512 (the one primitive sello
deliberately does not reimplement); everything else is pure Nim. Development
resolves and pins `nimcrypto` via milpa (`milpa.kdl`/`milpa.lock`, commit SHA
+ content hash); nimble-ecosystem consumers resolve it normally via
`sello.nimble`'s `requires` floor.

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
import sello

var seedBytes: array[32, byte]
# fill seedBytes from your own KDF/storage
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

let aSecret = x25519Secret()              # fresh, via std/sysrand
let bSecret = x25519Secret()

let aPublic = x25519Base(aSecret)
let bPublic = x25519Base(bSecret)

let shared = x25519(aSecret, bPublic)     # Option[X25519Shared]
doAssert shared.isSome                    # None only for a small-order peer key
doAssert toBytes(shared.get) == toBytes(x25519(bSecret, aPublic).get)
```

X25519 has three roles, and each gets its own nominal type (RFC-001 ledger
#29, revisited: this replaces the earlier single `X25519Key` design):
`X25519Secret` (a private scalar; `x25519Secret()` for a fresh one,
`toX25519Secret(bytes)` from existing material), `X25519Public` (a public
u-coordinate; `toX25519Public(bytes)` from a peer's wire value), and
`X25519Shared` (a completed DH output -- feed it to a KDF, never use it
directly as a key). `X25519Secret`/`X25519Shared` wipe themselves on scope
exit and on explicit `wipe(...)`, the same as `Seed`; `toBytes` converts any
of the three back to raw bytes, e.g. for persistence -- the returned copy is
caller-owned and not itself wiped.

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

sello is developed against milpa (Corey's Nim dependency resolver), not
nimble: `milpa.kdl` declares `nimcrypto` as a pinned git dependency,
`milpa fetch` clones it into `_deps/` and emits `nim.cfg`, and `milpa.lock`
records the exact commit SHA + content hash resolved (see
[`NOTICE`](NOTICE)). Run `milpa fetch` once after cloning.

The property-based tests (`tests/unit/test_properties_*.nim`) need
[proptest](https://github.com/coreyleavitt/proptest), declared as an
*optional* milpa dep so plain `milpa fetch` never pulls it in for
consumers of sello. Enable it once for local development:
`milpa fetch --features proptest`.

There is no host Nim toolchain requirement beyond the container image used
in development; the commands below are what CI-less verification looks
like for this project:

```sh
scripts/test.sh                          # full suite, pure-Nim backend
nim c -r tests/unit/test_field.nim       # one test module (after milpa fetch)
```

The libsodium backend and the timing harness need extra setup and are
separate scripts, not part of `scripts/test.sh`:

```sh
scripts/test-libsodium.sh                # same suite, -d:selloLibsodium
                                          # (builds the sello-dev image if missing)
scripts/ct.sh                            # dudect harness, ~1e6 samples/class
scripts/fuzz.sh [seconds-per-target]     # coverage-guided fuzzing, default 60s x 3 targets
scripts/bmc.sh [timeout_secs]            # Z3-backed symex proof, default 300s hard kill-timeout
                                          # (needs the sello-dev image, same one as test-libsodium.sh)
```

`scripts/ct.sh` is deliberately not part of `scripts/test.sh`: it is
statistical and environment-sensitive (a t-statistic, not a fixed
pass/fail vector) and takes considerably longer to run. See
`docs/ct-results.md` for the last recorded run and its measurement
environment. `scripts/fuzz.sh` and `scripts/bmc.sh` are likewise separate:
an open-ended fuzz campaign and a solver run are not fixed-assertion
suites either. `scripts/bmc.sh` wraps its podman run in a hard external
kill-timeout (mirroring proptest's own `scripts/dt-bounded.sh`) because Z3
queries can fail to terminate rather than return a verdict -- see
`tests/verify/symex_recode.nim`'s module doc comment for what happened
when this project's own first attempt hit exactly that wall, and what it
proves instead.

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
`nimcrypto` dependency, MIT) are in [`NOTICE`](NOTICE).
