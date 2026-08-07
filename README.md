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
  only sampled) now has a machine-checked Z3 proof: the per-iteration
  arithmetic step, the full 63-step composition in one query over a
  generalized free-nibble domain, and -- via a written composition
  argument, not a further solver run -- the literal byte-array-in
  function itself, since its nibbles are mask-bounded by construction
  into the exact domain the free-nibble proof already covers. The
  companion reconstruction identity (that the emitted digits actually
  reconstruct the original scalar) is a separate property, proved by a
  written paper induction and backed by a sampled property test. See
  `tests/verify/symex_recode.nim`'s module doc comment (run via
  `scripts/bmc.sh`) for the full writeup, including the historical
  whole-byte-array single-query attempt this composition argument
  supersedes.

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
    on all five real secret-holding targets -- ed25519's `signDetached`
    and `geScalarmultBase`, the X25519 Montgomery ladder (`x25519Base`),
    an ephemeral-secret construct+consume calibration check, and a
    fixed-vs-random-secret leak test of the `X25519StaticSecret`
    arbitrary-peer DH path -- with a deliberately-leaky positive control
    confirming the harness can actually detect a timing leak of that
    size. Full methodology, numbers, and the honest limits of what this
    evidence does and doesn't prove (container vs. bare metal,
    `powersave` vs. `performance`, one CPU model, one compiler, and a
    shared rather than exclusively quiet host for the two most recent
    runs) are in [`docs/ct-results.md`](docs/ct-results.md).
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
doAssert kp.public.verify("hello", sig)

# openArray[byte] works the same way as the string overload above.
let msg = @[0x01'u8, 0x02, 0x03]
doAssert kp.public.verify(msg, kp.sign(msg))
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
that's what lets their destructors guarantee the wipe. Both `Keypair` and
`Seed` are move-only (`=copy` is a compile error): pass them by value and
let Nim move them; a second live copy of a secret is a bug the compiler
catches for you at compile time. `toSeedBytes(kp)` returns the keypair's
raw seed bytes for persistence -- the returned copy is caller-owned and
not itself wiped.

`kp.sign(msg)` takes the keypair first (`sig = kp.sign(msg)`) and
`pk.verify(msg, sig)` takes the public key first, matching RFC 8032's own
VERIFY(pk, M, sig) notation and ed25519-dalek's
`VerifyingKey::verify(message, signature)` -- both actor-first, and both
matching `x25519`'s own actor-first argument order.

### X25519

Prefer a fresh **ephemeral** secret per exchange unless you specifically
need a reusable, long-lived (**static**) X25519 identity -- e.g. a server
key you publish and reuse across many exchanges; a fresh ephemeral costs
nothing but one `x25519EphemeralPair()` call and cannot be reused even by
accident.

```nim
import std/options
import sello

var (aEph, aPublic) = x25519EphemeralPair()   # fresh secret + its public value
var (bEph, bPublic) = x25519EphemeralPair()

let shared = x25519(move(aEph), bPublic)      # Option[X25519Shared]; CONSUMES aEph
doAssert shared.isSome                        # None only for a small-order peer key
doAssert toBytes(shared.get) == toBytes(x25519(move(bEph), aPublic).get)
```

`X25519EphemeralSecret` is move-only: `x25519` takes it by `sink`, so
reusing the same variable in a second `x25519` call, or copying it
(`var b = a`), is a compile error, not a documented caller obligation --
verified against checked-in negative-compile fixtures. `x25519EphemeralPair`
derives the public value *inside* the constructor, so `aEph`/`bEph` above
have exactly one reference each (the consuming `x25519` call); `move(...)`
is still required at that call site because it's the only way to assert a
move out of a `var` binding, but no earlier read forces it the way a
separate derivation step would.

If you need to send your public value before generating it via the pair
(or some other flow that genuinely needs the two steps apart), fall back to
`x25519EphemeralSecret()` plus the non-consuming `x25519Base` overload:

```nim
import std/options
import sello

var eph = x25519EphemeralSecret()   # fresh, single-use, via std/sysrand
let pub = x25519Base(eph)           # non-consuming: safe to send first

let peer = x25519Base(x25519EphemeralSecret())
let shared = x25519(move(eph), peer)   # Option[X25519Shared]; CONSUMES eph
doAssert shared.isSome
```

Here the consuming `x25519(move(eph), peer)` call needs an explicit
`move(...)` (`eph` declared `var`, not `let`, since `move` requires that)
-- Nim's own idiom for "this really is safe to move," needed because the
compiler's own last-use check does not see through the earlier, harmless
`x25519Base` read. There is deliberately no way to construct an
`X25519EphemeralSecret` from existing bytes and no way to export one back
to bytes -- freshness and unpersistability are the whole point.

For a reusable identity, use `X25519StaticSecret` instead --
`x25519StaticPair()` gives you a fresh one plus its derived public value in
one call, mirroring `x25519EphemeralPair()`'s shape:

```nim
import std/options
import sello

let (aSecret, aPublic) = x25519StaticPair()   # fresh secret + its public value
let (bSecret, bPublic) = x25519StaticPair()

let shared = x25519(aSecret, bPublic)         # Option[X25519Shared]
doAssert shared.isSome                        # None only for a small-order peer key
doAssert toBytes(shared.get) == toBytes(x25519(bSecret, aPublic).get)
```

`X25519StaticSecret` is deliberately copyable -- unlike `Seed`/`Keypair`,
there is no paired invariant a second live copy could violate: `aSecret`
above is reusable across as many exchanges as you like.
`toX25519StaticSecret(bytes)` constructs one from existing material (e.g. a
persisted key); pair `x25519Base(...)` with it yourself in that case --
`x25519StaticPair()` is only for a fresh secret.

X25519's public/shared roles round out the type family: `X25519Public` (a
public u-coordinate; `toX25519Public(bytes)` from a peer's wire value) and
`X25519Shared` (a completed DH output -- feed it to a KDF, never use it
directly as a key). Every secret-holding type (`X25519StaticSecret`,
`X25519EphemeralSecret`, `X25519Shared`) wipes itself on scope exit and on
explicit `wipe(...)`, the same as `Seed`; `toBytes` converts the other
types back to raw bytes, e.g. for persistence -- the returned copy is
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

A fresh clone's plain `milpa fetch` (no `--features proptest`) is enough to
run `scripts/test.sh` green: the four `test_properties_*.nim` files are
detected as unavailable and print a loud `SKIPPED (proptest not fetched --
run: milpa fetch --features proptest)` line instead of failing the build.

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
- **Batch verification** -- considered; deferred to a future RFC --
  random-weight batch verify is vartime-tier but has real
  small-order/cofactor subtleties.

## License

Apache License, Version 2.0 -- see [`LICENSE`](LICENSE). Third-party
attributions (ref10, orlp/ed25519, and TweetNaCl, all public domain; the
`nimcrypto` dependency, MIT) are in [`NOTICE`](NOTICE).
