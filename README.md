# sello

[![merge-gate](https://github.com/coreyleavitt/sello/actions/workflows/merge-gate.yml/badge.svg?branch=main)](https://github.com/coreyleavitt/sello/actions/workflows/merge-gate.yml?query=branch%3Amain)
[![nightly](https://github.com/coreyleavitt/sello/actions/workflows/nightly.yml/badge.svg?branch=main)](https://github.com/coreyleavitt/sello/actions/workflows/nightly.yml?query=branch%3Amain)

Pure-Nim ed25519 (EdDSA, RFC 8032) signing and verification, plus X25519
(ECDH, RFC 7748) key exchange -- the Curve25519 family. **No FFI in the
core.**

sello exists because the Nim ecosystem had no production pure-Nim
ed25519/X25519: every existing option wraps [orlp's ed25519][orlp] C.
sello fills that gap: pure-Nim ed25519, X25519, Curve25519, EdDSA, RFC 8032,
RFC 7748 -- **zero runtime dependencies**. SHA-512 (ed25519's internal hash)
was originally sourced from `nimcrypto`; as of RFC-006 it is in-house,
implemented directly from FIPS 180-4 and validated against the full NIST
CAVP SHAVS vector corpus, so nothing outside this source tree ever touches
a secret.

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

## Threat model / when not to use this

The prose above states these caveats in context; this section pulls them
into one skimmable list for anyone deciding whether sello fits their
threat model:

- **Timing evidence is statistical, not a proof of constant-time
  behavior.** The dudect-style harness (`tests/ct/`) reports a t-statistic
  under Welch's t-test, not a formal guarantee -- and its own honest
  limits matter: this environment's runs were in a container (not bare
  metal), under the `powersave` frequency governor (not `performance`),
  on a single CPU model and compiler, and -- for the three most recent
  runs -- on a host shared with another, otherwise-idle container rather
  than an exclusively quiet one. Full methodology, numbers, and this
  reasoning in detail are in [`docs/ct-results.md`](docs/ct-results.md).
- **No defense against a memory-dumping attacker beyond destructor-driven
  wipes.** Every secret-holding type volatile-store-wipes itself on scope
  exit (`sello/private/ct`), but sello does not `mlock` its stack pages or
  use a guarded-heap allocator -- an attacker who can read process memory
  or a core dump *while a secret is live* is not defended against by this
  library, only by the OS/runtime environment you run it in.
- **Signature malleability.** RFC 8032's cofactorless verification
  equation admits a second, distinct valid signature for the same message
  and key; never use signature bytes as a uniqueness or dedup key (see
  `verify`'s and `Signature`'s own doc comments).
- **The pure-Nim signer is unaudited.** It carries the roll-your-own-
  crypto trust tax described above; if that is not acceptable for your use
  case, `-d:selloLibsodium` dispatches `sign`/`keypair` to libsodium's
  audited C implementation instead, through the identical `Keypair` API.
  `verify` is pure-Nim on both backends and carries no such asterisk.
- **All timing evidence is from one machine.** No cross-CPU-model or
  cross-architecture (x86 vs. ARM) timing comparison has been run; see the
  point above and `docs/ct-results.md` for the exact environment.

## Install

```
requires "sello"
```

Nim >= 2.2.10. **Zero dependencies** -- SHA-512 is implemented in-house
(`src/sello/private/sha512.nim`, FIPS 180-4); `nimcrypto` was sello's SHA-512
dependency through the 0.4.0 release and has been fully retired. A plain
`milpa fetch` (development) or `nimble install` (ecosystem consumers)
resolves nothing at all for the core library; `proptest` remains, optional
and dev-only, for property-based testing (see "Building and testing"
below).

`nim >= 2.2.10` in `sello.nimble` is a compatibility floor, not a tested
matrix: every claim in this README (RFC vectors, Wycheproof, the timing
harness, mutation testing, the Z3 proofs) was gathered against exactly
Nim 2.2.10, the version pinned in `Containerfile`/`scripts/*.sh`'s
container image. Newer 2.x releases are expected to work but have not
been separately verified.

Source-tree builds and the test suite (`scripts/test.sh` and friends)
require milpa; a plain `nimble install` consumer gets the library only,
resolved through `sello.nimble`'s `requires` floor as above -- see
"Building and testing" below for what milpa does and the manual
equivalent for an environment without it.

## Usage

```nim
import sello

# Fresh identity. keypair() raises OSError on a broken CSPRNG, the
# same fail-fast policy shared by every fresh-secret constructor in
# sello's public surface (keypair, x25519StaticSecret,
# x25519EphemeralSecret, x25519StaticPair, x25519EphemeralPair) --
# let it propagate; failing fast on bad randomness is correct.
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

If your storage carries **both halves** of the key -- the dominant
real-world layout is OpenSSH's/libsodium's `seed(32) ‖ publicKey(32)`
secret key -- load through `keypair(seed, expectedPublic)` instead. It
re-derives the public key from the seed and returns `none` on a mismatch,
so a corrupted or mixed-up stored key is rejected at load time. Without
the check that failure mode is nasty and silent: sello derives the public
half from the seed, so a corrupted seed still *signs successfully* --
under a public key you never presented. `Keypair` is move-only, so
extract the payload with `move`:

```nim
import std/options
import sello

var seedHalf, publicHalf: array[32, byte]
# split your stored seed(32) ‖ publicKey(32) blob into the two halves
var loaded = keypair(toSeed(seedHalf), toPublicKey(publicHalf))
if loaded.isNone:
  quit("stored key is corrupt: seed does not derive the stored public key")
var kp = move(loaded.get())
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

The exception policy above is a **declared, compiler-checked effect**, not
a doc promise: every module in the public surface carries `{.push raises:
[], gcsafe.}`, with the five fresh-secret constructors explicitly
annotated `{.raises: [OSError].}` (and, under `-d:selloLibsodium` only,
the sign/keygen path adding `SodiumInitError`, exported through the
facade on that backend). Consumer code annotated `{.raises: [], gcsafe.}`
composes against sello's declared effects -- if a future sello change
accidentally introduced a raise on the pure surface, sello's own build
would go red rather than surfacing downstream as an opaque
effect-inference error.

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
public u-coordinate; `toX25519Public(bytes)` from a peer's wire value),
`X25519BasePoint` (the RFC 7748 base point as an `X25519Public` constant --
`x25519Base`'s implicit peer, exposed for callers who need it explicitly),
and `X25519Shared` (a completed DH output -- feed it to a KDF, never use it
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

### Ristretto255

[RFC 9496](https://www.rfc-editor.org/info/rfc9496) ristretto255: a
prime-order group built on top of the same Curve25519 curve, closing the
cofactor-malleability class of bug a raw curve point invites (Monero's
key-image double-spend is the canonical real-world casualty). It is the
substrate modern protocol work assumes -- Pedersen commitments, DH shares,
OPRF evaluation, Schnorr proofs-of-knowledge -- where a raw Edwards point's
small-order components and non-unique encodings are a foot-gun. Every
`RistrettoPoint` names one group element with exactly one canonical
32-byte encoding; non-canonical or small-order garbage does not decode.

```nim
import sello

# H: an independent generator with no known discrete log relative to the
# base point, derived via the one-way hash-to-group map from 64
# domain-separated bytes (a real protocol hashes its own context string;
# this example hardcodes bytes only so it is deterministic).
var hSeed: array[64, byte]
for i in 0 ..< 64: hSeed[i] = byte(i * 7 + 11)
let h = ristrettoFromUniformBytes(hSeed)

# A Pedersen commitment to value x, blinded by r: commit = xB + rH.
let x = ristrettoStaticSecret()   # the committed value
let r = ristrettoStaticSecret()   # the blinding factor
let commitment = ristrettoScalarmultBase(x) + ristrettoScalarmult(r, h)

# Open: recompute from the revealed (x, r) and compare via ==.
doAssert (ristrettoScalarmultBase(x) + ristrettoScalarmult(r, h)) == commitment
```

`ristrettoDecode`/`ristrettoEncode`/`==`/`ristrettoFromUniformBytes` are
constant-time by construction (the final accept/reject verdict is
inherently caller-visible and carries no CT obligation of its own -- see
`sello/ristretto`'s module doc comment for the full CT-posture writeup).
Scalar multiplication follows the same CT-vs-vartime type gate as the rest
of this library: `ristrettoScalarmultVartime` accepts only a bare
`array[32, byte]` (public-scalar protocol steps), while
`ristrettoScalarmultBase`/`ristrettoScalarmult` above take one of two
secret-scalar role types mirroring X25519's static/ephemeral split --
`RistrettoStaticSecret` (reusable, used above) or `RistrettoEphemeralSecret`
(single-use, move-only, for an ElGamal/ECIES-style one-shot DH share).

**The one-shot DH share's product is `Option[RistrettoShared]`, not a bare
`RistrettoPoint`.** `ristrettoScalarmult(sink RistrettoEphemeralSecret,
peer): Option[RistrettoShared]` -- the ephemeral role's consuming call --
hands back the completed `S = k*P` DH product as `RistrettoShared`: a
wiped, `x25519.X25519Shared`-shaped holder (`toBytes`, `wipe`, auto-wiping
`=destroy`), not a freely-copyable `RistrettoPoint`. `S` IS the shared
secret an ECIES/hybrid-encryption flow feeds to a KDF, unlike every other
`RistrettoPoint` this library hands back (a Pedersen commitment, an OPRF
blinded element), which is published and so needs no such hygiene. The
result is `none` iff `S` is the identity -- `peer` was itself
`RistrettoIdentity`, or (negligible for a freshly-sampled ephemeral) the
scalar reduced to 0 mod L -- the same `x25519`-style rejection of a
predictable, attacker-known "shared secret" (round-3 finding R3-1):

```nim
import sello
import std/options

var (ephemeralSecret, c1) = ristrettoEphemeralPair() # c1: send alongside the ciphertext
let (recipientSecret, recipientPublic) = ristrettoStaticPair()

# Sender: the ephemeral role's consuming call returns Option[RistrettoShared]
# -- `none` only for a degenerate identity peer, which a real
# recipientPublic never is. Extract its bytes -- feed them to a KDF to
# derive the symmetric key, never use them directly as one -- then dispose
# of both the extracted copy and the RistrettoShared itself.
let sharedOpt = ristrettoScalarmult(move(ephemeralSecret), recipientPublic)
doAssert sharedOpt.isSome
var shared = sharedOpt.get()
var sharedBytes = toBytes(shared)

# Recipient: the static-role overload recomputes the identical product
# from their own secret and the sender's c1, but returns a plain
# RistrettoPoint (see below for why).
let recipientShared = ristrettoScalarmult(recipientSecret, c1)

# Agreement check via the documented vartime RistrettoEncoded == idiom (see
# "Two == operators" below), not a raw-array compare -- both sides bring
# their product to the same canonical wire representation first.
doAssert ristrettoEncode(recipientShared) == toRistrettoEncoded(sharedBytes) # both sides agree on the DH product

wipe(shared)
wipe(sharedBytes)
```

The static-role overload above (`ristrettoScalarmult(secret:
RistrettoStaticSecret, ...)`) is deliberately UNCHANGED -- it still returns
a plain `RistrettoPoint`, because its own documented consumers (an OPRF
server's evaluation, a Pedersen commitment) publish the result. A caller
using the static role itself for a DH share (e.g. a CPace-style PAKE, which
needs two variable-base multiplications against the same scalar and so
cannot use the single-use ephemeral role) gets no automatic wipe of the
returned point -- there is none to give a freely-copyable type -- and
should either encode immediately and wipe the resulting bytes, or minimize
the point's lifetime, per `sello/ristretto`'s module doc comment.

**Two `==` operators, two timing registers -- read this before comparing
in a timing-sensitive position.** `RistrettoPoint`'s `==` (used above) is
constant-time; `RistrettoEncoded`'s `==` is the ordinary vartime
byte-compare every other wire type in this library uses. An operator
cannot carry a `Vartime` suffix, so the register switch is silent at the
call site -- compare `RistrettoPoint`s directly in any timing-sensitive
position; calling `ristrettoEncode` on both sides first (the natural move
for a caller about to serialize anyway) silently downgrades a CT
comparison to vartime. There is also deliberately no `hash(RistrettoPoint)`
-- key or dedupe on `RistrettoEncoded` (encode first), never on the point.

**What this ships, and what it doesn't:** this is the GROUP --
decode/encode/equality/the hash-to-group map/group operators/scalar
multiplication -- not a scalar-arithmetic API. That's enough for
commitment/DH/blinding-shaped protocols (Pedersen commit/open above,
ElGamal/ECIES-style encryption, an OPRF SERVER's evaluation step) but not
for protocols whose secret math goes further: a Schnorr response needs
mod-L scalar multiply-add, and an OPRF CLIENT's unblind step needs mod-L
scalar inversion -- neither is exposed at this facade (the multiply-add
exists submodule-only in `sello/scalar`; the inversion exists nowhere in
sello at any layer). See `sello/ristretto`'s module doc comment for the
full boundary.

## Validation

The `merge-gate` badge above reflects the status of `main`'s required CI
checks (see [`CONTRIBUTING.md`](CONTRIBUTING.md) for the current gate
list and how to run the same checks locally). The `nightly` badge
reflects a separate, NON-required, non-gating workflow: long-running
fuzz campaigns with a persisted corpus and property suites at a cranked
example count -- deeper evidence than fits a per-push gate, run on a
schedule rather than blocking a merge; a red `nightly` badge means one
of those deeper runs needs attention, not that `main` is broken. (A
third, unbadged workflow, `toolchain-canary`, watches Nim
devel/newest-stable, the newest packaged gcc/clang, and milpa's own
`main` HEAD for drift against this project's pinned toolchain --
advisory-only by design, so it deliberately carries no badge of its own;
see CLAUDE.md's CI section for the full nightly/canary design.) The
evidence backing the claims made throughout this README --
RFC 8032/RFC 7748 vector conformance, Wycheproof adversarial vectors, the
dudect timing harness, mutation testing, differential testing against
libsodium, property-based testing, coverage-guided fuzzing, and the Z3
proofs -- lives in [`docs/`](docs/): [`docs/ct-results.md`](docs/ct-results.md)
and [`docs/mutation-results.md`](docs/mutation-results.md) are the standing
evidence records, and `docs/rfc-001-signing.md` through
`docs/rfc-006-sha512.md` are the design docs each piece of that evidence
was built against.

### Validation map

The table below maps every claim in `CLAUDE.md`'s "The validation bar"
section to the mechanism that enforces it. It is hand-curated -- the
prose is the value -- but its load-bearing columns (**Category**,
**Mechanism**, **Freshness canary**, **Carve-out doc**, **Row key**) are
checked on every push by the `validation-map` gate
(`scripts/validation-map-check.sh`), so this table cannot silently drift
from what CI actually runs. **Category** is one of three kinds, each with
its own mechanical proof that the named mechanism is real, not merely
claimed:

- **required-check** -- a job in `merge-gate.yml`'s required set (checked:
  the job name exists in both `.github/workflows/merge-gate.yml` and
  `scripts/lib/gates.txt`; the live GitHub ruleset's required-check set is
  itself *generated* from `gates.txt` by `scripts/ruleset-apply.sh` and
  independently verified against it by the `ruleset-sync` gate, so
  `gates.txt` membership is the correct, non-duplicative proxy here).
- **nightly** -- a job in the separate, non-required `nightly.yml`
  workflow (checked: the job name exists there).
- **manual-ritual** -- a maintainer-run script with no CI wiring of its
  own yet (checked: the row's declared **Freshness canary** is real -- a
  committed file, an entry in the committed
  `scripts/lib/validation-map-pending.txt` allowlist recording which
  future slice owes the real canary, or an explicit `none (by design)`
  for a ritual the RFC never demanded a freshness canary for at all).

<!-- VALIDATION-MAP:TABLE START -->
| Claim | Category | Mechanism | Freshness canary | Carve-out doc | Row key |
|---|---|---|---|---|---|
| Bit-exact pass of RFC 8032 (ed25519) and RFC 7748 (X25519) vectors | required-check | `unit-linux-amd64-gcc` (and its six sibling `unit-*` legs across the CI matrix) | n/a | none | rfc-vectors |
| Pass Google Wycheproof adversarial vectors (ed25519 + X25519) | required-check | `unit-linux-amd64-gcc` (same unit suite; no Wycheproof corpus exists for ristretto255 -- RFC 9496 App. A plus fuzzing plus the libsodium differential suite carry that weight instead) | n/a | none | wycheproof |
| dudect timing harness -- compiles cleanly, no verdict | required-check | `build-smoke` (compiles `tests/ct/ct_main.nim`, never runs it) | n/a | none | dudect-compile-smoke |
| dudect timing harness -- real worst-case t-statistic verdict, ten targets | manual-ritual | `scripts/ct.sh` (maintainer-run, `-d:release`, roughly 1e6 samples/class) | pending slice 28 | `docs/ct-results.md` | dudect-full-battery |
| Taint-based deterministic CT harness -- compiles cleanly, no verdict | required-check | `build-smoke` (compiles every `tests/ct_taint/` target, never runs one under valgrind) | n/a | none | taint-compile-smoke |
| Taint-based deterministic CT harness -- real per-executed-path memcheck verdict, gcc and clang backends (a deterministic no-branch/no-index proof, not a statistical timing verdict -- complements the dudect rows above, does not replace them) | required-check | `taint-ct-linux-amd64-gcc` (and `taint-ct-linux-amd64-clang`) | n/a | none | taint-ct |
| Mutation testing of the highest-risk arithmetic/boundary logic (84/84 killed) | required-check | `mutation` (`scripts/mutation.sh`, full catalog, unsharded) | n/a | `docs/mutation-results.md` | mutation-catalog |
| Coverage ratchet -- aggregate + per-file line coverage, monotone per file (not diff coverage) | required-check | `coverage-ratchet` (`scripts/coverage.sh`, full unit+property suite, fixed proptest seeds, build+run twice for a determinism check) | n/a | `tests/coverage/expected/baseline.txt` | coverage-ratchet |
| Audited alternative implementation builds cleanly (`-d:selloLibsodium`) | required-check | `api-surface-libsodium` (facade compiles and its surface diff is pinned under this config; does not itself run the interop suite below) | n/a | none | libsodium-build |
| Differential adversarial testing against libsodium, bidirectional interop | required-check | `unit-linux-amd64-gcc-libsodium` (recompiles the unit suite with `-d:selloLibsodium`; `SELLO_REQUIRE_LIBSODIUM=1` makes any skip fatal, so it can never silently degrade to a no-op suite) | n/a | none | libsodium-interop |
| Property-based testing of field/scalar/ristretto/sha512 primitives | required-check | `property-linux-amd64-gcc` (and `property-linux-amd64-clang`, `property-linux-arm64-gcc`) | n/a | none | property-merge-gate |
| Property-based testing -- deeper nightly pass at a cranked example count | nightly | `cranked-properties` (10x `maxExamples`, same suites as the merge-gate job above) | n/a | none | property-cranked-nightly |
| Coverage-guided fuzzing -- target and driver compile, one iteration run | required-check | `build-smoke` (real SanitizerCoverage instrumentation; one deterministic known-valid input, not a campaign) | n/a | none | fuzz-compile-smoke |
| Coverage-guided fuzzing -- real campaign with cross-run corpus continuity | nightly | `fuzz` (450s/target default, persisted corpus via proptest's `directoryBasedDatabase`) | n/a | none | fuzz-nightly-campaign |
| Coverage-guided fuzzing -- periodic corpus snapshot promoted into the committed seed corpus | manual-ritual | hand-curation of interesting entries into `fuzz_common.nim`'s `*Seeds()` procs (the one standing manual duty the no-bots rule imposes) | `scripts/nightly-fuzz.sh` (its corpus staleness canary is the compensating control) | none | fuzz-snapshot-ritual |
| Machine-checked Z3 proof of `recodeScalarRadix16` plus the CT mask/equality/reduce primitives | required-check | `bmc-symex` (`scripts/bmc.sh`, needs the `sello-dev` image) | n/a | none | bmc-symex |
| Platform breadth (A4) -- big-endian s390x via cross-compile + QEMU user-mode, unit/KAT suite plus a runtime endianness canary | nightly | `s390x` (`scripts/test.sh --cpu s390x`; unit+KAT scope only -- the property suites proved prohibitively slow under emulation, see CLAUDE.md's own record) | n/a | none | s390x-nightly |
| Untainted memcheck (A9) -- Valgrind memcheck over the unit suite for uninitialized reads and invalid accesses | nightly | `memcheck` (`scripts/memcheck.sh`) | n/a | none | memcheck-nightly |
<!-- VALIDATION-MAP:TABLE END -->

**Platform support.** <!-- VALIDATION-MAP:PLATFORM START -->The required
CI matrix builds and tests sello on: linux amd64 (`unit-linux-amd64-gcc`,
`unit-linux-amd64-clang`, `unit-linux-amd64-gcc-asan-ubsan`), linux i386
(`unit-linux-i386-gcc`, 32-bit multilib, unit suite only), linux arm64
(`unit-linux-arm64-gcc`), macOS arm64 (`unit-macos-arm64-clang`), and
Windows amd64 (`unit-windows-amd64-gcc`, MinGW-w64 gcc). MSVC (`vcc`) is
not a supported build target: the constant-time signer's secret-wipe
primitive (`private/ct.nim`) depends on an `asm volatile` compiler
barrier, which MSVC's compiler intrinsics have no equivalent for. WASM is
not merely untested but **unsupported-for-secrets**: `private/ct.nim`'s
wipe barrier and `std/sysrand` do not exist there, so the wipe and
keygen guarantees are void; the verify-only path may well compile, but
nothing in this README claims more than that.<!-- VALIDATION-MAP:PLATFORM END -->

**CT claim scope.** <!-- VALIDATION-MAP:CT-SCOPE START -->The dudect
timing evidence in `docs/ct-results.md` is verified on the CI-pinned
toolchains only: gcc 16.1.1, clang 22.1.8, both inside the pinned image
`ghcr.io/coreyleavitt/nim@sha256:cd4708fb29d16ec4256a0bdcf8a4873b1f5a7a7200e32890ed52d5893227e780`
(`scripts/lib/image-pins.txt`'s own committed record is the source of
truth for these three numbers; this sentence is checked against it, not
the other way around). A consumer who compiles sello with their own
toolchain -- a different gcc/clang version, a different libc, a different
optimization level -- is compiling code this project believes is
constant-time by construction (branchless on secret data, arithmetic
masking throughout), but has not itself measured under that toolchain;
that residual is disclosed here, not elided.<!-- VALIDATION-MAP:CT-SCOPE END -->

## Building and testing

sello is developed against milpa (Corey's Nim dependency resolver), not
nimble. As of RFC-006 (in-house SHA-512 retired the `nimcrypto`
dependency), `milpa.kdl` declares no unconditional dependency at all: a
plain `milpa fetch` resolves ZERO deps, emitting a `nim.cfg` with just
`src/`'s own `--path` line. `proptest` (see below) is the one dependency
`milpa.lock` ever records, and only once fetched with `--features
proptest`. Run `milpa fetch` once after cloning.

**Reproducibility note:** milpa is the author's own tool, and this
repository does not reference a public URL for it (unlike `proptest`,
which is an ordinary public git repository pinned in `milpa.lock` once
fetched); the container image the dev scripts build against,
`ghcr.io/coreyleavitt/nim:2.2.10`, is likewise not established here as
publicly pullable. Neither is required to verify sello's claims, though:
everything milpa generates for this project is `nim.cfg`'s `--path` lines
(`src/`, plus one per resolved dependency directory -- `nim.cfg` itself is
gitignored/regenerated, not checked in; `config.nims`, which milpa never
touches, is the other file Nim reads). The manual equivalent in any Nim
2.2.10 environment for the core library is simply `--path:src` passed to
`nim c`/`nim check` -- no dependency clone of any kind is needed. For the
optional property tests (below), add [proptest][proptest-repo] cloned at
the commit `milpa.lock` records once fetched, plus its own transitive
`nim-z3`/`softlink` clones, each contributing one more `--path:<clone>` --
this is the one case where a dependency clone is needed at all, and it is
never needed for a plain build of the library itself. The exact
invocations themselves (what flags, what image, what mounts) are
documented in `scripts/*.sh`, so the build is reproducible from the
scripts' own text even without milpa or the container image.

[proptest-repo]: https://github.com/coreyleavitt/proptest

The property-based tests (`tests/unit/test_properties_*.nim`) need
[proptest][proptest-repo], declared as an *optional* milpa dep so plain
`milpa fetch` never pulls it in for consumers of sello. Enable it once for
local development: `milpa fetch --features proptest`.

There is no host Nim toolchain requirement beyond the container image used
in development; the commands below are what CI-less verification looks
like for this project:

```sh
scripts/test.sh                          # full suite, pure-Nim backend
nim c -r tests/unit/test_field.nim       # one test module (after milpa fetch)
```

A fresh clone's plain `milpa fetch` (no `--features proptest`) is enough to
run `scripts/test.sh` green: the six `test_properties_*.nim` files are
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

- **decaf448** -- no Curve448 core exists in sello and none is planned;
  ristretto255 (Curve25519-based) above is the only prime-order group this
  library ships.
- **A public scalar-arithmetic API** on the ristretto255 group -- see the
  Ristretto255 section above for the boundary this draws (commitment/DH/
  blinding-shaped protocols are served; Schnorr responses and OPRF client
  unblinding are not).
- **Batch/double-scalar ristretto255 operations** and **Elligator inverse**
  (element to uniform bytes, for censorship-resistant transports) -- real
  features, deferred until a consumer exists to size them.
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
attributions (ref10, orlp/ed25519, and TweetNaCl, all public domain; RFC
9496, whose formulas and constants `sello/ristretto` transcribes, subject
to the IETF Trust's terms; FIPS 180-4, a public NIST standard, whose
algorithm and constants `sello/private/sha512` transcribes; the `nimcrypto`
dependency, MIT, retired as of RFC-006 -- its SHA-512 implementation served
sello through the 0.4.0 release) are in [`NOTICE`](NOTICE).
