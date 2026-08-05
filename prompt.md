 Build `sello` — a pure-Nim cryptographic library for the Curve25519 family. This
  is a NEW standalone library, pure nim.

  ## Why it exists
  The Nim ecosystem has NO production pure-Nim ed25519 or X25519 — every option
  (niv/ed25519.nim, MerosCrypto/mc_ed25519 [archived]) is an FFI wrapper around
  orlp's C. nimcrypto (pure Nim) covers hashes/HMAC/symmetric well but has neither
  25519 primitive. `sello` fills that gap. Its eventual consumer is a future crisol
  RFC that needs ed25519 signed attestation behind a `TrustPolicy` port — but that
  is downstream and out of scope here; build `sello` as a general-purpose lib on its
  own merits.

  ## Name & discoverability
  Name: `sello` (Spanish "seal/signet" — the wax seal that authenticates a
  document). Keep the evocative name BUT make the lib discoverable: load the .nimble
  description and README with keywords — "pure-Nim ed25519 + X25519, Curve25519,
  EdDSA, RFC 8032, RFC 7748, no FFI". People search by primitive, not by metaphor.

  ## Scope (a deep module around one shared core)
  The natural boundary is the field GF(2^255−19) and Curve25519 — everything built
  on it shares the hard implementation core (field arithmetic + scalar mul):
  - ed25519 (EdDSA signatures, RFC 8032) — the driver.
  - X25519 (ECDH key exchange, RFC 7748) — INCLUDE IT. It reuses the exact field/
    curve core (it's the same math minus the SHA-512 wrapping), and it's the other
    real pure-Nim gap. Two gaps, one core.
  - Ristretto255 — DEFER (a layer up; not needed initially; leave room for it).
  - SHA-512 (ed25519's internal hash) — do NOT reimplement; depend on nimcrypto
    (pure Nim, well-exercised). Keep `sello`'s "trust me" surface limited to the
    25519 math, not hashing.
  Anything past this (AES, RSA, P-256) is scope creep — nimcrypto/others cover it.

  ## The load-bearing design decision: split SIGN from VERIFY
  Sign and verify are independent implementations of the same standard (they
  interoperate by spec), and they have RADICALLY different requirements:

  - VERIFICATION touches NO secret (inputs: public key, message, signature — all
    public). Therefore it has NO constant-time requirement at all, and its
    correctness is fully testable to a high bar. This is the cleanly-ownable part:
    pure Nim, no asterisks, ships to every consumer. Make this excellent.

  - SIGNING / KEYGEN holds the secret scalar → MUST be constant-time → and carries
    the unaudited-roll-your-own-crypto trust tax. This is the hard, liability-heavy
    part.

  Design the API and the build so that the common path (verifying) is pure-Nim with
  zero ceremony, and signing is where the caution lives. Specifically:
  - Provide a pure-Nim signer, CT-hardened (see toolkit below), AND
  - Provide an OPTIONAL FFI signer adapter (libsodium) selectable by a build flag
    (e.g. `-d:selloLibsodium`) for users who want an audited signer. Same API,
    swappable impl. This dissolves the "nobody trusts your crypto" objection — the
    distruster flips a flag; you never force your signer on anyone.

  ## Constant-time toolkit for the signing path (Nim-specific)
  The secret-dependent-branch-reintroduction risk is at the C-compiler layer (shared
  with careful C). Close the Nim-specific surface with:
  - `{.push checks: off.}` (or targeted boundChecks/overflowChecks/nilChecks off)
    around the crypto core — removes Nim-inserted, potentially secret-placed checks.
  - Stack-only fixed `array[N, uint64]` for all secret material; NEVER seq/string
    for secrets; zero allocation in the hot path → orc/GC is simply not involved.
  - Constant-time selection by arithmetic masking (`r = b xor ((a xor b) and mask)`)
    — no secret-dependent branches, the same idiom ref10 uses.
  - `{.emit.}` / `asm volatile("" ::: "memory")` barriers after CT selects, plus
    `{.noinline.}`, to stop cc from "optimizing" masking back into a branch.
  - Zero secrets after use (volatile wipe).

  ## Validation bar (this is what earns trust without an audit)
  - Functional correctness: pass ALL RFC 8032 (ed25519) and RFC 7748 (X25519) test
    vectors, bit-exact.
  - Adversarial correctness (the important one for verification): pass Google
    Wycheproof's ed25519/X25519 vectors — malleability, non-canonical S, small-order
    points, invalid encodings, the "Taming the many EdDSAs" edge cases. The verifier
    must reject every forgery in that set.
  - Constant-time evidence for the signer: a dudect/ctgrind-style statistical timing
    harness, ideally across x86 and ARM and >1 cc version. Document the results and
    their limits honestly.

  ## Implementation approach
  - Port from a well-regarded, permissively-licensed reference (ref10/djb [public
    domain], TweetNaCl [public domain], or orlp/ed25519) — attribute properly. Get
    functional correctness against vectors FIRST, then CT-harden the signer.
  - Nim 2.x, `--mm:orc`. Match my toolchain conventions: milpa for deps (nimcrypto
    is in my milpa CAS), podman-wrapped build/test (no host nim) — mirror crisol's
    `./dev` wrapper pattern; set up the equivalent for this repo.
  - Tests in `tests/unit/` (vectors, Wycheproof) and a `tests/ct/` for the timing
    harness.

  ## Suggested first steps
  1. add nimcrypto dep.
  2. Build the field-arithmetic + Curve25519 scalar-mul core (shared by both).
  3. ed25519 verify → pass RFC 8032 + Wycheproof. (Pure win, no CT concerns.)
  4. ed25519 sign + keygen, CT-hardened → pass vectors + dudect.
  5. X25519 (reuses the core) → pass RFC 7748 + Wycheproof.
  6. Optional libsodium FFI signer adapter behind `-d:selloLibsodium`.
  7. Ristretto255: leave a clean extension point, do not build yet.

  Design from first principles, deep module, PhD-CS bar. Confirm the plan before
  writing code.
