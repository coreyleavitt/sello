# RFC-001: ed25519 signing milestone (sign, keygen, CT evidence, adapter)

Status: draft — pending two `/architect` review rounds
Scope: completes prompt.md steps 4 and 6, plus the `tests/ct/` harness and packaging.
Out of scope: Ristretto255 (deferred by spec), any new primitives.

## Context

`sello` today ships the safe half: a pure-Nim ed25519 verifier and X25519,
both clean against RFC vectors and Wycheproof (668 adversarial cases, zero
failures). What remains is the half that carries the trust tax: signing and
keygen hold the secret scalar, must be constant-time, and are the reason the
spec demands a swappable audited backend and honest timing evidence.

The load-bearing constraint from CLAUDE.md/prompt.md is preserved throughout:
**`sello/ed25519` stays verify-only and never touches a secret.** All
secret-handling code lands in a new module so the CT audit surface is one
file plus the field primitives it calls.

## Design

### Module: `src/sello/signer.nim`

New layer beside `ed25519.nim`, built on `field.nim` + `scalar.nim` types.
Holds everything secret-touching:

- `scMulAdd(s, a, b, c)` — S = (a·b + c) mod L, verbatim ref10
  `sc25519_muladd` port (same family as the existing `scReduce`).
- `geScalarmultBase(h, a)` — constant-time fixed-base scalar mult
  ([a]B is all signing ever needs; variable-base stays vartime in
  `scalar.nim` for the verifier). Ports ref10 `ge_scalarmult_base`:
  signed radix-16 digits, 32×8 precomputed table, CT table select via
  equality/negation masking (`feCMove`).
- `keypairFromSeed`, `sign` — RFC 8032 §5.1.5/§5.1.6.

**Precomputed table: derive, don't transcribe.** ref10's `base[32][8]`
table is ~30KB of magic constants; transcription is the likeliest place to
plant a silent bug. Instead compute the table at **compile time** with the
existing (vartime, public-data — the basepoint is public) curve ops via Nim
const evaluation, and assert equality against runtime-computed multiples in
tests. If the VM chokes on the int64 arithmetic, fall back to a checked-in
generator (`tools/gen_basetable.nim`) whose output is diffed in CI — never
hand-transcribed constants.

### Public API (facade additions)

```nim
type
  Seed* = array[32, byte]        # RFC 8032 secret key = 32-byte seed
  Keypair* = object
    public*: PublicKey
    seed*: Seed

func keypair*(seed: Seed): Keypair
func sign*(msg: openArray[byte]; kp: Keypair): Signature
```

Signing re-expands the seed via SHA-512 per call (standard RFC 8032 shape;
no long-lived expanded secret to protect). `SecretKey` (existing alias)
becomes `Seed`'s deprecated twin or is unified — architect rounds decide.

### Constant-time discipline (prompt.md toolkit, applied)

- `{.push checks: off.}` around `signer.nim`'s core (as `x25519.nim` does).
- Secrets only in fixed stack arrays; zero heap allocation in sign path.
- All secret-indexed selection via arithmetic masking (`feCMove`, new
  `cmovPrecomp`/`negateConditional` helpers); no secret-dependent branches
  or table indices.
- New `src/sello/private/ct.nim`: `wipe(var openArray[byte])` using volatile
  stores + `{.emit: "asm volatile(\"\" ::: \"memory\");".}` barrier;
  `{.noinline.}` on masking helpers to keep the C compiler from
  re-introducing branches.
- Evidence, not vibes: `tests/ct/` dudect-style harness (below).

### libsodium adapter (`-d:selloLibsodium`)

Same facade API; when the flag is set, `keypair`/`sign` dispatch to
libsodium (`crypto_sign_seed_keypair` / `crypto_sign_detached`) via FFI.
`verify` stays pure-Nim always — it's the part with no asterisks.
Compile-time dispatch (`when defined(selloLibsodium)`) in the facade, so
the pure signer isn't even compiled into distrusters' binaries.
Container needs `libsodium-devel` added to `Containerfile.amox`.

### Timing harness (`tests/ct/`)

dudect-style: run `sign` (and `x25519`) over two input classes — fixed
secret vs. per-sample random secret — collect cycle timings, Welch's
t-test; fail the task if |t| exceeds threshold (dudect convention: 10).
Separate `nimble ct` task, compiled `-d:release`; not part of `nimble test`
(statistical, environment-sensitive). Results and their limits (single
arch, single cc, no ctgrind) documented in `docs/ct-results.md`.

## Slices (each one `/tdd`-sized)

Stage A — secret-side math
1. **`scMulAdd`**: ref10 port + unit vectors (triples precomputed with an
   independent bignum tool, embedded in the test).
2. **Compile-time base table + CT select primitives**: table equals
   runtime-computed multiples of B; `cmovPrecomp`/conditional-negate
   behave per index/sign (all public-data tests).
3. **`geScalarmultBase`**: encoding of [k]B matches existing vartime
   `scalarmult(k, B)` for RFC seeds and random scalars.

Stage B — RFC 8032 layer
4. **`keypairFromSeed`**: RFC 8032 §7.1 seed→public-key vectors (3 cases).
5. **`sign`**: RFC 8032 §7.1 signatures bit-exact; sign→verify roundtrip
   property; facade exports wired.

Stage C — hardening + evidence
6. **Secret hygiene**: `private/ct.nim` wipe + barriers; audit pass over
   signer/x25519 (checks-off coverage, no-alloc, wipe-on-all-paths);
   wipe unit test.
7. **`tests/ct/` dudect harness** for `sign` + `x25519`; `nimble ct` task;
   `docs/ct-results.md` with honest limits.

Stage D — adapter + packaging
8. **libsodium adapter** behind `-d:selloLibsodium`: same RFC vector suite
   green under the flag; Containerfile gains libsodium-devel.
9. **README + package polish**: keyword-loaded README (spec
   §discoverability), license/attribution audit, nimble metadata.

Done-when per slice: tests green in the container, refactor clean, no slice
starts mid-RED. Slices 1–5 are strictly sequential; 6–7 and 8–9 can
interleave after 5.

## Risks / open questions for architect rounds

- Nim VM const-eval of the 10-limb int64 math for the base table — verify
  early in slice 2; generator fallback specified above.
- CT in Nim ultimately bottoms out at the C compiler (shared risk with
  careful C, per spec). The harness measures; it cannot prove. Documented
  honestly, plus the libsodium escape hatch.
- `SecretKey`/`Seed` naming unification (minor API break allowed pre-1.0).
- Whether `sign` should also accept a pre-expanded key form for hot paths
  (lean no: one obvious API, re-expansion is cheap relative to scalarmult).
