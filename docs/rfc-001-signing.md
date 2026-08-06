# RFC-001: ed25519 signing milestone (sign, keygen, CT evidence, adapter)

Status: draft — architect round 1 applied, pending round 2
Scope: completes prompt.md steps 4 and 6, plus the `tests/ct/` harness and packaging.

Non-goals (explicit, so silence isn't ambiguity):
- Ristretto255 — deferred by spec; leave the extension point clean.
- Ed25519ctx / Ed25519ph (RFC 8032 §5.1 context/prehash variants) — not in
  prompt.md scope; libsodium supports ph, so a future RFC may add them, but
  nothing ships now.
- Fault-injection hardening (nonce "hedging"): RFC 8032's deterministic
  nonce is kept exactly as specified. Glitch resistance is a documented
  non-goal — revisit only if a hardware-adjacent consumer appears.
- Reordering the shipped `verify(sig, msg, pk)` for family symmetry — it is
  tested and shipped; candidate for a separate, explicitly-scoped RFC.

## Context

`sello` today ships the safe half: a pure-Nim ed25519 verifier and X25519,
both clean against RFC vectors and Wycheproof (668 adversarial cases, zero
failures). What remains is the half that carries the trust tax: signing and
keygen hold the secret scalar, must be constant-time, and are the reason the
spec demands a swappable audited backend and honest timing evidence.

The load-bearing constraint from CLAUDE.md/prompt.md is preserved throughout:
**`sello/ed25519` stays verify-only and never touches a secret.** All
secret-handling code lands in a new module so the CT audit surface is one
file plus the primitives it calls.

## Design

### Module layout

Three new homes, chosen so the audit surface stays small and the facade
stays logic-free:

- **`src/sello/signer.nim`** — the pure-Nim secret-math backend. Seed-level
  primitives only, no `Keypair` knowledge: `scMulAdd`, `geScalarmultBase`,
  `derivePublic(seed): PublicKey`, `signDetached(seed, msg): Signature`.
- **`src/sello/signing.nim`** — types, lifecycle, and backend dispatch.
  Defines `Seed`/`Keypair` (fields private), the constructors, the
  `=destroy` wipe hook, and the `when defined(selloLibsodium)` backend
  import (adapter vs `signer`). The facade re-exports from here and gains
  no conditional logic. Because dispatch and types live here, the pure
  signer is not even compiled under the flag, and both backends share one
  `Keypair` with no duplicate type definitions to drift.
- **`src/sello/private/ct.nim`** — wipe + barrier utilities (below).

**Layering prep (slice 1, behavior-preserving).** RFC 8032 signing must run
`scReduce` over secret-derived values (the nonce hash) and needs
`pointEncode` for R and A — both currently live in `ed25519.nim`, whose
whole identity is "verify-only, never touches a secret". So: move
`scReduce`, `scIsCanonical`, `load3`/`load4`, and `pointEncode` down into
`scalar.nim` (ref10 keeps the `sc25519_*`/`ge_*` families together for the
same reason), with the `sc*` group under `{.push checks: off.}` since it
now sees secret-derived input. `ed25519.nim` imports them back; its
verify-only claim stays literally true, and `signer.nim` builds only on
`field.nim` + `scalar.nim` + nimcrypto SHA-512. Also in the same prep pass:
extract a shared `clampScalar*(var array[32, byte])` (the X25519 clamp
inlined in `ladder` is bit-identical to RFC 8032 keygen clamping — one
audited copy, two callers), delete the dead `SecretKey` alias (exported but
used by nothing), and delete the unused `GePrecomp` scaffold (see next
section).

### Fixed-base scalar mult (`geScalarmultBase`)

Ports ref10 `ge_scalarmult_base` structure: signed radix-16 digits, 32×8
precomputed table, CT table select. Deviations from ref10, stated so the
implementer doesn't rediscover them mid-slice:

- **Table representation: `GeCached` with `z = FeOne`** — not ref10's
  `ge_precomp` (yminusx/yplusx/xy2d). This reuses the existing, verifier-
  tested `geAdd`/`geSub` unmodified; no `ge_madd`/`ge_msub` mixed-addition
  port is needed at all. Cost: one multiply-by-one per addition and ~33%
  more table bytes — irrelevant at 256 entries. Benefit: zero new group
  arithmetic to write or vector-test. (`GePrecomp` is currently declared in
  `scalar.nim` and used by nothing; delete it rather than leave a trap.)
- **Conditional negation of a `GeCached` entry is exactly:**
  `swap(yPlusX, yMinusX)`; `t2d = -t2d`; `z` unchanged. Spelled out because
  sign-flip bugs only manifest on negative digits (half of all nonzero
  digits).
- **CT select contract:** `cmovCached(out, table, digit)` scans all 8
  entries on every call — fixed, secret-independent iteration count, no
  early exit — with selection and negation masks derived arithmetically
  from the secret digit (`feCMove` family), never branched on.
- **Recoding invariants (the historically bug-prone step):** 64 nibbles →
  64 signed digits in [−8, 8] via carry propagation; this terminates in
  exactly 64 digits **iff bit 255 of the scalar is 0**. Precondition:
  `geScalarmultBase` accepts only clamped-shape scalars (bit 254 set,
  bit 255 clear — guaranteed by `clampScalar`). Mandatory test vectors:
  the maximal clamped scalar (top byte `0x7F`, the final-carry boundary),
  RFC seeds, and random clamped scalars — all checked against the existing
  vartime `scalarmult`.

**Base table: derive at compile time — de-risked.** Verified empirically in
the build container (Nim 2.2.10 VM): 250 compile-time point doublings and a
representative `const` `GeCached` table evaluate in ~1 s, byte-exact
against runtime output, with no int64/shift semantics divergence. The real
32×8 table is the same order of magnitude. The checked-in generator
(`tools/gen_basetable.nim`) is a **contingency only** — do not build it up
front. Standing guard (this repo has no CI, so nothing may rely on one): a
test in the normal `nimble test` run asserts every table entry equals the
runtime-computed multiple of B, every time.

### Public API (via `signing.nim`, re-exported by the facade)

```nim
type
  Seed* = array[32, byte]
    ## RFC 8032 private key: 32 uniformly random bytes. Every bit pattern
    ## is a valid seed — there is no decode/rejection path (contrast
    ## PublicKey/Signature). Not libsodium's 64-byte secret key.

  Keypair* = object      # fields deliberately NOT exported
    public: PublicKey
    seed: Seed

func public*(kp: Keypair): PublicKey
func seed*(kp: Keypair): Seed        ## for persistence; caller wipes after
func keypair*(seed: Seed): Keypair   ## deterministic; the ONLY constructor
proc keypair*(): Keypair             ## fresh identity via std/sysrand
func sign*(kp: Keypair; msg: openArray[byte]): Signature
proc wipe*(s: var Seed)              ## volatile wipe for caller-held seeds
```

Contracts the doc comments must state (bar: `pointDecode`'s specificity):

- **Invariant:** `kp.public == derive(kp.seed)`, always. Fields are private
  and `keypair(seed)` is the only constructor, so a mismatched pair is
  unconstructible — which is precisely what lets `sign` use the cached
  `kp.public` in `H(R || A || msg)` without re-deriving A each call.
- **`sign` is deterministic and total.** Same `(kp, msg)` → same signature
  (RFC 8032 EdDSA property; callers may rely on it). It cannot fail for any
  seed/message — unlike `x25519`, whose `Option` exists only because of the
  small-order degenerate input class, which signing structurally lacks.
  Hence `Signature`, not `Option[Signature]`.
- **Key-first argument order** (`kp.sign(msg)`) matches `x25519`'s
  actor-first precedent and reads naturally under UFCS.
- **Lifecycle:** `Keypair` gets a `=destroy` hook that wipes `seed` at
  scope exit (ORC is already the project's memory mode); copies each wipe
  independently. Doc warning: never box key material in `seq`/`ref`
  containers — hold `Keypair` as a stack value.
- **Seed sourcing:** `keypair(seed)` is for import/tests/derivation;
  `keypair()` is the zero-ceremony "give me an identity" path, sourcing
  from `std/sysrand` (OS CSPRNG; stdlib, so the no-FFI-crypto story is
  intact) and raising `OSError` on entropy failure. README example shows
  this path explicitly; never `std/random`.
- **One name:** `keypair`, everywhere. No `keypairFromSeed`.
- **`func` vs `proc` caveat:** the volatile-wipe/emit barriers may not pass
  Nim's `noSideEffect` checker; if so the affected symbols become `proc`
  (or use `{.cast(noSideEffect).}` only where honest). Resolve in slice 7;
  the shapes above don't otherwise change.

`sign` internals (RFC 8032 §5.1.6): expand seed via SHA-512 →
`(a, prefix)`, `clampScalar(a)`; `r = scReduce(SHA-512(prefix ‖ msg))`;
`R = pointEncode(geScalarmultBase(r))`; `k = scReduce(SHA-512(R ‖ A ‖ msg))`;
`S = scMulAdd(k, a, r)`. The seed is re-expanded per call — no persistent
expanded-key API (one obvious API; expansion is cheap next to scalarmult).

### Constant-time discipline (prompt.md toolkit, applied)

- **The secrets are: seed, `a`, `prefix`, `r`, and `r`'s digit recoding.**
  `r` is exactly as catastrophic as `a`: partial leakage of `r` across two
  signatures recovers `a` (`S = r + k·a mod L`). Every rule below applies
  to `r` and its derived forms with no exceptions.
- `{.push checks: off.}` around `signer.nim`'s core (as `x25519.nim` does)
  and around the relocated `sc*` group in `scalar.nim`.
- Secrets only in fixed stack arrays; zero heap allocation in the sign path.
- All secret-indexed selection via arithmetic masking; no secret-dependent
  branches or table indices (see the select contract above).
- **SHA-512 over secret input:** audit nimcrypto's sha512 context type for
  internal heap use (expected stack-only — verify, it's a project-rule
  requirement), and `ct.wipe` the context object after `finish()` at the
  two secret-hashing call sites — it buffers a secret-containing block.
- `src/sello/private/ct.nim`: `wipe` using volatile stores +
  `{.emit: "asm volatile(\"\" ::: \"memory\");".}` barrier; `{.noinline.}`
  on masking helpers so the C compiler can't re-introduce branches.
- **Known defect to fix (slice 7), not generic cleanup:** `x25519.nim`'s
  trailing zero-loop over `e` is an unbarriered dead store — the C compiler
  is licensed to delete it at `-d:release`, and likely does. Replace with
  `ct.wipe` and confirm in the generated code that the stores survive.
- Evidence, not vibes: `tests/ct/` harness (below).

### libsodium adapter (`-d:selloLibsodium`)

- **Dispatch lives in `signing.nim`, not the facade** — the facade stays a
  logic-free re-export, matching the rest of the stack.
- **Backend contract is seed-level** (`derivePublic`, `signDetached`), so
  both backends share the same `Keypair` unchanged; the adapter rebuilds
  libsodium's 64-byte secret key (seed ‖ pk) per call via
  `crypto_sign_seed_keypair`, then `crypto_sign_detached`.
- **`sodium_init()`** is called once, guarded and idempotent, before any
  `crypto_sign_*` call; its tri-state return is checked (< 0 is a hard
  error, never a silent fallthrough).
- **Interop tests — the actual point of a swappable backend:** pure `sign`
  → libsodium `crypto_sign_verify_detached`, and libsodium sign → sello's
  pure `verify`. Bidirectional interop is strictly stronger evidence than
  both backends passing the same fixed vectors separately.
- **Test matrix:** a `nimble testLibsodium` task recompiles and runs the
  full RFC-vector + Wycheproof suite under the flag, plus the interop
  tests. `verify` stays pure-Nim always — it's the part with no asterisks.
- **Linkage:** dynamic against distro `libsodium-devel`; the functions used
  are ancient and stable (any libsodium ≥ 1.0.x) — pin the tested version
  in a comment. Missing library = ordinary linker error; README notes it.
- **Containerfile:** `Containerfile.amox` gains `libsodium-devel`. Network
  availability is session-dependent, not guaranteed — rebuild the image
  early in stage D while it's confirmed available; `nimble test` /
  `nimble ct` need no network afterward.

### Timing harness (`tests/ct/`)

dudect methodology, stated fully so the harness is implementable without
re-reading the paper:

- Two input classes — fixed secret vs. per-sample random secret — with
  samples **randomly interleaved between classes within a single run**.
  Non-negotiable: interleaving is what cancels drift (thermal, frequency
  scaling, cache/branch warmup on the repeated fixed input) that otherwise
  fakes or masks a secret-dependent signal.
- Welch's t-test on the two populations, with dudect's upper-percentile
  cropping; **minimum 10⁶ samples per class** (t grows with n — a threshold
  without a sample floor is meaningless).
- **Both dudect thresholds reported:** |t| > 10 fails the task;
  4.5 < |t| ≤ 10 is a soft warning that must be investigated and written up
  in `docs/ct-results.md`, never silently passed.
- Preflight: pin to one core (`taskset`); attempt the `performance`
  governor (the host currently runs `powersave` — if it can't be changed in
  this sandbox, the results doc says so and carries the extra-variance
  caveat). `rdtsc` is verified working inside the podman container.
- Separate `nimble ct` task, `-d:release`, not part of `nimble test`
  (statistical, environment-sensitive).
- `docs/ct-results.md` names the exact measurement environment (container
  image, host governor, pinning status, no bare-metal run) among its honest
  limits: the harness measures, it cannot prove — the libsodium adapter is
  the escape hatch for consumers who need an audited CT implementation.

## Slices (each one `/tdd`-sized)

Stage A — layering + secret-side math (strictly sequential)
1. **Layering prep** (behavior-preserving): move `scReduce` /
   `scIsCanonical` / `load3` / `load4` / `pointEncode` from `ed25519.nim`
   to `scalar.nim` (sc* group under checks-off); extract `clampScalar*` and
   use it from `x25519.nim`; delete `SecretKey` and `GePrecomp`. Full
   existing suite stays green — that is the test.
2. **`scMulAdd`**: ref10 `sc25519_muladd` port. Vectors: edge cases
   (a, b, c ∈ {0, 1, L−1} and carry-saturating products) plus ≥1000 random
   triples from a checked-in python3 generator script (builtin bigints are
   the independent oracle — no library needed), regenerated
   deterministically from a fixed RNG seed.
3. **Compile-time base table + CT select**: `const` 32×8 `GeCached(z=1)`
   table; `cmovCached` full-scan select + conditional negate as specified;
   `nimble test` assertion that every entry equals the runtime-computed
   multiple of B. (All public-data tests.)
4. **`geScalarmultBase`**: signed radix-16 with the stated clamped-input
   precondition; encoding of [k]B matches vartime `scalarmult(k, B)` for
   RFC seeds, random clamped scalars, and the `0x7F`-top-byte boundary.

Stage B — API + RFC 8032 layer (sequential, after 4)
5. **`signing.nim` types + keygen**: `Seed`/`Keypair` (private fields,
   getters, `=destroy` wipe), `keypair(seed)`, `keypair()` via sysrand,
   `wipe(var Seed)`; `signer.derivePublic`; **all four** RFC 8032 §7.1
   seed→public-key vectors (TEST 1, 2, 3, and the 1023-byte TEST-1024).
6. **`sign`**: `signer.signDetached` + `signing.sign(kp, msg)`; all four
   §7.1 signatures bit-exact — TEST-1024 is the only official multi-block
   SHA-512 vector, exactly where a fresh signer breaks; sign→verify
   roundtrip property; backfill TEST 3 + TEST-1024 into the verify suite;
   facade exports and `sello.nimble` test wiring.

Stage C — hardening + evidence (7 before 8)
7. **Secret hygiene**: `private/ct.nim` (wipe + barrier + noinline);
   replace `x25519.nim`'s dead-store scrub and verify stores survive
   `-d:release`; nimcrypto sha512-context audit + wipe at secret call
   sites; no-alloc audit over signer/x25519; resolve the func/proc
   question; wipe unit test.
8. **`tests/ct/` dudect harness** per spec above; `nimble ct` task;
   `docs/ct-results.md` with named environment and honest limits.

Stage D — adapter + packaging (9 before 10)
9. **libsodium adapter**: `signing.nim` dispatch; `sodium_init` guard;
   bidirectional interop tests; `nimble testLibsodium` task;
   `Containerfile.amox` + image rebuild (early, while network is
   confirmed available).
10. **Packaging**: README (keywords per spec §discoverability, seed-
    sourcing example, flag docs); add LICENSE file + third-party notices
    consolidating the public-domain ref10/orlp attributions; update the
    facade docstring (sign example) and CLAUDE.md (layering + status
    flips); version → 0.2.0.

Done-when per slice: tests green in the container, refactor clean, no slice
starts mid-RED. 1–6 strictly sequential; the pairs (7, 8) and (9, 10) may
interleave with each other after 6, but 7 precedes 8 and 9 precedes 10.

## Risks / open questions for architect rounds

- ~~Nim VM const-eval of the base table~~ — **de-risked empirically** (see
  Design); the generator contingency remains specified but unbuilt.
- dudect in a container on a `powersave` host: measurements will be noisier
  than bare metal. Mitigations (pinning, governor attempt, named
  environment) are specified; a clean pass is evidence, not proof.
- `noSideEffect` vs emit barriers (func/proc) — resolved in slice 7.
- CT in Nim ultimately bottoms out at the C compiler (shared risk with
  careful C, per spec). The harness measures; it cannot prove. Documented
  honestly, plus the libsodium escape hatch.
