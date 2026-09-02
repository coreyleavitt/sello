# RFC-001: ed25519 signing milestone (sign, keygen, CT evidence, adapter)

Status: implemented — (originally: draft) architect rounds 1 and 2 applied
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
  tested and shipped; candidate for a separate, explicitly-scoped RFC. The
  facade re-export carries a one-line comment naming the asymmetry as known
  and deferred, so it reads as a decision, not an oversight.
- Streaming/incremental signing — EdDSA's two-pass construction (r over
  prefix ‖ msg, then k over R ‖ A ‖ msg) structurally requires the whole
  message; `sign` takes a full in-memory buffer. Large-payload callers
  buffer, or hash-then-sign at their protocol layer.
- Key-container formats (PKCS#8/RFC 8410 DER, OpenSSH, JWK OKP) — sello
  speaks raw 32-byte seeds only; extracting a seed from a container is the
  caller's responsibility.
- Batch verification — considered; deferred to a future RFC — random-weight
  batch verify is vartime-tier but has real small-order/cofactor
  subtleties.

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

New homes, chosen so the audit surface stays small and the facade stays
logic-free:

- **`src/sello/private/backend.nim`** — the pure-Nim secret-math backend.
  Seed-level primitives only, no `Keypair` knowledge: `scMulAdd`,
  `geScalarmultBase`, `derivePublic(seed): PublicKey`,
  `signDetached(seed, msg): Signature`. It lives under `private/` because
  these exports necessarily bypass every `Keypair` guarantee (no invariant,
  no auto-wipe) — the same social-contract treatment `ct.nim` gets; the
  module doc-comment opens with a danger warning pointing callers at
  `sello.sign`. The name also removes the draft's `signer`/`signing`
  three-letter near-collision and matches the word the dispatch design
  already used ("backend"). The libsodium adapter is the sibling
  `private/backend_sodium.nim`.
- **`src/sello/signing.nim`** — types, lifecycle, and backend dispatch.
  Defines `Seed`/`Keypair` (fields private), the constructors, the
  `=destroy` wipe hook, and the `when defined(selloLibsodium)` backend
  import (`backend_sodium` vs `backend`). The facade re-exports from here
  and gains no conditional logic. Because dispatch and types live here, the
  pure backend is not even compiled under the flag, and both backends share
  one `Keypair` with no duplicate type definitions to drift.
- **`src/sello/private/ct.nim`** — wipe + barrier utilities (below).

**Layering prep (slice 1, behavior-preserving).** RFC 8032 signing must run
`scReduce` over secret-derived values (the nonce hash) and needs
`pointEncode` for R and A — both currently live in `ed25519.nim`, whose
whole identity is "verify-only, never touches a secret". So: move
`scReduce`, `scIsCanonical`, `load3`/`load4`, and `pointEncode` down into
`scalar.nim` (ref10 keeps the `sc25519_*`/`ge_*` families together for the
same reason), with the `sc*` group under `{.push checks: off.}` since it
now sees secret-derived input. `ed25519.nim` imports them back; its
verify-only claim stays literally true, and `backend.nim` builds only on
`field.nim` + `scalar.nim` + nimcrypto SHA-512. (Verified: none of the
moved symbols is referenced anywhere in `tests/`; `pointDecode` stays put;
no circular-import risk.) Accepted side effect, stated so it is a decision
rather than an accident: verify's calls into the relocated
`sc*`/`pointEncode` now also run checks-off — safe because these functions
index fixed-size arrays at compile-time-constant offsets, not because
verify needs CT.

Also in the same prep pass, three extractions/deletions:

- `clampScalar*(var array[32, byte])` — one audited clamp, two callers
  (X25519's `ladder` inlines the bit-identical RFC 8032 clamp today). It
  goes in **`field.nim`, not `scalar.nim`**: the clamp touches only bytes,
  and `x25519.nim` must remain a `field.nim`-only consumer (the documented
  architecture) — the shared bottom layer is the only home that adds no
  import edge. Note the *clamp* is shared, not the derivation (X25519
  clamps the raw secret directly; ed25519 clamps `SHA-512(seed)[0..31]`).
- `challenge*(R, A: array[32, byte]; msg: openArray[byte])` — the shared
  challenge hash `scReduce(SHA-512(R ‖ A ‖ msg))`, extracted from `verify`
  now and called by `signDetached` later. Same one-audited-copy discipline
  as `clampScalar`, and higher-stakes: two hand-maintained copies of this
  formula is a latent sign/verify self-consistency break with no compiler
  signal. It lives beside `scReduce` in `scalar.nim` (which gains the
  nimcrypto import); it is public-data code — R, A, msg, and k are public
  in both protocols — so no CT constraint follows.
- Delete the dead `SecretKey` alias — **including its re-export in
  `sello.nim`'s facade line, or slice 1 does not compile.** Removing an
  exported symbol is a (pre-1.0) breaking API change; the 0.2.0 changelog
  entry says so plainly. Delete the unused `GePrecomp` scaffold likewise
  (see next section).

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
  from the secret digit (`feCMove` family), never branched on. The output
  is initialized to the identity `GeCached` (`yPlusX = yMinusX = z = 1`,
  `t2d = 0`) before the scan, so digit 0 selects the identity with no
  special case — spelled out for the same reason the sign-flip contract
  is: silent-wrong-answer territory.
- **Recoding invariants (the historically bug-prone step):** 64 nibbles →
  64 signed digits via carry propagation. The digit range is asymmetric:
  positions 0–62 land in **[−8, 7]**; only digit 63 can reach **+8** (a
  mid-position +8 is a carry bug, not valid output — do not document the
  range as a uniform [−8, 8]). Termination in exactly 64 digits requires
  precisely one thing: **bit 255 of the scalar is 0.** That is the whole
  precondition, and it must NOT be stated as "clamped shape": this
  function serves two scalar domains — clamped secret scalars `a`
  (bit 255 clear, bit 254 set) and **reduced nonces `r = scReduce(…) < L`,
  whose top three bits are always clear** (L < 2²⁵³). Bit 254 is *never*
  set on the nonce path, so a clamped-shape assertion would reject every
  real `R = [r]B` computation in `sign` while every clamped-domain test
  passes green.
- **Mandatory test vectors — both domains,** all checked against the
  existing vartime `scalarmult`: clamped — RFC seeds, random clamped
  scalars, and the maximal clamped scalar (top byte `0x7F`, the
  final-carry boundary); r-shaped — random reduced-mod-L scalars and
  values just below L (the bit-252 boundary region). Plus a white-box
  recoding test asserting digits[0..62] ∈ [−8, 7] and digit[63] ∈ [−8, 8]
  over random scalars from both domains — the black-box point comparison
  alone can pass on compensating recoding errors.

**Base table: derive at compile time — de-risked.** Verified empirically in
the build container (Nim 2.2.10 VM): 250 compile-time point doublings and a
representative `const` `GeCached` table evaluate in ~1 s, byte-exact
against runtime output, with no int64/shift semantics divergence (and
re-verified with `{.push checks: off.}` active — the pragma does not alter
VM arithmetic). The real 32×8 table is the same order of magnitude. The checked-in generator
(`tools/gen_basetable.nim`) is a **contingency only** — do not build it up
front. Standing guard (this repo has no CI, so nothing may rely on one): a
test in the normal `nimble test` run asserts every table entry equals the
runtime-computed multiple of B, every time.

### Public API (via `signing.nim`, re-exported by the facade)

```nim
type
  Seed* = distinct array[32, byte]
    ## RFC 8032 private key: 32 uniformly random bytes. Every bit pattern
    ## is a valid seed — there is no decode/rejection path (contrast
    ## PublicKey/Signature). Not libsodium's 64-byte secret key.
    ## distinct + own =destroy wipe; construct via the explicit Seed(bytes).

  Keypair* = object      # fields deliberately NOT exported; move-only
    public: PublicKey
    seed: Seed

func public*(kp: Keypair): PublicKey
func seed*(kp: Keypair): Seed        ## persistence escape hatch; the
                                     ## returned copy auto-wipes at scope exit
func keypair*(seed: Seed): Keypair   ## deterministic; the ONLY constructor
proc keypair*(): Keypair             ## fresh identity via std/sysrand
func sign*(kp: Keypair; msg: openArray[byte]): Signature
func sign*(kp: Keypair; msg: string): Signature   ## zero-copy byte view
proc wipe*(s: var Seed)              ## explicit early wipe (before scope exit)
```

Contracts the doc comments must state (bar: `pointDecode`'s specificity):

- **Invariant:** `kp.public == derive(kp.seed)`, always. Fields are private
  and `keypair(seed)` is the only constructor, so a mismatched pair is
  unconstructible — which is precisely what lets `sign` use the cached
  `kp.public` in `H(R || A || msg)` without re-deriving A each call.
- **`Seed` is `distinct`, not an alias.** `PublicKey` has the same raw
  shape (`array[32, byte]`); with a plain alias the compiler accepts a
  public key anywhere a seed belongs — including transposed fields inside
  `signing.nim` itself — and no `=destroy` can attach to `Seed`
  specifically. `distinct` makes ingestion an explicit, greppable
  `Seed(bytes)` at exactly the point where bytes become secret, and lets
  `Seed` carry its own wipe hook, so the copy `seed()` returns — and any
  caller-held `Seed` — zeroes itself at scope exit instead of relying on a
  doc comment. `wipe` remains for explicit early wiping. Borrow `==` only,
  documented as vartime (tests/tooling). Fallback if 2.2.10 balks at hooks
  on a distinct array: a one-field object, same API.
- **`Keypair` is move-only:** `=copy` is declared `{.error.}` — a second
  live copy of the seed is a compile error, not a hygiene footnote;
  legitimate transfers move (Nim inserts moves at last use). Verified on
  2.2.10/ORC: by-value `kp` parameters are borrows — no copy, no per-call
  destroy; `=destroy` fired exactly once, at scope exit, across repeated
  `sign` calls — so the accessor and `sign` shapes above cost nothing,
  and reassignment (`kp = keypair(other)`) destroys, i.e. wipes, the old
  value first. No custom `=sink` needed.
- **`sign` is deterministic and total.** Same `(kp, msg)` → same signature
  (RFC 8032 EdDSA property; callers may rely on it). It cannot fail for any
  seed/message — unlike `x25519`, whose `Option` exists only because of the
  small-order degenerate input class, which signing structurally lacks.
  Hence `Signature`, not `Option[Signature]`.
- **Key-first argument order** (`kp.sign(msg)`) matches `x25519`'s
  actor-first precedent and reads naturally under UFCS. The `string`
  overload exists because `openArray[byte]` does not accept `string` in
  Nim, and a signing API where `kp.sign("hello")` fails to compile flunks
  the ergonomics bar; it is a zero-copy `toOpenArrayByte` view, and
  `verify` gains the matching additive overload in the same slice.
- **Lifecycle:** `Keypair` and `Seed` both carry `=destroy` wipes (ORC is
  already the project's memory mode). Doc warning: never box key material
  in `seq`/`ref` containers — hold `Keypair` as a stack value.
- **Concurrency:** everything here is a plain value type — `sign` on
  independent `Keypair`s from multiple threads is safe by construction,
  and the docs say so in one sentence. The only shared mutable state in
  the whole feature is the libsodium `sodium_init` guard (below), which
  is specified atomic.
- **Seed sourcing:** `keypair(seed)` is for import/tests/derivation;
  `keypair()` is the zero-ceremony "give me an identity" path. It MUST
  use `std/sysrand`'s in-place `urandom(dest: var openArray[byte]): bool`
  overload, filling the stack `Seed` directly, and raise `OSError` itself
  on `false` — never the `urandom(size)` convenience overload, which
  routes the fresh seed through a heap `seq` (verified in the 2.2.10
  stdlib source), violating the no-`seq`-secrets rule. Doc comment states
  this is the only function in sello's public surface that can raise;
  README shows it uncaught (fail-fast on a broken CSPRNG is correct) and
  never `std/random`.
- **One name:** `keypair`, everywhere. No `keypairFromSeed`.
- ~~`func` vs `proc` caveat~~ — resolved empirically on 2.2.10: `{.emit.}`
  asm barriers compile inside `func` with no effect-checker complaint (the
  analyzer does not look inside emit blocks), and nimcrypto's sha512 API
  is itself `func`. The shapes above stand; slice 8 keeps a one-line
  spot-check only.

`sign` internals (RFC 8032 §5.1.6): expand seed via SHA-512 →
`(a, prefix)`, `clampScalar(a)`; `r = scReduce(SHA-512(prefix ‖ msg))`;
`R = pointEncode(geScalarmultBase(r))` — an r-shaped scalar, see the
recoding precondition; `k = challenge(R, A, msg)` — the same audited
function `verify` calls, never a second hand-written copy of the formula;
`S = scMulAdd(k, a, r)`. The seed is re-expanded per call — no persistent
expanded-key API (one obvious API; expansion is cheap next to scalarmult).

### Constant-time discipline (prompt.md toolkit, applied)

- **The secrets are: seed, `a`, `prefix`, `r`, and `r`'s digit recoding.**
  `r` is exactly as catastrophic as `a`: partial leakage of `r` across two
  signatures recovers `a` (`S = r + k·a mod L`). Every rule below applies
  to `r` and its derived forms with no exceptions.
- `{.push checks: off.}` around `backend.nim`'s core (as `x25519.nim`
  does) and around the relocated `sc*` group in `scalar.nim`.
- Secrets only in fixed stack arrays; zero heap allocation in the sign path.
- All secret-indexed selection via arithmetic masking; no secret-dependent
  branches or table indices (see the select contract above).
- **SHA-512 over secret input:** nimcrypto's `Sha2Context` is verified
  stack-only (read directly: `vendor/nimcrypto/sha2/sha2_common.nim` —
  fixed arrays, scalars, and a proc pointer; no `seq`/`ref`/`string`).
  Still `ct.wipe` the context object after `finish()` at the two
  secret-hashing call sites — it buffers a secret-containing block.
- `src/sello/private/ct.nim`: `wipe` using volatile stores +
  `{.emit: "asm volatile(\"\" ::: \"memory\");".}` barrier; `{.noinline.}`
  on masking helpers so the C compiler can't re-introduce branches.
- **Known defect to fix (slice 8), not generic cleanup:** `x25519.nim`'s
  trailing zero-loop over `e` is an unbarriered dead store — confirmed by
  disassembly at `-d:release`: the loop is entirely absent from the
  emitted machine code. The fix shape is equally confirmed: volatile byte
  stores plus the memory barrier survive as literal store instructions.
  `ct.nim` standardizes exactly that shape; the slice re-checks the
  generated code after integration.
- Evidence, not vibes: `tests/ct/` harness (below).

### libsodium adapter (`-d:selloLibsodium`)

- **Dispatch lives in `signing.nim`, not the facade** — the facade stays a
  logic-free re-export, matching the rest of the stack.
- **Backend contract is seed-level** (`derivePublic`, `signDetached`), so
  both backends share the same `Keypair` unchanged; the adapter rebuilds
  libsodium's 64-byte secret key (seed ‖ pk) per call via
  `crypto_sign_seed_keypair`, then `crypto_sign_detached`.
- **`sodium_init()`** is called once before any `crypto_sign_*` call; its
  tri-state return is checked (< 0 is a hard error, never a silent
  fallthrough). The once-guard is an atomic CAS (`std/atomics`), not a
  plain check-then-set flag — the latter is a data race under
  `--threads:on`, and this guard is the feature's only shared mutable
  state.
- **Interop tests — the actual point of a swappable backend:** pure `sign`
  → libsodium `crypto_sign_verify_detached`, and libsodium sign → sello's
  pure `verify`. Bidirectional interop is strictly stronger evidence than
  both backends passing the same fixed vectors separately.
- **Test matrix:** a `nimble testLibsodium` task recompiles and runs the
  full RFC-vector + Wycheproof suite under the flag, plus the interop
  tests. The unit-test file list is factored into one shared helper in
  `sello.nimble`, consumed by both `test` and `testLibsodium`
  (parameterized by extra `-d:` defines) — two hand-maintained lists
  would silently drift and narrow the libsodium matrix. `verify` stays
  pure-Nim always — it's the part with no asterisks.
- **Linkage:** dynamic against distro `libsodium-devel`; the functions used
  are ancient and stable (any libsodium ≥ 1.0.x) — pin the tested version
  in a comment. Missing library = ordinary linker error; README notes it.
- **Container:** `Containerfile.amox` is amoxtli's sandbox image, not
  sello build infrastructure — its package list (rust/go/node/openssl) is
  unrelated to this library, and the documented build runs the base
  `ghcr.io/coreyleavitt/nim:2.2.10` image directly. Do not bolt
  `libsodium-devel` onto a foreign image: slice 10 adds a minimal
  sello-owned `Containerfile` (`FROM ghcr.io/coreyleavitt/nim:2.2.10`,
  add `libsodium-devel`) used only for `nimble testLibsodium`;
  `Containerfile.amox` is left untouched. Build it early while network is
  confirmed available; `nimble test` / `nimble ct` need no network and no
  libsodium afterward.

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
   to `scalar.nim` (sc* group under checks-off); extract `challenge` into
   `scalar.nim` and refactor `verify` to call it; extract `clampScalar*`
   into `field.nim` and use it from `x25519.nim`; delete `SecretKey`
   (including the facade export line) and `GePrecomp`. Full existing suite
   stays green — that is the test.
2. **`scMulAdd`**: ref10 `sc25519_muladd` port. Vectors: all 27 joint
   combinations of (a, b, c) ∈ {0, 1, L−1}³ — (L−1, L−1, L−1) is the
   carry-saturation worst case, (1, 1, L−1) isolates the additive carry —
   plus ≥1000 random triples from a checked-in python3 generator script
   (builtin bigints are the independent oracle — no library needed),
   regenerated deterministically from a fixed RNG seed.
3. **Compile-time base table + CT select**: `const` 32×8 `GeCached(z=1)`
   table; `cmovCached` full-scan select (identity-initialized output) +
   conditional negate as specified; `nimble test` assertion that every
   entry equals the runtime-computed multiple of B. (All public-data
   tests.)
4. **`geScalarmultBase`**: signed radix-16 with the bit-255-clear
   precondition; encoding of [k]B matches vartime `scalarmult(k, B)` over
   both scalar domains (clamped incl. the `0x7F` boundary; r-shaped incl.
   just-below-L), plus the white-box digit-range test.

Stage B — API + RFC 8032 layer (sequential, after 4)
5. **`signing.nim` types + keygen**: `Seed` (distinct, `=destroy` wipe;
   fallback one-field object if distinct hooks balk), `Keypair` (private
   fields, getters, `=destroy`, `=copy` `{.error.}`), `keypair(seed)`,
   `keypair()` via in-place `urandom` + explicit `OSError`,
   `wipe(var Seed)`; `backend.derivePublic`; **all four** RFC 8032 §7.1
   seed→public-key vectors (TEST 1, 2, 3, and the 1023-byte TEST-1024).
6. **`sign` core**: `backend.signDetached` (via shared `challenge`) +
   `signing.sign(kp, msg)`; TEST 1–3 signatures bit-exact; sign→verify
   roundtrip on those vectors.
7. **`sign` completion**: TEST-1024 bit-exact — the only official
   multi-block SHA-512 vector, exactly where a fresh signer breaks.
   Source the 1023-byte message by scripted extraction from a pasted copy
   of RFC 8032 §7.1, never hand-retyped; assert length 1023 and endpoint
   bytes as a transcription self-check. Backfill TEST 3 + TEST-1024 into
   the verify suite; `string` overloads for `sign` and `verify`; facade
   exports; `sello.nimble` wiring via the shared file-list helper.

Stage C — hardening + evidence (8 before 9)
8. **Secret hygiene**: `private/ct.nim` (wipe + barrier + noinline — the
   disassembly-confirmed volatile-store shape); replace `x25519.nim`'s
   dead-store scrub and re-verify stores survive `-d:release`; sha512
   context wipe at the two secret call sites; no-alloc audit over
   backend/x25519; func/proc spot-check (expected no-op); wipe tests —
   direct `wipe(var Seed)` test plus best-effort destructor smoke tests
   (scope exit and reassignment, raw-memory re-read, explicitly labeled
   best-effort under a managed allocator).
9. **`tests/ct/` dudect harness** per spec above; `nimble ct` task;
   `docs/ct-results.md` with named environment and honest limits.

Stage D — adapter + packaging (10 before 11)
10. **libsodium adapter**: `private/backend_sodium.nim` + `signing.nim`
    dispatch; atomic `sodium_init` guard; bidirectional interop tests;
    `nimble testLibsodium` task; sello-owned `Containerfile` + image
    build (early, while network is confirmed available).
11. **Packaging**: README (keywords per spec §discoverability, seed-
    sourcing example shown fail-fast, string-message note, flag docs);
    add LICENSE file + third-party notices consolidating the
    public-domain ref10/orlp attributions; `CHANGELOG.md` (0.2.0: signing
    surface added, `SecretKey` removed — breaking); update the facade
    docstring (sign example + the one-line argument-order note) and
    CLAUDE.md (layering + status flips); version → 0.2.0.

Done-when per slice: tests green in the container, refactor clean, no slice
starts mid-RED. 1–7 strictly sequential; the pairs (8, 9) and (10, 11) may
interleave with each other after 7, but 8 precedes 9 and 10 precedes 11.

## Risks / open questions for architect rounds

- ~~Nim VM const-eval of the base table~~ — **de-risked empirically**
  (round 1); re-verified under `{.push checks: off.}` in round 2. The
  generator contingency remains specified but unbuilt.
- ~~`noSideEffect` vs emit barriers (func/proc)~~ — **de-risked
  empirically** (round 2): emit-in-func compiles clean, nimcrypto's API is
  itself `func`. Slice 8 spot-checks only.
- ~~`=destroy`/copy semantics under ORC~~ — **de-risked empirically**
  (round 2): hooks fire at scope exit and on reassignment; by-value
  parameters are borrows, not copy-in/destroy-out. Residual: hooks on a
  `distinct` array type specifically (slice 5 carries the one-field-object
  fallback).
- dudect in a container on a `powersave` host: measurements will be noisier
  than bare metal. Mitigations (pinning, governor attempt, named
  environment) are specified; a clean pass is evidence, not proof.
- CT in Nim ultimately bottoms out at the C compiler (shared risk with
  careful C, per spec). The harness measures; it cannot prove. Documented
  honestly, plus the libsodium escape hatch.
