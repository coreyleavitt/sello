# RFC-008: performance and silicon — a verified 64-bit backend, published benchmarks, data-independent-timing modes

Status: DRAFT (stage 1 — not yet through architect review)
Depends on: RFC-005 (the evidence battery every backend must pass),
RFC-007 (desirable, not required: the audit certifies the new codegen;
the DSL is not a dependency since this RFC touches field arithmetic, not
the select kernels)

## Why

sello ships only the ref10 32-bit radix-2^25.5 field core. Every serious
peer (libsodium, curve25519-dalek, Go, BoringSSL) carries a 64-bit
radix-2^51 backend; on x86-64 we are plausibly 2-4x slower on sign and
verify, and we have never published a number — which is itself a claims
gap for a project whose whole identity is evidence over authority. The
32-bit core stays: it is the portability story (i386 and s390x legs run
it in CI) and, once two backends exist, each is a standing differential
oracle for the other — the libsodium-interop trick turned inward.

Separately, "constant time" on modern cores is no longer only branches
and addresses: data-OPERAND-dependent timing exists, and the documented
mitigations are explicit CPU modes — ARM's DIT bit, Intel's DOITM.
Almost no library sets them; a library with a dudect harness and (soon)
a quiet timing box is unusually well placed to ship them AND measure
whether they matter.

## Load-bearing property

A 64-bit field backend whose functional correctness is inherited from a
verified generator (fiat-crypto's proved arithmetic, transliterated with
the transliteration differentially checked), producing BIT-IDENTICAL
results to the 32-bit core across the entire existing vector corpus
(RFC 8032/7748/9496, Wycheproof, CAVP, the property suites), passing the
ENTIRE existing evidence battery (dudect, taint both compilers, disasm,
mutation, coverage, symex where applicable), and MEASURABLY faster on
x86-64 — the measurement published. Slice 1's tracer: one fiat-derived
2^51 `feMul`/`feCarry` wired behind `-d:sello64` with one RFC 7748 KAT
passing end-to-end through the real `x25519` entry point.

## Part A — the backend

- **Source of truth: fiat-crypto's generated curve25519-64 arithmetic**
  (functional correctness is a Coq theorem about the generator's
  output). Decision to record in-slice: transliterate fiat's C output
  into Nim (keeping the proof lineage documented, with byte-exact
  differential tests against the fiat C compiled directly as the
  transliteration check) vs. `{.compile.}`-ing fiat's C (rejected
  default: reintroduces a C TU into the no-FFI core; revisit only if
  transliteration proves error-prone — the differential harness decides,
  not taste).
- `Fe` becomes backend-parametric (5x uint64 limbs vs 10x int32) behind
  `-d:sello64`; the public API and every module above `field.nim` is
  untouched — the layering earns its keep here.
- **CryptOpt-style superoptimized asm is explicitly deferred** (a later
  slice at most, likely RFC-N+1): the verified-transliteration step must
  exist and be trusted first.
- Default-flip criterion recorded now: 64-bit becomes the default only
  after (i) full battery green on both compilers, (ii) one full release
  cycle as opt-in, (iii) the benchmark delta published. Until then
  `-d:sello64` is opt-in and the 32-bit core remains the shipped
  default.

## Part B — benchmarks as claims

`tests/bench/` + `scripts/bench.sh`: sign, verify, keygen, x25519,
ristretto scalarmult; sello-32 vs sello-64 vs libsodium (the adapter and
its differential suite already link it — the oracle doubles as the
yardstick). Methodology recorded (cycle counts, median-of-N, pinned
image, the ct.sh environment-banner discipline reused); results
published in `docs/bench-results.md` with the same honesty register as
`docs/ct-results.md` (shared-host caveats until the quiet box; refreshed
per release, staleness = a dated header, not a canary). README gets
numbers WITH the caveats, or no numbers — never numbers without.

## Part C — data-independent-timing modes

`withDataIndependentTiming` scopes entered by the secret-path entry
points: set/restore ARM DIT (aarch64, incl. Apple silicon), document the
DOITM story honestly (an MSR, generally kernel-gated — likely
"documented, not settable from userspace" is the finding; record what is
actually possible rather than promising), no-op elsewhere with the
residual disclosed in README's CT-scope paragraph. The timing box, when
live (RFC-005 slices 27-29), runs a dudect A/B with the mode on/off —
opportunistic, not a dependency.

## Slices (sketch)

1. Tracer: fiat-derived 2^51 mul/carry behind `-d:sello64`, one x25519
   KAT green end-to-end through the facade.
2. Full field surface on the 64-bit backend; bit-identical corpus run;
   the transliteration differential harness (vs fiat's own C).
3. Evidence integration: dudect/taint/disasm/mutation/coverage over the
   new backend (a second set of disasm baselines; the register's cells
   grow backend qualifiers — design recorded in-slice).
4. CI legs: `unit/property-linux-amd64-gcc-64` (+clang) required checks.
5. Benchmark harness + first published results (32 vs 64 vs libsodium).
6. DIT scope + aarch64 leg verification; DOITM finding recorded.
7. Close-out: default-flip decision explicitly NOT taken (recorded gate
   criteria), claims audit.

## Risks / non-goals

- The battery cost doubles per backend — slice 3 must measure and may
  scope some instruments to the default backend with recorded rationale.
- Non-goals: CryptOpt asm, AVX2/batch throughput work, changing the
  default in this RFC, WASM (RFC-009's verify-only tier).
