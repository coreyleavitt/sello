# RFC-007: CT certification — relational binary verification + a secrecy-typed kernel DSL

Status: DRAFT (stage 1 — not yet through architect review)
Author: drafted from the 2026-09-01/02 design discussion
Depends on: RFC-005 (validation infrastructure — the disasm resolver, the
secret-target register, the taint harness, the evidence culture this RFC
builds on), fix-slice 22a (the clang finding this RFC exists to answer)

## Why (the problem, stated from our own incident data)

RFC-005 closed every constant-time gap a source-distributed library can
close by *pinning and watching*: pinned toolchains, a taint harness, a
disassembly gate with per-backend baselines, a toolchain canary. Its
honest residual is disclosed in README's CT-scope paragraph: **the
instruments bind to the CI-pinned toolchains, and a consumer of a
source-distributed library compiles with a toolchain we never saw.**

The residual is not hypothetical. The taint harness's first day on a
clang leg (slice 22) found that clang compiles the barrier-free masked
select in `feCMove`/`feCSwap`/`cmovCached` into a literal secret-dependent
branch (`test %edx,%edx; je` — verified by objdump, 4348 memcheck errors).
The source was grammatically correct CT algebra; the defect was injected
by compilation. Fix-slice 22a's value barrier closes it for the compilers
we can see. Nothing closes it for the compilers we cannot.

Across RFC-001..006 and every RFC-005 instrument, this is the **only**
genuine CT defect ever found in sello — and it was compiler-introduced,
not source-introduced. That asymmetry drives this RFC's design: the
authoring side (the `SecretScalar` type gate, review, the instruments)
has held; the compilation side is where the one real hit landed.

Two rejected framings, recorded:
- **Shipping prebuilt binaries** freezes a toolchain instead of checking
  one, converts sello into a worse-trusted libsodium, and inherits the
  reproducible-build problem our own pin file records as infeasible
  ("rebuild and compare digests is explicitly infeasible", slice 7).
- **Pinning harder** (more canaries, more baselines) scales watching, not
  trust; the consumer's compiler remains unwatched by construction.

The organizing idea instead: **treat every compiler — ours and the
consumer's — as an untrusted component whose output is checked.** The
check travels; the binary does not.

## Load-bearing property and definition of done

**The load-bearing property:** for a compiled artifact containing
sello's secret-path roots — including one built by a consumer with a
toolchain this project has never seen — a mechanical check produces a
verdict on the RELATIONAL constant-time property of that artifact: two
executions with equal public inputs and differing secrets have identical
control-flow and memory-address traces through every checked root. A
planted secret-dependent branch (the fix-slice 22a defect class,
reintroduced as a fixture) is reported with a concrete location; the
current fixed code passes.

This is leg 3 of the design discussion. Leg 1 (the DSL) exists to shrink
and structure the surface leg 3 must verify, and to make secret misuse
unrepresentable at authoring time — it is load-bearing for
maintainability and for the asm-emission path, but the property above is
what the RFC lives or dies on, so its producer is slice 1.

**Definition-of-done dichotomy (inherited from RFC-005 verbatim):** every
mechanism here is either (a) a required/scheduled check with a
demonstrated red through the real entry point, or (b) a documented
manual ritual with a named freshness/liveness control. A verifier that
has never produced a red on a real planted defect has no verdict
authority. The 22a defect class is this RFC's canonical red: a build
variant reintroducing the pre-barrier masked select under clang MUST be
reported by the audit, on a real run, before any green is claimed.

## Part A — `sello-audit`: relational verification of binaries (leg 3)

### A1. Tool decision — verify-first spike, before any harness exists

The property is relational (self-composition: two copies, equal public
inputs, symbolic secrets, assert equal branch/address traces). Candidate
engines, evaluated in slice 1 against the REAL `feCMove` lifted from a
real `-d:release` binary:

- **BINSEC/Rel** (primary candidate): purpose-built relational symbolic
  execution for constant-time verification of binaries; the closest
  published fit to this exact property. OCaml; availability in the
  sello-dev image to be established (a zypper/opam question — a
  Containerfile addition means a sello-dev repin, the slice-19 ritual).
- **angr** (fallback candidate): python, general-purpose lifting +
  symbolic execution; self-composition assembled by hand. More plumbing,
  broader platform support, easier packaging for consumers (pip).
- **A bespoke lifter over proptest/nim-z3**: REJECTED up front. The
  existing symex walker carries four documented limitations on far
  simpler queries (`symex_recode`/`symex_mask`/`symex_equal`'s own module
  docs); building binary lifting on it is a research project inside a
  research project.

**Go/no-go criterion (two-sided, the taint-slice precedent):** GO
requires (i) the engine proves the relational property for the current
`feCMove` (gcc and clang release builds) with zero counterexamples, AND
(ii) the same engine, run on a build variant with the pre-22a barrier
removed under clang, reports a counterexample resolving to the
synthesized branch. Either half failing for BOTH engines activates the
recorded degraded mode (A5) — stated now, not discovered later.

**Trusted-base honesty clause:** the lifter/engine joins the trusted
computing base. This is disclosed wherever the audit's claim is made
(README, the tool's own output header): the audit converts "trust every
consumer compiler" into "trust one open, published verification engine" —
a reduction, not an elimination. The engine's version is pinned and
recorded per the standing pin register.

### A2. Target inventory and tiering — driven by the A7 register

The verification targets are the secret-path roots the A7 register
(`tests/registers/secret_targets.nim`) already enumerates and the disasm
gate already resolves (`disasmRoots()`, the `{.noinline.}` set: the three
select kernels + `signDetached`, `derivePublic`, `ladder`,
`geScalarmultBase`, `geScalarmultCT`, `ristrettoEncode`, `` `==` ``,
`feSqrtRatioM1`, `compress`). The register grows an **audit column**
(`direct`/`coveredBy`/`exempt`, the established cell vocabulary) and the
audit asserts its column exactly as dudect/taint/disasm assert theirs —
the fourth instrument on the same audited fact-set, closing its own
silent-miss mode on day one.

**Tier A (straight-line roots):** `feCMove`, `feCSwap`, `cmovCached`,
`feSqrtRatioM1`, `` ristretto.`==` ``, `ristrettoEncode` — no loops or
public-constant-bound loops only; full relational proof expected.
**Tier B (loopy roots):** `ladder` (255 iterations), `compress` (80
rounds), `geScalarmultBase`/`geScalarmultCT` (64/256 steps),
`signDetached`/`derivePublic` (composites) — bounded unrolling with
public constant bounds is semantically clean but may hit solver walls
(the `symex_reduce` full-chain precedent: attempted, resource wall,
gated off, disclosed). Tier B lands per-root, each with its own
proved-or-degraded verdict recorded; a Tier-B root that cannot complete
falls back to A5's scan mode FOR THAT ROOT, in the register's audit
column as an `exempt(rationale)` citing the attempt — never silently.

**Preconditions per root are data, not prose:** the register entry
carries the public-input preconditions the proof assumes (e.g.
`geScalarmultBase`'s bit-255-clear), so the audit's claim scope is
mechanically stated.

### A3. The consumer contract

`sello-audit <binary>` (a script + the engine, packaged so a consumer
runs it against THEIR build):
1. Resolve sello's root symbols in the given binary — the RFC-005 slice-23
   resolver already handles Nim 2.x mangling and `-O3` clone suffixes;
   it is generalized from "our nimcache" to "a binary + the sello source
   tree the consumer already has" (the source-relocate step exists).
2. Run the relational check per root, Tier A always, Tier B where the
   engine completes within a per-root budget.
3. Emit a verdict table (per root: PROVED / COUNTEREXAMPLE(location) /
   SKIPPED(reason)) plus a machine-readable certificate (root, binary
   hash, engine version, verdict) — the proof-carrying-build artifact,
   suitable for a consumer's own evidence records.

Platform scope v1: linux x86-64 and aarch64 ELF, disclosed. (Windows/
macOS object formats are a lifting-frontend question deferred to a
future RFC; the README claim is scoped in as many words.)

### A4. CI integration — our own builds go first

Before any consumer runs it, WE run it: required checks
`audit-linux-amd64-gcc` / `audit-linux-amd64-clang` on the sello-dev
image, over the same binaries the disasm gate profiles. Relationship to
the existing disasm gate, decided now: the mnemonic-baseline gate STAYS
(it is fast, catches benign-looking drift the relational check would
prove safe, and its per-backend baselines double as the canary's rolling
substrate); the audit is the deeper, slower verdict. If experience shows
full subsumption, retiring the disasm gate is a later, separate decision
through the check-rename two-step — not this RFC's call.

**Permanent negative fixture:** a `-d:selloAuditPlantedBranch` build
variant reintroducing the pre-22a select (the exact clang defect) is
asserted COUNTEREXAMPLE on every audit run — the 22a incident as a
standing regression test, the `target_planted_leak` pattern.

### A5. Degraded mode (recorded now)

If the spike NO-GOs, or for Tier-B roots that hit walls: the
**toolchain-independent branch-scan mode** — the disasm resolver +
objdump, asserting the structural property "zero conditional branches in
Tier-A roots; branch count == public-loop count in Tier-B roots" with no
baseline required. Strictly weaker than the relational proof (blind to
secret-indexed addressing and to cmov), stated as such everywhere it
substitutes. This mode ships inside `sello-audit` regardless (it is the
zero-dependency fallback when a consumer cannot install the engine).

## Part B — the CT kernel DSL (leg 1)

### B1. What it is

`src/sello/private/ctdsl.nim`: a macro (`ctKernel`) defining an embedded
DSL in which the CT selection kernels are written once and lowered to
multiple backends. Inside a kernel: values are `Secret[T]` or
`Public[T]`; the admitted operations on `Secret` are a whitelist (xor,
and, or, not, add/sub, shifts by `Public` amounts, `select(mask, a, b)`,
widening/narrowing); `if`/`case` on a secret, indexing by a secret, and
comparison yielding a bare `bool` are NOT REPRESENTABLE — rejected at
macro expansion with a diagnostic naming the offending node. The
property "no secret-dependent branch or index exists in this kernel's
source" becomes a grammar theorem, not a review outcome. This
generalizes the codebase's signature move (`SecretScalar`'s type gate,
the unexported taint shim binding): misuse is a compile error.

Negative fixtures (the `reject_*` subprocess-`nim c` pattern) pin every
rejection class.

### B2. Backends, and where the guarantee actually lives

1. **Portable backend (default):** emits exactly the barrier'd masked
   arithmetic shipped today — the migration goal for this backend is
   BYTE-IDENTICAL generated C for the three select kernels, so the
   evidence refresh for the migration slice is an equality argument, not
   a new battery. Honesty clause: this backend's CT still terminates at
   the compiler; it is certified by Part A, not by the types.
2. **Asm backend (`-d:selloAsmKernels`, x86-64 + aarch64):** the DSL
   emits the kernels as inline assembly — the compiler has zero codegen
   freedom over the selection. The emission templates are a hand-written
   TRUSTED COMPONENT (we are not building Jasmin's preservation proof);
   what certifies them is Part A's audit running on the asm-backend
   binary — the composition that makes the two legs one design. The
   portable backend remains the default and the only path on other
   architectures; the register's audit column records which backend each
   CI leg certifies.
3. **Obligation export:** the kernel AST exports its semantics as SMT
   terms for the existing proptest/nim-z3 harness, replacing
   `symex_mask.nim`-style hand-transliterations (whose re-encoding gap
   is today closed by concrete cross-checks) with obligations derived
   from the single source of truth. The existing files stay as
   cross-checks, per the belt-and-suspenders register.

### B3. Migration scope — kernels only, honestly

v1 migrates exactly the mask-select kernels (`feCMove`, `feCSwap`,
`cmovCached`'s select core). NOT a general information-flow system for
the library: the field arithmetic, ladder, and hash cores stay ordinary
Nim under the existing instruments (their risk is arithmetic, which the
DSL does not address, and their CT is certified by Part A). Widening the
DSL's coverage is future work contingent on the 64-bit backend RFC.
Every migration touch of `src/sello/` follows the standing
shipped-codegen rules: mutant re-sync, coverage repin, evidence refresh
(cheap where byte-identical emission is proved, full where not).

## Part C — composition (why this is one RFC, not two)

Leg 1 without leg 3 rearranges the residual: its types stop at the
compiler, and its asm backend introduces a new unproved trusted
component. Leg 3 without leg 1 verifies a larger, less structured
surface and leaves authoring discipline manual. Together: the DSL
shrinks the audit's Tier-A surface to grammatically-CT kernels, the
audit certifies both DSL backends AND every consumer build, and the
register binds all of it to the same fact-set the other three
instruments already assert against.

## Slices

Ordering rule inherited from RFC-005: the load-bearing property's
producer is slice 1; infra slices verify by running the thing; every
gate slice's DoD includes its red demonstration.

1. **Spike: the relational verdict, end-to-end (GO/NO-GO).** BINSEC/Rel
   then angr, against real gcc+clang `-d:release` binaries: prove
   current `feCMove`, counterexample the pre-22a variant (both halves of
   A1's criterion). Engine choice, versions, image implications (repin?)
   recorded. NO-GO on both engines → the RFC re-scopes around A5 and
   returns to review — an escalation, not a silent fallback.
2. **Audit harness, Tier A.** Resolver generalization, the six Tier-A
   roots, per-root preconditions from the register, the planted-branch
   fixture red. Local + both compilers.
3. **Register audit column + CI gates.** `audit-linux-amd64-{gcc,clang}`
   required checks (check-adding flow), the column asserted
   union-across-battery, red demo on a real run.
4. **`sello-audit` consumer packaging.** The CLI contract (A3), the
   certificate format, the scan-mode fallback bundled, docs + README
   (the CT-scope paragraph REWRITTEN from disclosure to check — this is
   the RFC's user-visible payoff), validation-map rows.
5. **Tier B, per root.** Bounded unrolling budgets; each root lands
   proved or recorded-degraded with the attempt's evidence (the
   `symex_reduce` precedent for honest walls).
6. **DSL core.** `ctKernel`, `Secret`/`Public`, the whitelist, rejection
   diagnostics, negative fixtures, obligation export skeleton. No
   shipped code changes yet.
7. **Kernel migration, portable backend.** The three selects through the
   DSL with byte-identical emission proved (or the delta argued + full
   refresh); mutants/coverage re-synced.
8. **Obligation export replaces hand-encodings.** Derived SMT obligations
   discharge in `scripts/bmc.sh`; `symex_mask.nim` demoted to
   cross-check.
9. **Asm backend.** x86-64 + aarch64 emission behind `-d:selloAsmKernels`,
   certified by the audit gates on an asm-backend CI leg; dudect A/B of
   the two backends on the timing box (if live) recorded.
10. **Close-out.** Claims audit against the dichotomy, CLAUDE.md/docs
    sweep, the register's four instrument columns cross-checked.

Slices 1–5 (Part A) and 6–8 (Part B core) are independent after slice 1;
9 depends on both 6–8 and 2–3; 4 can land any time after 2.

## Ordering & risks

- **Engine availability/packaging** is the biggest unknown (OCaml
  toolchain in the image; consumer install ergonomics) — squarely why
  slice 1 is a spike with a two-sided criterion and a named fallback.
- **Solver walls on Tier B** are expected, not exceptional; the per-root
  proved-or-degraded design absorbs them without blocking the RFC.
- **Evidence refresh cost** for slice 7 is bounded by the byte-identical
  emission goal; slice 9 is an honest full-refresh event (new codegen by
  design) and is sequenced late for that reason.
- **The lifter joins the TCB** — repeated here because it must appear in
  every claim the audit makes; overclaiming "proved" without naming the
  engine is the exact crowned-property violation RFC-005 round 2 killed
  elsewhere.
- The timing box (RFC-005 slices 27–29) is NOT a dependency; slice 9's
  dudect A/B is opportunistic.

## Non-goals

- Jasmin/FaCT/CompCert-CT adoption (a compiler-pipeline migration, not a
  library feature; recorded as the field's long-term answer).
- A general information-flow type system over the whole library (B3).
- The 64-bit/fiat-generated field backend and hardware DIT/DOITM modes —
  legs 2 and 4 of the design discussion, deliberately split into a
  future RFC-008 so this RFC stays one property deep.
- Windows/macOS binary formats in `sello-audit` v1 (scoped, disclosed).
- Proving the asm emission templates (Jasmin's theorem) — v1 certifies
  their OUTPUT via the audit instead, stated in as many words.
