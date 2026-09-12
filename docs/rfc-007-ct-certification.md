+++
type    = "rfc"
id      = "007"
title   = "CT certification — relational binary verification + a secrecy-typed kernel DSL"
state   = "draft"
wiring   = "unproven"
stage   = "architecture"
round   = 1
size    = "xl"
value   = "high"
profile = "rfc-flow@3"
blocked_by = ["005"]

[[item]]
id    = "part-b-shape"
title = "Part B's shape (see the FORK marker at the head of Part B)"
state = "open"
owner = "corey"
+++

# RFC-007: CT certification — relational binary verification + a secrecy-typed kernel DSL

Status: DRAFT (stage 1 — architect round 1 applied 2026-09-09; one open
fork outstanding: Part B's shape, see the FORK marker at the head of
Part B)
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

**Prior art (round-1 addition):** Ledger's cargo-checkct is the existing
consumer-facing product with this exact shape — Binsec's relational CT
check packaged so a downstream project runs it against its own build.
Its existence validates the approach; its contract calibrates ours: it
does NOT audit arbitrary application binaries — it builds a dedicated
per-entry-point harness binary with the consumer's toolchain and
verifies that. A3's two-mode contract adopts the same honesty.

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

**The property's distinguishing clause — "a toolchain we never saw" —
must itself be demonstrated, not implied (round-1 liveness finding):**
every audit run in slices 1–3 uses the pinned gcc 16.1.1/clang 22.1.8.
Two mechanisms, both precedented, are therefore part of this RFC's own
DoD (slice 4): the toolchain canary's `newest-gcc`/`newest-clang` legs
run the audit against genuinely-unpinned rolling compilers (the
slice-23 disasm-canary extension pattern, alert-only), and a
consumer-route run builds sello the way `release-consumer` does (nimble
install + a bare `nim c`, no milpa, no nim.cfg) and audits THAT binary.
Until at least one of these has run red-capable for real, the README
rewrite (slice 4) would be an unchecked claim — the exact violation
RFC-005's go-public rule exists to prevent.

This is leg 3 of the design discussion. Leg 1 (the DSL) exists to
structure the kernel-authoring surface and enable the asm-emission path
— it is load-bearing for maintainability, but the property above is
what the RFC lives or dies on, so its producer is slice 1.

**Definition-of-done dichotomy (inherited from RFC-005 verbatim):** every
mechanism here is either (a) a required/scheduled check with a
demonstrated red through the real entry point, or (b) a documented
manual ritual with a named freshness/liveness control. A verifier that
has never produced a red on a real planted defect has no verdict
authority. The 22a defect class is this RFC's canonical red: a build
variant reintroducing the pre-barrier masked select under clang MUST be
reported by the audit, on a real run, before any green is claimed.

## Leakage model and claim scope (stated once, cited everywhere)

The verified property is the standard binary-level CT discipline:
**branch-trace + memory-address-trace equality under secret variation.**
That is a leakage *model*, not "constant time" in the physical sense,
and the certificate will be read as the latter unless the scope rides
with it. The following enumeration appears VERBATIM in the certificate
format (A3) and the README CT-scope rewrite (slice 4) — the same
treatment the trusted-base clause already gets:

- **Covered:** secret-dependent control flow (branches, secret-bounded
  loops); secret-dependent memory addressing (table lookups, indexing)
  — the two classes every instrument in this codebase targets, and the
  class the one real incident (22a) belonged to.
- **Not covered — operand-dependent instruction timing:** variable-
  latency multiply/divide on secret operands. The relational trace
  property is blind to it by construction; dudect alone can see it on
  real silicon, and hardware DIT/DOITM modes (RFC-008) are the field's
  systematic answer. The scan pass additionally *asserts* no `div`/
  `idiv` appears in any root's secret dataflow (sello emits none on
  secrets — asserted, not assumed). cargo-checkct records the identical
  assumption in as many words.
- **Not covered:** speculative-execution leakage (Spectre-class),
  intra-cache-line access granularity, physical side channels.
- **CMOV — a recorded, deliberate divergence from the taint gate
  (round-1 depth finding):** RFC-005's CMOV policy is stricter than the
  baseline CT policy — memcheck fails a secret-conditioned CMOV even
  though CMOV is constant-time on the pinned targets. The relational
  property PROVES a cmov-on-secret binary clean (neither trace is
  perturbed), so a consumer compiler that lowers the select to `cmov`
  (the canonical lowering; on aarch64, `csel` is the DEFAULT lowering)
  earns a PROVED verdict for a construction our own required checks
  reject. Handling: the audit report carries an ADVISORY column
  flagging every `cmovcc`/`csel`-family instruction whose
  flags-producer lies in the secret dataflow slice — never a verdict,
  but never silent. The divergence is stated here so it is a decision,
  not an omission.

**The four-instrument frame** (also the honest answer to "does the
audit subsume the disasm gate," A4): dudect measures the *effect* —
time, on real silicon; the other three examine the *cause* at
increasing semantic depth. Disasm gate: the binary's syntax, all paths,
shallow (a branch-profile change detector). Taint harness: one executed
path's semantics, exact, dynamic. Audit: all paths' semantics,
relational, symbolic. Each instrument's residual is named by the frame:
operand timing is dudect's alone; untaken paths are invisible to taint;
semantic equivalence under syntactic drift is invisible to disasm; the
audit's residual is its TCB (the engine) and its walls (Tier B).

## Part A — `sello-certify`: relational verification of binaries (leg 3)

(Naming, round-1: the consumer-facing tool is `sello-certify` — its
artifact is a certificate, and "audit" is this repo's standing word for
human review rounds (RFC-002/003), an authority-blur the tool should
not wear. The *instrument* and its CI checks keep "audit" internally:
the audit column, `audit-linux-amd64-*` — instrument names are internal
vocabulary alongside dudect/taint/disasm.)

### A1. Tool decision — verify-first spike, before any harness exists

The property is relational (self-composition: two copies, equal public
inputs, symbolic secrets, assert equal branch/address traces). Candidate
engines, evaluated in slice 1 against the REAL `feCMove` lifted from a
real `-d:release` binary:

- **Binsec, mainline, `checkct` plugin (primary candidate).** Round-1
  correction, load-bearing: the github.com/binsec/Rel repository is the
  ARCHIVED research prototype — "no longer maintained," x86-32 only.
  The relational CT analysis lives in mainline Binsec (≥ 0.10, `-checkct`;
  0.11 released Jan 2026) with x86-64/aarch64/RISC-V lifting via the
  `unisim_archisec` decoders, distributed on opam. Pin the opam version
  per the standing pin register. The published evaluation (S&P 2020 /
  TOPS 2022) verified complete X25519 ladders — donna-class, millions
  of unrolled instructions — in minutes, on the x86-32 path; the
  x86-64/aarch64 decoders are younger than that evaluation, so decoder
  fidelity ON OUR EXACT CODE SHAPES is itself a spike question: the
  spike records whether the amd64 decoder handles every SSE2
  `pand/pandn/por` form gcc emits in `feCMove`, and what an unsupported
  instruction does (hard stop vs. over-approximation — record which,
  since a silent over-approximation would be a soundness hole in the
  verdict). OCaml/opam availability in the sello-dev image is Stage 0
  of the spike (a zypper/opam verify-first question — opam appears to
  live in the devel:languages:ocaml OBS repo, not clearly main oss; a
  multi-stage build extracting the built binsec binary is the accepted
  fallback for keeping the image lean) — a Containerfile addition means
  a sello-dev repin, the slice-19 ritual, named as its own commit.
- **angr (fallback candidate):** python, general-purpose lifting +
  symbolic execution; self-composition assembled by hand. More plumbing,
  broader platform support, easier packaging for consumers (pip).
  Explicitly CONTINGENT: spend nothing on it if checkct GOes.
- **A bespoke lifter over nelli/nim-z3**: REJECTED up front. The
  existing symex walker carries four documented limitations on far
  simpler queries (`symex_recode`/`symex_mask`/`symex_equal`'s own module
  docs); building binary lifting on it is a research project inside a
  research project.

**Go/no-go criterion (three-sided — round-1 widened from two):** GO
requires (i) the engine proves the relational property for the current
`feCMove` (gcc and clang release builds) with zero counterexamples; AND
(ii) the same engine reports a counterexample resolving to the planted
branch on BOTH planted-defect forms — the barrier-stripped variant
under clang (the historical 22a defect, produced for the spike by the
`F31` exact-string patch or a git-stash hand-edit, the fix-slice-22a
arc's own method; the permanent flag mechanism is designed later, in
A4) and a source-level explicit secret-conditioned branch on both gcc
AND clang (the barrier-stripped form is only a branch where the
compiler chooses to synthesize one — clang today, gcc never — so it
cannot carry a two-backend criterion alone); AND (iii) the engine
proves ONE multiplication-chain Tier-A root (`feSqrtRatioM1`, or
`ladder` — the paper-precedented shape) within a stated budget on at
least one backend. Rationale for (iii): `feCMove` is a ~30-instruction
leaf; Tier-A feasibility is actually decided by symbolic term-DAG
growth through hundreds of inlined 10-limb multiplications, and a GO
earned on the leaf alone licenses slices 2–4 of harness/CI/packaging
work that a `feSqrtRatioM1` wall would strand. The published ladder
result says demanding this is realistic, not gold-plating. Any side
failing for BOTH engines activates the recorded degraded mode (A5) —
stated now, not discovered later.

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
and the audit asserts its column exactly as dudect/taint/disasm assert
theirs — the fourth instrument on the same audited fact-set, closing
its own silent-miss mode on day one. Round-1 cell-vocabulary decisions:

- A root covered only by a degraded mode gets a NEW cell kind,
  `ckDegraded(name, rationale)` — NOT `ckExempt`, which means "no
  target exists"; a scan-covered root IS covered, by the weaker mode,
  and collapsing that into "no coverage" throws away exactly the
  distinction the certificate must preserve (A3's disjoint verdict
  vocabulary). One-line `Coverage` variant addition.
- Not-yet-audited Tier-B cells (between slices 3 and 5) use the
  temporary-exemption `Pending` vocabulary — RETIRED by slice 21, whose
  register doc records the revival mechanism for exactly "a future
  instrument that needs it again"; RFC-007 is that instrument, and
  slice 3 revives it citing that note.
- The column stays PER-ROOT. The audit is the first instrument whose
  coverage genuinely varies per (root × compiler × kernel-backend);
  that config matrix lives in the certificate (A3), not smuggled into
  cell rationale free-text, and slice 10 cross-checks certificate
  matrix against register column.

**Tier A (straight-line roots):** `feCMove`, `feCSwap`, `cmovCached`,
`feSqrtRatioM1`, `` ristretto.`==` ``, `ristrettoEncode` — no loops or
public-constant-bound loops only; full relational proof expected.
**Tier B (loopy roots):** `ladder` (255 iterations), `compress` (80
rounds), `geScalarmultBase`/`geScalarmultCT` (64/256 steps),
`signDetached`/`derivePublic` (composites). The loop bounds are
compile-time public constants, so unrolling is TOTAL, not bounded-k: a
completed exploration is a full proof, and an incomplete one is a
TIMEOUT, nothing stronger. **Verdicts are total by definition (round-1):
PROVED (exploration exhausted) / COUNTEREXAMPLE / SKIPPED(budget, with
iterations-reached recorded as a diagnostic only).** There is no
"proved up to iteration k" cell anywhere — in the register, the
certificate, or the report; a prefix-CT ladder is not a CT ladder. A
Tier-B root that cannot complete falls back to A5's ladder FOR THAT
ROOT, recorded as `ckDegraded` citing the attempt — never silently.

**Preconditions AND declassifications per root are data, not prose
(round-1 — the second half was missing and the property is
unsatisfiable without it):** each register entry carries
(a) the public-input preconditions the proof assumes (e.g.
`geScalarmultBase`'s bit-255-clear), and (b) the root's sanctioned
declassification cut-points. This codebase maintains a curated register
of nine sanctioned secret-derived disclosures (`private/taint.nim`'s
`declassRegister`): `` ristretto.`==` ``'s whole OUTPUT is a
secret-derived verdict byte; `x25519`'s zero-verdict is branched on by
its wrapper; the import constructors branch on their verdicts. A
relational engine told "the secret differs" will — correctly, per its
model — report a violation at every such point. Binsec's checkct has no
built-in declassify; the harness must therefore cut the trace-equality
obligation at each registered disclosure (stop the obligation at the
declassified value, or havoc-equalize it in both copies), and the
per-root cut-point list is derived from the entries' existing
type-checked `declassIds` field and drift-checked against
`declassRegister` the same way `taint_anchor_check.py` already checks
the taint column. Without this, slice 2 discovers mid-implementation
that the load-bearing property is false on its own target list.

**Entry-state specification is a harness artifact, not documentation
(round-1):** relational SE on a binary function requires a defined
initial state — which registers/stack bytes are secret vs. public-equal,
pointer arguments to properly-sized disjoint buffers, and `Fe` limb
inputs constrained to their radix-2^25.5 bounds (an unconstrained
32-bit limb reaches overflow paths no real caller reaches —
`symex_reduce`'s input-bound envelope is the precedent and the
derivation style). Slice 2 produces the per-root entry-state records
(secret layout + bounds + cut-points), the register carries them, and
each root's record is exercised by a fixture that VIOLATES it: an
unconstrained-input run that finds a spurious counterexample is the
natural red demo that the preconditions are load-bearing rather than
decorative.

### A3. The consumer contract — two modes, stated honestly

Round-1 rewrite: the slice-23 resolver's actual inputs are (1) `nim
jsondoc` over a resolvable module graph, (2) **the nimcache C of the
exact build, compiled `--lineDir:on`** (the `#line`/`N_NOINLINE` scan is
how the mangled symbol is found at all), and (3) an unstripped symbol
table — and the mangling embeds the relative module path and varies by
Nim version. "A binary + the source tree" cannot be resolved; a
stripped release binary (the median consumer artifact) cannot even be
scanned. The contract is therefore two modes, the cargo-checkct shape:

- **Mode 1 (sound, recommended): `sello-certify build && sello-certify
  run`.** The tool builds a dedicated harness binary from the
  CONSUMER'S toolchain + the sello tree they already have, with pinned
  flags (`-d:release --lineDir:on`, nimcache retained), per-root
  drivers with designated secret/public input locations (the marking
  spec slice 1 records), then verifies that artifact. This still
  discharges the RFC's actual residual — the consumer's compiler
  compiles the roots — and the resolver transfers essentially as-is.
  **Claim boundary, stated in the output:** mode 1 certifies
  this-toolchain-on-these-roots-under-these-flags, NOT the consumer's
  application link (different flags ⇒ different codegen; LTO across
  the app boundary is the app's own event).
- **Mode 2 (best-effort): `sello-certify <binary> --nimcache <dir>`.**
  Resolution inside an existing binary, requiring the build's nimcache
  dir (cheap and honest — anyone who just built has one), an
  unstripped binary, and a Nim major version the resolver was
  validated against (disclosed). Every failure mode is a FIRST-CLASS
  VERDICT — `UNRESOLVED(stripped|lto|version-skew|no-nimcache)` —
  never a silent skip; a tool that quietly skips the roots it cannot
  find is the silent-miss mode the register culture exists to forbid.

**Verdict vocabulary — lexically disjoint by mode (round-1):**
relational mode: `PROVED(engine, version)` / `COUNTEREXAMPLE(location)`
/ `SKIPPED(budget)` / `UNRESOLVED(reason)`. Scan mode (A5 rung 3):
`SCAN_CLEAN` / `BRANCH_FOUND(location)` — a different word for the
positive verdict, so `PROVED` is UNSPELLABLE in the weaker mode, plus a
printed blindness line (`blind to: cmov/csel, secret-indexed loads`) on
the verdict itself. Exit codes distinguish all-proved (0) from
clean-but-any-degraded (3) so a consumer's CI can gate on proof
strength mechanically. `mode` is a required per-root certificate field
(Tier-B roots mix modes within one run).

**Certificate (the proof-carrying-build artifact):** machine-readable;
schema-version field with a stability policy — the certificate is
consumed by other people's evidence records, i.e. the same class of
stable public interface as check names, evolved by the two-step. Per
root: root, tier, MODE, verdict, engine + engine version, the
preconditions and declassification cut-points assumed (register-derived
— the claim scope travels as data, not prose), budget outcome; per
run: binary hash, sello source version, platform, the leakage-model
scope enumeration VERBATIM, the TCB clause. Slice 4 decides signing
(the `.github/allowed_signers` trust root exists) explicitly, even if
the decision is "unsigned v1, revisit."

**The certificate has a consumer on day one (round-1 — an interface
with no consumer is the classic inert mechanism):** our own audit CI
jobs run a `sello-certify verify-cert` round-trip on the certificate
they just emitted, and `release-publish` attaches the release build's
certificates alongside the tarball + sha256.

**Platform scope v1: linux x86-64 ELF.** The aarch64 claim is GATED on
slice 1's aarch64 half passing (cross-compile `feCMove` with an
aarch64-target gcc, lift and verify the ELF on the amd64 sello-dev host
— the engine is static analysis, no qemu needed; the s390x-leg pattern
minus emulation), and aarch64 gets ENGINE-MODE ONLY until an aarch64
scan table lands with its own red demo — the scan stack is
x86/AT&T-specific today (`Jcc` mnemonics; aarch64 conditional control
flow is `b.cond`/`cbz`/`cbnz`/`tbz`/`tbnz`, and `csel` raises the CMOV
question as the default lowering, not an occasional one). Windows/macOS
object formats remain deferred to a future RFC; the README claim is
scoped in as many words.

### A4. CI integration — our own builds go first

Before any consumer runs it, WE run it: required checks
`audit-linux-amd64-gcc` / `audit-linux-amd64-clang` on the sello-dev
image, over the same binaries the disasm gate profiles.

**Placement and budget (round-1 — previously unstated, and symbolic
execution is the most budget-volatile instrument ever proposed here):**
the required checks run TIER A + the planted fixture only, each root
under a per-root budget cap, with the measured-before-landing step and
the bmc-symex timeout-triage policy adopted verbatim (internal
`timeout --signal=KILL` below the job ceiling; one retry for hosted
variance; a second timeout on the same code is investigated, never
re-run to green). Tier B runs in `nightly.yml` (slice 5), which means
three named touch points: the `notify` job's `needs:` list, a
freshness posture for its results, and an explicit decision whether the
audit job joins `release_gate.py` clause (ii)'s ENUMERATED nightly
subset (default: yes, once two clean scheduled runs exist — decided in
slice 5, not left to drift).

Relationship to the existing disasm gate, decided now — on the honest
axes (round-1: latency, coverage, platform reach — not verdict
strength, where the audit dominates when it completes): the
mnemonic-baseline gate STAYS. It runs in seconds on every push; it
covers the roots the audit SKIPs and every platform the lifter doesn't
reach; its per-backend baselines are the canary's rolling substrate.
Once the audit is live, the disasm gate's README validation-map row is
RENAMED from CT evidence to regression telemetry — its honest role. If
experience shows full subsumption, retiring it is a later, separate
decision through the check-rename two-step — not this RFC's call.

**Toolchain-canary extension (round-1 — the project's own "compiler we
never saw" simulator, previously unwired):** the canary's
`newest-gcc`/`newest-clang` legs additionally run the audit over the
rolling Tumbleweed compilers, alert-only, exactly as slice 23 Stage 4
extended the same two legs with `disasm-gate.sh --canary`. This is the
cheapest standing mechanism that catches the next 22a before any
consumer does, and it exercises the harness against genuinely-unseen
compiler output nightly. An audit COUNTEREXAMPLE under a future
compiler is notify-and-triage (the canary's register: an expected
finding class, the canary working), never gate-red.

**Permanent negative fixture (round-1 redesign — the drafted fixture
depended on a compiler heuristic staying stable):** the permanent,
both-backends fixture plants a SOURCE-LEVEL explicit secret-conditioned
branch (a literal `if` on the mask, the `target_planted_leak` pattern) —
the defect exists by construction, on gcc and clang, forever. The
barrier-stripped-under-clang build (the historical 22a form) is a
SECOND, dated fixture with a recorded expiry condition: valid while the
pinned clang synthesizes the branch; on a repin where it stops, retired
with a note — never a red that reads "audit broken" when the truth is
"fixture evaporated." (gcc never synthesized the branch, so the
stripped-barrier form can carry no two-backend assertion — the reason
the permanent fixture is source-level.) The `-d:selloAuditPlantedBranch`
flag is a `when defined` fork touching the most CT-critical lines in
the codebase, so it carries: the taint-shim two-key guard (the flag
alone, outside the harness script, is a deliberate LINK error — the
`SELLO_TAINT_HARNESS_ACTIVE` precedent, so a consumer cannot compile a
planted-branch sello that passes every functional test); the
flag-absent codegen-identity proof (byte-identical modulo suffix
renumbering, the slice-19 diff method); and re-anchoring of the
exact-string mutation patches that match those lines (`F20`, `S08`,
`S09`, retired `F31`).

### A5. Degraded modes — a ladder, not a cliff (round-1 respec)

The drafted fallback asserted "zero conditional branches in Tier-A
roots; branch count == public-loop count in Tier-B" — an invariant our
OWN COMMITTED BASELINES falsify today: `feSqrtRatioM1` carries 8
benign branches under the pinned gcc (one `-fstack-protector-strong`
canary check per inlined helper frame — a distro default no build asked
for), `feCMove` carries the auto-vectorizer's pointer-distance dispatch,
and `ladder` shows 39 branches against one source loop
(`tests/ct_disasm/expected/justifications.md` documents all of it). On
an arbitrary consumer toolchain the benign classes multiply. As
specified, the fallback fails every honest binary ever built, ours
included. Respec'd as a LADDER of three rungs, strongest available
wins, each rung's strength printed on its own verdict:

1. **The relational proof** (the instrument; everything above).
2. **Consumer taint mode (round-1 addition — the strongest
   already-built alternative, previously never weighed):** build with
   `-d:selloTaint` and run the EXISTING valgrind memcheck battery on
   the consumer's own toolchain's output — the instrument that FOUND
   the 22a defect. Deterministic, red-demoed, valgrind is in every
   distro (no opam/pip TCB addition), and it sees secret-indexed
   addressing (which rung 3 is blind to). Disclosed weaknesses:
   per-executed-path only, linux-only, requires execution not just
   lifting, blind to untaken paths, and it inherits the taint
   harness's own script-gated build (the two-key guard). Bundled as
   `sello-certify --taint`; its positive verdict is
   `TAINT_CLEAN(paths-executed)`, lexically its own.
3. **Advisory branch scan (weakest, zero-dependency):** the disasm
   resolver + objdump, now specified honestly: an idiom-classification
   pass (recognize stack-protector canary and vectorizer-dispatch
   shapes by their non-secret operand pattern — heuristic, stated as
   such) and a report of every UNEXPLAINED conditional branch, plus
   the div/idiv-in-secret-dataflow assertion from the leakage-model
   section. Verdicts `SCAN_CLEAN`/`BRANCH_FOUND` per A3's disjoint
   vocabulary, blindness line printed (`blind to: cmov/csel,
   secret-indexed loads`), human-triage residual disclosed. x86-64
   only in v1 (A3). Scan mode has ITS OWN red demo (slice 4): the
   planted source-level branch, caught by the scan on a real run.

If the slice-1 spike NO-GOs on both engines, the RFC re-scopes around
rungs 2–3 and RETURNS TO REVIEW — an escalation, not a silent
fallback; the weaker rungs are not a substitute for the load-bearing
property.

## Part B — the CT kernel DSL (leg 1)

> **FORK (round 1, OPEN — awaiting Corey; everything below is kept as
> drafted pending this decision, with round-1 fixes applied inside).**
> The design review proposes REPLACING the DSL with the codebase's own
> signature move applied once more: a nominal `CtMask` type
> (`distinct int32`, no converters, whose ONLY constructor is
> `ctMask(b: bool): CtMask = CtMask(valueBarrier32(-int32(b)))` — making
> "an unbarriered mask cannot exist" an ordinary type-checking fact,
> which is the one real authoring-side hazard today's three-site grep
> convention leaves open) plus two asm-bodied primitives
> (`ctSelect32`/`ctSwap32` in `private/ct.nim`, per-arch `{.emit.}`
> bodies behind `-d:selloAsmKernels`, portable body = today's exact
> code). Grounds, all verified this round: (a) the DSL is a large
> interface (grammar + whitelist + diagnostics + fixture battery +
> three backends + SMT export) hiding a small implementation (two
> ~10-line formulas) — the inversion of the deep-module bar; (b) this
> RFC's own Why concedes the authoring side has never failed, and
> B2.1's honesty clause concedes the portable backend's types certify
> nothing Part A doesn't on the one axis that has failed; (c) the
> proof-spike rule: the DSL's named future consumers have declined it
> in writing — RFC-008: "the DSL is not a dependency"; RFC-009:
> "independent of RFC-007/008"; RFC-010: audit "desirable," DSL
> unmentioned — so the interface would freeze against N=1, the three
> selects it was reverse-engineered from. Under the alternative,
> slices 6–8 collapse into one slice ("CT select primitives with
> per-arch asm bodies, certified by the audit gates") absorbing 9a,
> slice 8's obligation export is cut (see B2.3's moved-gap note), and
> Part C's composition survives intact (the audit still certifies the
> asm output; the DSL-shrinks-the-surface arrow was already false —
> see Part C). This restructure would invalidate leg 1 of the founding
> design discussion, so it is ESCALATED, not applied. If the DSL is
> retained, its interface must be proof-spiked against a real second
> consumer before freezing (the rule the fork exists to enforce).

### B1. What it is

`src/sello/private/ctdsl.nim`: a macro (`ctKernel`) defining an embedded
DSL in which the CT selection kernels are written once and lowered to
multiple backends. Inside a kernel: values are `Secret[T]` or
`Public[T]`; the admitted operations on `Secret` are a whitelist (xor,
and, or, not, add/sub, shifts by `Public` amounts, `select(mask, a, b)`,
widening/narrowing); `if`/`case` on a secret, indexing by a secret, and
comparison yielding a bare `bool` are NOT REPRESENTABLE — rejected at
macro expansion with a diagnostic naming the offending node.

Round-1 soundness constraints, previously unstated:
- **Default-deny over TYPED AST:** the macro rejects every node kind
  not whitelisted — `cast`, `addr`/`unsafeAddr`, `{.emit.}`, calls to
  any symbol outside the DSL's op set, and un-expanded
  template/macro invocations (the macro takes `typed`, or re-sems its
  body, so nothing smuggles through an alias) — a closed grammar, not
  a default-allow with named rejections. Negative fixtures (the
  `reject_*` subprocess-`nim c` pattern) pin every rejection class AND
  every escape hatch: `cast`, `addr`, `emit`, a smuggled template.
- **The boundary is specified, not assumed:** `Secret[T]` values do not
  exit the kernel as bare `T`; construction/destruction sites are
  explicit doors (the `SecretScalar`/`feFromLimbs` one-door precedent).
  The bridge between the two secrecy vocabularies — how a
  `SecretScalar` or an `Fe` limb enters a kernel and becomes
  `Secret[int32]`, and leaves — is part of B1's design, because two
  unbridged secrecy-typing systems in one codebase is where confusion
  lives.
- **Naming:** `Public[T]` collides with the wire-role sense of "public"
  (`PublicKey`/`X25519Public` = sendable); the DSL sense is
  observable-dependence-allowed. Pick a non-colliding word (e.g.
  `Open[T]`).
- The property "no secret-dependent branch or index exists in this
  kernel's SOURCE" becomes a grammar theorem, not a review outcome —
  and every use of the phrase "grammar theorem" travels glued to
  B2.1's honesty clause, because the theorem is source-shape only.

### B2. Backends, and where the guarantee actually lives

1. **Portable backend (default):** emits exactly the barrier'd masked
   arithmetic shipped today. Round-1 correction to the migration goal:
   literal byte-identical C is UNATTAINABLE BY CONSTRUCTION — the
   project's own slice-19/21 proofs record that adding a module/import
   shifts Nim's global symbol-suffix counter, and slice 7 necessarily
   adds an import. The goal is the already-precedented standard by
   name: **byte-identical modulo Nim's `_u<N>` suffix renumbering,
   verified by the slice-19 diff comparator, committed as a script;
   any other hunk class is a hard failure** — so the evidence refresh
   is an equality argument under a declared, audited normalization,
   never ad-hoc diff-filtering (which is where a real instruction
   slips through). Honesty clause: this backend's CT still terminates
   at the compiler; it is certified by Part A, not by the types.
2. **Asm backend (`-d:selloAsmKernels`, x86-64 + aarch64):** the DSL
   emits the kernels as inline assembly — the compiler has zero codegen
   freedom over the selection. The emission templates are a hand-written
   TRUSTED COMPONENT (we are not building Jasmin's preservation proof);
   what certifies them is Part A's audit running on the asm-backend
   binary. Round-1 scope corrections: (a) that certification is
   PER-AUDITED-BINARY — a consumer who enables the flag and never runs
   `sello-certify` carries hand-written templates with ZERO instruments
   on them, a strictly worse posture than the default backend (whose
   shape passed dudect/taint/disasm on CI); the flag's own docs say
   "use with sello-certify" in as many words. (b) The slice-1 spike
   confirms the engine's decoder lifts the exact instructions the
   templates emit — an unsupported-instruction stop inside the asm
   kernel would make the asm leg UNAUDITABLE, the one composition
   failure that breaks the "one design" claim.
3. **Obligation export:** the kernel AST exports its semantics as SMT
   terms for the existing nelli/nim-z3 harness. Round-1 honesty: this
   RELOCATES the re-encoding gap rather than closing it — the AST then
   has two lowerings (AST→C, AST→SMT) whose agreement is exactly as
   unproved as today's source↔hand-transliteration agreement (which is
   at least closed by 1124 concrete cross-check cases and documented);
   and machine-generated obligations cannot be hand-restructured
   around the nelli walker's four documented crash classes the way
   `symex_mask.nim`'s proofs had to be. The existing files stay as
   cross-checks regardless, per the belt-and-suspenders register.

### B3. Migration scope — kernels only, honestly

v1 migrates exactly the mask-select kernels (`feCMove`, `feCSwap`,
`cmovCached`'s select core). NOT a general information-flow system for
the library: the field arithmetic, ladder, and hash cores stay ordinary
Nim under the existing instruments (their risk is arithmetic, which the
DSL does not address, and their CT is certified by Part A). Widening the
DSL's coverage is future work contingent on a real second consumer
(none exists in writing today — see the FORK note). Every migration
touch of `src/sello/` follows the standing shipped-codegen rules:
mutant re-sync, coverage repin, evidence refresh (cheap where
normalized-identical emission is proved, full where not) — slice 7
enumerates the actual refresh set.

## Part C — composition (what is genuinely one design)

Round-1 correction: the drafted claim "the DSL shrinks the audit's
Tier-A surface" was false as scoped — Tier A includes
`feSqrtRatioM1`/`` `==` ``/`ristrettoEncode`, which the DSL never
touches, and the audit verifies the identical binary whether or not a
macro authored three of twelve roots. The REAL composition is one
arrow, and it is an ORDERING constraint: **the asm backend ships only
after the audit exists to certify its output** (slice 9 needs 2–3),
because an unproved hand-written trusted component with no instrument
on it would move the project backwards. Beyond that arrow, Parts A and
B are independent after slice 1 (the slice graph says so), Part A alone
carries the load-bearing property — which is exactly why Part B's shape
is severable as the open fork — and the register binds whichever parts
land to the same fact-set the other three instruments already assert
against.

## Slices

Ordering rule inherited from RFC-005: the load-bearing property's
producer is slice 1; infra slices verify by running the thing; every
gate slice's DoD includes its red demonstration.

1. **Spike: the relational verdict, end-to-end (GO/NO-GO).** Stage 0:
   opam/binsec into the sello-dev Containerfile (verify-first: zypper
   availability; multi-stage extraction fallback), the slice-19 repin
   ritual as its own commit. Then mainline binsec `checkct` (angr only
   if it NO-GOes), against real gcc+clang `-d:release` binaries: all
   three sides of A1's criterion (current `feCMove` proved; both
   planted forms counterexampled — barrier-stripped-clang via the F31
   patch/stash hand-edit, source-level branch on both backends; one
   multiplication-chain root proved within a stated budget). Plus the
   aarch64 half: cross-compile `feCMove` for aarch64, lift/verify the
   ELF on the amd64 host (gates A3's aarch64 claim). Recorded outputs:
   engine + version pin, decoder-coverage notes (SSE2 forms;
   unsupported-instruction behavior), the secret/public input marking
   spec the harness will reuse, image repin. NO-GO on both engines →
   the RFC re-scopes around A5's rungs 2–3 and returns to review — an
   escalation, not a silent fallback.
2. **Audit harness, Tier A, our tree.** The slice-23 resolver reused
   as-is (no consumer generalization yet — that is slice 4's contract
   work); a per-root driver/probe set with designated secret inputs +
   per-root engine scripts; per-root preconditions AND declassification
   cut-points derived from the register (`declassIds`), drift-checked;
   the entry-state records + the precondition-violation fixture (A2);
   the `-d:selloAuditPlantedBranch` mechanism designed and landed
   (two-key guard, flag-absent codegen-identity proof, mutant
   re-anchors — A4); the six Tier-A roots; both compilers; the planted
   fixtures red, locally.
3. **Register audit column + CI gates.** The column sync set,
   enumerated (round-1 — each item is a silent-miss if skipped):
   extend `test_registers.nim`'s per-instrument loops to the fourth
   column FIRST and watch them fail (the default-value trap: an
   omitted `audit:` field compiles as a silently-"direct" empty-named
   cell on all 37 entries — the test extension must precede the field);
   the all-37 sweep (wipe paths, import constructors, sha512-message
   get reasoned cells, mostly `ckExempt` with rationale); the
   `ckDegraded` variant added; the `Pending` vocabulary revived per the
   register doc's own recorded mechanism; the audit harness asserts
   its column via a COMPILED accessor (`auditRoots()`/`auditCells()`,
   the `nim r` probe pattern) — not a third regex parser over the
   register source (and if the field's insertion point moves,
   `ct-taint.sh`'s field-order-anchored regex is re-verified in the
   same commit). Then `audit-linux-amd64-{gcc,clang}` as required
   checks (the check-adding flow), Tier A + fixtures only, per-root
   budget caps, measured before landing, the bmc timeout-triage policy;
   red demo on a real hosted run.
4. **`sello-certify` consumer packaging (depends on 3 — round-1: the
   README rewrite before the checks exist would be an unchecked
   claim, and the validation-map rows fail their own drift check
   without the jobs).** The two-mode contract (A3), the certificate +
   `verify-cert` round-trip + release-artifact wiring, the `--taint`
   rung bundled, the scan rung with idiom classification AND its own
   red demo, the two unseen-toolchain demonstrations (the
   toolchain-canary extension, alert-only; the consumer-route build +
   audit — which is also the first real exercise of mode 2's input
   contract), docs + README (the CT-scope paragraph REWRITTEN from
   disclosure to check — this is the RFC's user-visible payoff —
   preserving `validation_map_check.py`'s regex-asserted pin strings
   or updating the checker in the same slice), validation-map rows.
5. **Tier B, per root, nightly.** Bounded budgets; each root lands
   PROVED or `ckDegraded` with the attempt's evidence (the
   `symex_reduce` precedent for honest walls); `nightly.yml` placement
   with the three named touch points (notify `needs:`, freshness,
   the release-gate clause-(ii) membership decision).
6. **DSL core** *(CONTINGENT on the Part B fork).* `ctKernel`,
   `Secret`/renamed-`Public`, the default-deny typed grammar, the
   boundary/bridge spec, rejection diagnostics, negative fixtures
   including the escape hatches, obligation export skeleton. No
   shipped code changes yet — but this slice runs the verify-first
   probe slice 7 depends on: does `nim jsondoc`'s reported line and
   nimcache's `#line`-preceded definition survive macro emission (the
   disasm resolver's steps 1–2 — a divergence here breaks two live
   required checks and must be discovered where it costs nothing).
7. **Kernel migration, portable backend** *(CONTINGENT).* The three
   selects through the DSL with normalized-identical emission proved
   (the committed comparator; any non-suffix hunk = hard failure) or
   the honest fallback paid in full (full dudect battery + both disasm
   baselines + taint reruns + coverage repin); mutants re-anchored
   (`F20`/`S08`/`S09`/`F31`) and re-verified red; coverage baseline
   updated (including the 0-line-macro-module decision); red demo: the
   equality harness itself demonstrated failing on a planted
   one-instruction delta.
8. **Obligation export replaces hand-encodings** *(CONTINGENT).*
   Derived SMT obligations discharge in `scripts/bmc.sh` (budget
   headroom re-measured against the ~165s baseline); `symex_mask.nim`
   demoted to cross-check; red demo: a corrupted derived obligation
   fails `scripts/bmc.sh` for real.
9. **Asm backend** — split (round-1: six surfaces across a platform
   fork is a round, not a slice): **9a** x86-64 emission behind
   `-d:selloAsmKernels` + the amd64 audit leg certifying it + the full
   evidence refresh (an honest full-refresh event, new codegen by
   design); **9b** aarch64 emission + a cross-aarch64 toolchain into
   the Containerfile (repin ritual) + the cross-compiled probe audited
   on the amd64 host (the s390x pattern minus qemu) — only after this
   does the README's aarch64-asm sentence exist; **9c** dudect A/B of
   the two backends on the timing box (if live), opportunistic.
10. **Close-out.** Claims audit against the dichotomy across ALL the
    claim surfaces, enumerated: README (CT-scope + validation map),
    SECURITY.md's posture section, CONTRIBUTING.md's affected-gate
    battery (grows the audit gates), CLAUDE.md's validation bar; the
    certificate config-matrix ↔ register-column cross-check; the
    register's instrument columns cross-checked.

Slices 1–5 (Part A) and 6–8 (Part B core, if retained) are independent
after slice 1; 9 depends on both 6–8 (or the fork's collapsed slice)
and 2–3; 4 depends on 2 AND 3.

## Ordering & risks

- **Engine availability/packaging** is the biggest unknown (opam/OCaml
  in the image — Stage 0 verify-first; consumer install ergonomics —
  mitigated by the mode-1 harness-build contract and the rung-2 taint
  fallback) — squarely why slice 1 is a spike with a three-sided
  criterion and a named fallback ladder.
- **Wall clock**: symbolic execution is budget-volatile; Tier A is
  required-check material only with measured numbers, Tier B is
  nightly by design, and the merge gate's existing long pole
  (coverage-ratchet, ~13.5 min) is the ceiling to respect.
- **Solver walls on Tier B** are expected, not exceptional; the
  per-root proved-or-degraded design absorbs them without blocking the
  RFC.
- **The mode-1 claim boundary**: `sello-certify` certifies
  toolchain-on-roots-under-pinned-flags, not the consumer's
  application link — stated in the output, the README, and the
  certificate, so the strongest honest claim is the one that ships.
- **Evidence refresh cost** for slice 7 is bounded by the
  normalized-identity goal (with the full-battery fallback priced
  honestly in the slice); slice 9a is an honest full-refresh event and
  is sequenced late for that reason.
- **The lifter joins the TCB** — repeated here because it must appear in
  every claim the audit makes; overclaiming "proved" without naming the
  engine is the exact crowned-property violation RFC-005 round 2 killed
  elsewhere. The leakage-model scope enumeration travels the same way.
- The timing box (RFC-005 slices 27–29) is NOT a dependency; slice 9c's
  dudect A/B is opportunistic.

## Non-goals

- Jasmin/FaCT/CompCert-CT adoption (a compiler-pipeline migration, not a
  library feature; recorded as the field's long-term answer).
- A general information-flow type system over the whole library (B3).
- Certifying the consumer's APPLICATION binary beyond the mode-1
  harness boundary (their link, their flags, their LTO — disclosed,
  A3).
- The 64-bit/fiat-generated field backend and hardware DIT/DOITM modes —
  legs 2 and 4 of the design discussion, deliberately split into a
  future RFC-008 so this RFC stays one property deep.
- Windows/macOS binary formats in `sello-certify` v1 (scoped,
  disclosed); aarch64 scan-mode tables in v1 (engine-mode only, A3).
- Proving the asm emission templates (Jasmin's theorem) — v1 certifies
  their OUTPUT via the audit instead, stated in as many words.
