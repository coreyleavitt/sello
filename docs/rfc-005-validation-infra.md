# RFC-005: Validation infrastructure — suite gaps, CI, and the public evidence story

- **Status:** in-progress — ACCEPTED (stage 3 opened 2026-08-24 — Corey's sign-off given by
  launching the implementation grind; architect rounds 1 and 2 applied
  2026-08-23). Drafted 2026-08-14 from the
  first-principles design session (grill) of the same date; the resolved
  decisions table from that session is this RFC's requirements record —
  decisions below cite it rather than re-litigating. Round-1 and round-2
  corrections are in place, dated, per the amendment register precedent;
  the headline ones are listed in the **Round-1 review record** and
  **Round-2 review record** at the bottom.
- **Numbering / ordering:** RESOLVED (2026-08-23 amendment) — RFC-006
  (in-house SHA-512) shipped first (0.5.0). Every "post-RFC-006" conditional
  in the original draft is now unconditional: the tree resolves zero core
  dependencies, `--path:src` is the whole build configuration for core
  jobs, the SHA-512 taint/disasm targets are in scope, and the dudect
  carve-out set is **three** targets (`` ristretto.`==` ``,
  `x25519(static)`, `sha512` compress), not two. Enumerations below are
  phrased intensionally ("every dudect carve-out target") where a count
  could go stale again.
- **Handoff doc:** `docs/rfc-005-validation-infra.handoff.md`.
- **Standing orders:** identical to RFC-001..004 (PhD-CS bar; genuine forks
  escalate; wrong-spec assumptions escalate; per-slice commits after gates
  pass — noting that mid-RFC, "commit" targets this RFC's own branch once
  the branch model below exists; this RFC bootstraps the rule it will then
  live under).
- **Specs / references:** GitHub Actions + repository rulesets (behavior
  verified against live GitHub, not memory, at implementation time — the
  required-checks-without-PR mechanics, the push-ruleset file-path
  restriction, and tag rulesets are all load-bearing); Valgrind memcheck
  client requests (`valgrind/memcheck.h` — compiler-visible magic asm
  sequences in the C macro; sello reaches them through a shim TU, see A1);
  BoringSSL's `CONSTTIME_DECLASSIFY` pattern (the declassification-marker
  precedent A1 follows); gcov/lcov; QEMU user-mode emulation;
  NIST/Wycheproof corpora unchanged.

## Load-bearing property and definition of done

*(Added in round 1; restated honestly in round 2 — the original round-1
text claimed slice 1 produced the property, which its own clause (i)
contradicts.)*

**This RFC lives or dies on:** *every claim in the validation bar is either
(i) continuously enforced by a named required check, traceable through the
gates manifest, or (ii) an explicitly labeled deliberate manual ritual
(timing-tier runs, results-doc commits, corpus snapshots) whose freshness is
bounded by a CI-checked gate.*

**When the property becomes true (round-2 correction):** slice 1 produces
the *observable, failable check* end-to-end through the real entry point —
a real push, a real red — but a check without a ruleset enforces nothing;
clause (i)'s "required" first exists at the ruleset slice. The property is
therefore first TRUE at the end of phase 0, and phase 0 is ordered so that
**enforcement exists before the repo is public** (the ruleset slice
precedes go-public — rulesets work fine on private repos, and a public
repo with advisory-only checks would publish an evidence story that
overclaims for the width of the gap). Every later slice only widens the
property's coverage. The final close-out slice audits each validation-bar
line against this dichotomy.

A1 (taint CT) is this RFC's **largest new capability**, not its headline —
the original draft's "headline" label is demoted. The Context section ranks
problem 3 (the timing environment) most severe while the slices address it
last; that inversion is deliberate and now recorded: the timing tier is the
RFC's only physical-world dependency, and severity does not override
dependency order. The property above is produced by phase 0 and merely
widened by everything after; problem 3's slices can slide without making
the RFC's core property false.

**Red-then-green rule (applies to every gate slice, matrix legs
included — round-2 scope clarification):** a gate's definition of done
includes a demonstration that the gate can *fail* through the real entry
point — a real push turning the real check red — plus the slice's
enumerated negative control. Matrix legs are gate slices: each leg carries
(i) a **platform-identity canary** compiled into the suite run (arch/OS
assert — the i386 pointer-width assert generalized to every leg, because
the classic matrix failure is a leg silently running the wrong thing:
host arch instead of target, cached amd64 image on arm64, a skip-riddled
suite) and (ii) one demonstrated red run. A gate proven only green is
indistinguishable from a gate that cannot fire; that is the S07 class this
RFC exists to kill, and it will not be rebuilt inside the RFC's own
deliverables.

**Per-slice doc rule (round-2 addition):** a slice that adds a script, env
var, ritual, or required check updates CLAUDE.md (and CONTRIBUTING/README
where touched) in the same commit — DoD, not close-out. Slices 2 onward
execute against the operating manual they change; deferring doc updates to
close-out is how a later session re-derives or contradicts a landed
decision (this is every prior RFC's in-slice-doc precedent, kept).

## Context

sello's validation battery is real but **invisible and manual**: seven gate
scripts run by hand on one shared podman host, results transcribed into
`docs/`. Three structural problems, in increasing order of severity:

1. **Nothing runs automatically.** Every gate is only as fresh as the last
   time someone remembered to run it; the S07 mutation-anchor breakage sat
   silent across an entire slice until the next manual mutation run.
2. **The evidence is unverifiable.** The repo is private and the docs say
   "trust our transcripts." For a library whose entire premise is trust
   earned through evidence, the evidence must be publicly reproducible and
   continuously produced.
3. **The timing instrument is compromised by its environment.** Every
   dudect verdict on file comes from a shared host; RFC-004 paid a
   multi-round artifact-investigation tax twice, and three targets carry
   carve-outs that a quiet box could either retire or genuinely confirm.

Separately, the suite itself has gaps no amount of CI fixes: CT verification
is statistical-only (dudect) when a deterministic instrument exists; nothing
measures coverage; nothing exercises 32-bit or big-endian, the two
environments where ported carry-chain arithmetic historically breaks; and
the toolchain pin (Nim 2.2.10 — and, equally load-bearing, the C compilers
inside the pinned image) has no canary watching for upstream drift.

## Design

### Part A — new suite capability (the gaps CI would otherwise automate)

**A1. Deterministic CT verification, taint-based.** A new harness
(`tests/ct_taint/`, `scripts/ct-taint.sh`) runs the secret-holding paths
under Valgrind memcheck with secrets marked UNDEFINED via client requests
(`VALGRIND_MAKE_MEM_UNDEFINED`): any conditional branch or memory index
influenced by undefined (= secret-derived) data is a deterministic error
with a stack trace — the ctgrind construction. This complements dudect, it
does not replace it: taint proves no-branch/no-index *on this binary*;
dudect measures the composite reality on real silicon.

- Tooling choice (recorded): Valgrind, not MemorySanitizer — works against
  the existing gcc-backend release build with zero mandatory code changes
  to the core; MSan needs the clang backend plus instrumenting every
  translation unit, considered and declined for now (revisitable — it is
  the recorded fallback, and the taint slice's *first task* is the
  empirical go/no-go below, before any register construction begins).
- **Mechanism, stated precisely (round-2 correction — the round-1 "magic
  asm sequence, not a linked call" phrasing conflated the C macro's
  nature with sello's route to it):** the client-request macros are
  C-only; sello reaches them through a small C shim TU
  (`src/sello/private/taint_shim.c` — adjacent to `taint.nim`, compiled
  via a conditional `{.compile.}` only under `-d:selloTaint`, so consumer
  builds never see it) exposing by-address functions
  (`pointer + len` — client requests operate on addressable memory, so
  `declassify` takes the lvalue's address; verdict words that live in
  registers are spilled by the call, and the call's clobber semantics
  make post-call reads reload the now-defined memory — the BoringSSL
  construction, recorded here because the shim signature depends on it).
  The honest invariant statement: `declassify` expands to **nothing** in
  every normal build (no FFI, zero cost, for every build a consumer ever
  makes); under `-d:selloTaint` it is a **call into the shim TU — a
  deliberate, confined FFI exception that exists only in the taint
  build** (no linked library; building the core with `-d:selloTaint`
  outside the harness is a link error by design). Residual, disclosed:
  the taint binary is a third *source* variant, not just a third
  compilation — the shim call is an optimization barrier and codegen
  around each disclosure point can differ from the no-taint build;
  mitigated by the disasm gate (A2) running on the *non-taint* binary, so
  branch-synthesis evidence comes from the unperturbed source.
- **Declassification markers live in the core, as compile-time no-ops
  (round-1 correction).** The original draft placed every
  `VALGRIND_MAKE_MEM_DEFINED` in the harness; that construction cannot
  work: memcheck reports at the branch instruction, and the sanctioned
  branches are *interior* to library code (`x25519`'s all-zero
  OR-accumulate verdicts in both overloads, `toRistrettoStaticSecret`'s
  `scIsCanonicalCT` verdict, the ephemeral `ristrettoScalarmult`'s
  identity zero-check, `keypair(seed, expectedPublic)`'s public-key
  compare). A harness-side declassification is either too late (after the
  call returns) or destroys the test (declassifying the secret input).
  Valgrind suppression files are not an acceptable fallback — they match
  at function granularity and would mask *new* errors in the same
  function, gutting the fails-loud guarantee. Instead, the BoringSSL
  `CONSTTIME_DECLASSIFY` pattern: `src/sello/private/taint.nim` exports
  `declassify(id: DeclassId, ...)` — buffer overload *and* scalar overload
  (several registered disclosures are single verdict words, not buffers;
  without the scalar form call sites would contort verdicts into byte
  arrays). For derived-public-material entries disclosed at return, the
  stated idiom is assign-`result`, `declassify`, then return — one shape
  at every such site.
- **The register is a `const` table, indexed by the enum (round-2
  redesign — round 1's doc-comment register had no mechanical substrate
  for its own checks):** `DeclassId` remains the compile-time gate (the
  raw shim binding is unexported and takes only `DeclassId`, so an
  unregistered declassification is a **compile error**), but the metadata
  lives in `const declassRegister: array[DeclassId, DeclassEntry]` —
  disclosed *width* as a typed field (a verdict bit vs. 64 signature
  bytes — the audit value is how much, not just where), module-doc anchor
  id, rationale, and an optional build-condition. `array[DeclassId, …]`
  makes register completeness itself a compile error (every index must be
  populated — the doc-comment shape had no analogue). Enum doc comments
  stay as one-line human pointers; enum members follow a fixed prefix
  convention (`diX25519ZeroVerdict`-style) settled before the first entry
  lands, since these ids are the citation currency module docs carry.
- **Register checks, with mechanisms (round-2 — round 1 named the checks
  but not how they could exist):** under `-d:selloTaint` the `declassify`
  template additionally bumps a per-id counter recorded via the shim; the
  harness asserts every register entry is exercised, **union-across-the-
  battery** (the battery is multiple target executables; the assertion
  aggregates), skipping entries whose recorded build-condition excludes
  the current configuration (skip-with-notation, not silently green). The
  anchor drift check is a trivial data query over the table (a 10-line
  emitter prints it as TSV): every entry's cited module-doc anchor exists,
  and every sanctioned-disclosure claim in a module doc cites an entry —
  drift mechanically impossible harness→register, mechanically checked
  register→docs. Module docs cite entries by id. These checks run inside
  the taint gate (no separate check name).
- The register's initial enumeration: the x25519/ristretto all-zero
  verdicts, `RistrettoPoint`'s `==` result, `scIsCanonicalCT`'s import
  verdict, the ephemeral identity check, signature bytes, and derived
  public material — `derivePublic`'s public key, `x25519Base`'s outputs,
  `ristrettoScalarmultBase`'s encoding, and `keypair(seed,
  expectedPublic)`'s re-derived public key including its interior vartime
  `==` (sanctioned because public keys are public; the register entry's
  rationale field is where that argument now lives). **Boundary rule
  (round-2):** a register entry records a *sanctioned publication*.
  Secret *outputs* — `X25519Shared`/`RistrettoShared` DH results — are
  never register entries: disclosing them is not sanctioned, and the
  correct tool for the harness's KAT comparison of a secret output is
  harness-side `MAKE_MEM_DEFINED` *after the call returns* (the round-1
  argument against harness-side declassification applies only to interior
  branches; post-return definedness on the harness's own copy is outside
  the library and exactly right). Constructor-only secret types
  (`X25519EphemeralSecret` has no from-bytes route and private fields)
  are tainted via a harness-side cast to their byte representation —
  stated, since it is the one place the harness reaches past the API.
- **CMOV policy (recorded).** Memcheck's error class is "conditional jump
  *or move* depends on uninitialised value(s)": a compiler-synthesized
  CMOV with a tainted condition fails the gate even though CMOV is
  constant-time on the pinned targets. The enforced property is therefore
  *strictly stronger* than no-branch/no-index — no secret-conditioned
  CMOV either. Accepted as the bar (CMOV-on-secret is µarch-sensitive);
  sanctioned cases route through `declassify` like any other disclosure,
  and a CMOV finding is a named triage category in the harness docs, not
  "Valgrind noise."
- **Build pinning.** The taint binary is built with flags identical to the
  dudect harness's (`-d:release`, same C compiler, same image digest) —
  a non-release build false-positives immediately on the debug asserts
  (`geScalarmultBase`'s bit-255 precondition assert branches on the nonce;
  `signDetached`'s re-derivation assert compares vartime). The gate runs
  on **both gcc and clang backends** — both legs are named deliverables of
  the taint CI slice, not an adjective. Honesty clause, disclosed in the
  README evidence table: taint, disasm, and dudect certify separate
  compilations (and the taint one a separate source variant, per above),
  and a source-distributed library's consumers compile yet another — the
  instruments bind to the CI-pinned toolchains, and the README claim says
  so in as many words.
- **Go/no-go criterion (round-2 — "if it cannot be made sound" named no
  observable):** the taint slice's first task runs a toy target before
  any register construction. GO requires both: (i) the masked-select
  chain (`feCMove`/`feCSwap`, a ladder step) on tainted input produces
  **zero** memcheck errors, and (ii) a planted secret-conditioned branch
  on the same toy produces **exactly one** error class with a stack trace
  resolving to the branch. Either half failing = the recorded MSan
  fallback activates, before the register exists.
- **Targets** (asserted against the A7 secret-target register):
  `signDetached`/`derivePublic` (seed tainted), `x25519` both roles +
  `x25519Base` (scalar tainted), `ristrettoScalarmult` both overloads +
  `ristrettoScalarmultBase` (scalar tainted), `ristrettoEncode` and
  `` `==` `` (point coordinates tainted), `ristrettoFromUniformBytes`
  (input tainted), the import paths `toRistrettoStaticSecret` and
  `keypair(seed, expectedPublic)` (import bytes / seed tainted), and the
  SHA-512 core (message tainted, digest declassified for KAT comparison —
  the inverted class whose register entry the schema proof-spike below
  validates) — every dudect carve-out target gets its deterministic
  hearing. **Per-target input-class coverage is part of the definition of
  done:** taint verdicts are per-executed-path, so both verdict arms are
  driven (small-order AND normal peer per x25519 target; matching AND
  mismatching `expectedPublic`; canonical AND non-canonical import
  bytes). **The zero-annotation red→green arc is per-target and repeats
  for every target ever added** (round-2): run the target with no
  declassifications first — the harness MUST error at every documented
  disclosure point; a target producing zero undeclassified errors is
  investigated as **taint washout** (secret definedness silently lost
  upstream), never recorded as a pass. Public-input sampling reuses the
  existing KAT + boundary corpora; the harness doc states the honest
  scope: deterministic per executed path, not per all paths.
- **Wipe paths, re-specified (round-1 correction — the original target was
  vacuous):** wiping stores *defined* zeros, so interior stack wipes (the
  ladder's accumulators, sha512's schedule) are unobservable to memcheck —
  the frames are dead before any check could run. The taint harness checks
  the observable subset only: caller-owned in-place buffers (`wipe.nim`'s
  overload, the role types' `wipe`s, `=destroy`-visible objects) via
  make-undefined-then-check-defined assertions. Interior-frame wipe
  verification remains owned by `test_ct.nim`'s existing scans plus
  review, stated explicitly so the line item cannot imply coverage it
  lacks.

**A2. Disassembly gate.** Stage-4 finding 1 (`feSqrtRatioM1`'s
secret-dependent jumps surviving `-O3`) was caught by a human reading
objdump; `scripts/disasm-gate.sh` automates the class. Round-1 re-specified
the unit of analysis and the resolver; round 2 makes the unit *structural*
and defines the pinned artifact:

- **Unit of analysis: `{.noinline.}` secret-path roots (round-2 hardening
  of round 1's "roots that survive as real symbols").** Round 1 correctly
  rejected per-primitive profiles (the `{.inline.}` helpers have no
  symbol at `-O3`) but left the roots' survival *empirical*: `ladder` and
  sha512 `compress` are module-private funcs with all call sites in their
  own TU — gcc may inline them and leave a stale standalone copy whose
  profile is *not what executes*, the exact false negative round 1
  diagnosed for helpers, now on the gate's own roots, flippable by any
  pinned-image compiler bump. Fix: every enumerated root —
  `signDetached`, `derivePublic`, the x25519 `ladder`, `geScalarmultBase`,
  `geScalarmultCT`, `ristrettoEncode`, `` `==` ``, `feSqrtRatioM1`, and
  sha512 `compress` — carries `{.noinline.}`, joining the existing trio
  `feCMove`/`feCSwap`/`cmovCached`. **This is a deliberate shipped-codegen
  change** (the audited-binary-is-the-shipped-binary property is worth a
  call boundary; the trio set the precedent, and every root is
  coarse-grained enough that the call cost is noise). Each root's pinned
  profile is understood to include all inlined callees' branches (the
  honest artifact); inline-only helpers are audited via their containing
  roots, stated in the baseline's header. `-fno-inline` remains rejected:
  it gates a binary nobody runs.
- **The pinned artifact, defined (round-2 — round 1 never said what a
  "profile" contains, which decides its churn rate):** per root, the
  ordered list of conditional-branch instructions as **address-free
  mnemonics with symbolized context**, plus the count. Address-bearing
  profiles churn on every edit; bare counts miss branch substitutions;
  this shape pins what matters and survives unrelated edits. The resolver
  matches **all clone-suffixed variants** of a root (`-O3` routinely
  emits `.constprop.N`/`.isra.N`/`.cold`/`.part` clones; pinning "the"
  name while a clone executes is a false negative) and fails loud on an
  unrecognized suffix.
- **Resolver: from the nimcache-generated C**, not objdump-symbol regex.
  Nim 2.x mangling (`name__<moduleHash>_<counter>`) churns its counter on
  unrelated edits and renders overload pairs (`x25519` ×2,
  `ristrettoScalarmult` ×2) distinguishable only by opaque suffix; naive
  prefix matching aliases `ristrettoScalarmult` into its `Base`/`Vartime`
  siblings. The nimcache C carries proc-name and `#line` info tying each
  C function to its Nim proc; since overloads are distinguished by
  *definition line*, which moves on any edit above the proc, the resolver
  **re-locates each pinned signature in current Nim source at gate time**
  (a stated resolver step, not an assumption) and then maps
  signature → current line → nimcache C name → mangled symbol.
- The disassembled binary is named: a dedicated `tests/ct_disasm/main.nim`
  built with the same flags as `ct_main`, inside the digest-pinned image
  (the profile is a function of the exact compiler). Baselines are
  **per-backend** (gcc and clang), live under `tests/ct_disasm/expected/`
  (the regenerable-baseline idiom below — whose tool-written header
  records the image digest and compiler versions the pin was generated
  under, so a compiler bump fails first with "stale baseline — regenerate"
  rather than an inexplicable 40-line profile diff), and are regenerated —
  a reviewed diff — on every deliberate image/compiler bump.
- **Division of labor, stated:** the gate sees conditional branches only.
  Secret-indexed loads and secret-dependent indirect jumps (a jump-table
  `case` has zero conditional branches) are invisible to it — those are
  A1's job, on A1's binary. Loop back-edges on public counters are
  expected branches; the pin is the per-root profile. A new conditional
  jump in straight-line CT code fails the gate with the root's name.
  The root list is asserted **⊇ the A7 register's `disasmRoots` union**
  (containment, not equality — the root list legitimately includes
  internal symbols no secret-role-typed export names).

**A3. Coverage with a ratchet.** Unit+property suite built with
`--passC:--coverage --passL:--coverage` and `--lineDir:on` (so gcov's
line records map to `src/sello/*.nim`, not nimcache C files whose
content-derived names churn wholesale), per-test-binary object directories
merged via lcov, `--extract`ed to `src/sello/*`. The baseline
(`tests/coverage/expected/baseline.txt`, regenerable-baseline idiom) pins
**the aggregate percentage AND a per-file floor**, each floored to one
decimal — absorbing the line-level jitter that macro expansion and
Nim-inserted lines produce. **Per-file floors are the round-2 correction
to an overstated claim:** an aggregate-only ratchet enforces "aggregate
coverage is monotone," not "new code arrives tested" — a large well-tested
addition can mask a simultaneous untested one. Per-file floors close the
masking mode for existing files; a *new* file arrives with its own floor
from its first pin. The gate's header and README row state the honest
residual in as many words (monotonicity per file, not per-change diff
coverage; diff-coverage is the recorded future upgrade). The coverage job
runs the randomized property suites under **fixed seeds** (a varying
covered-set flakes a ratchet, and every flake pressures a baseline edit).
The gate fails if any pinned number *drops*; raising is a deliberate
commit. **The down-path is governed too, with the ledger split out of the
regenerable file (round-2 — an in-file justification register inside a
wholesale-regenerated file is nuked by the next `--update`; that was the
curated/regenerable conflation the idiom section below exists to kill):**
a legitimate drop (refactor deleting covered code) is unblocked by a
baseline decrease whose justification lives in a **curated sibling**
(`tests/coverage/expected/justifications.md`); the gate accepts a drop iff
the ledger's newest entry cites the new number. The slice's DoD includes
one deliberate coverage-drop commit shown red through the real CI entry
point, plus a determinism check (build+run twice, identical numbers). No
arbitrary threshold — the ratchet encodes monotone coverage without
retroactive theater. (Mutation testing remains the depth instrument; this
is the breadth instrument it never claimed to be.)

**A4. Platform breadth as test capability.** The suite must pass on
32-bit (`--cpu:i386` cross-build, where the field core's `int64`
intermediates become register pairs), big-endian (s390x via QEMU
user-mode, where every encode/decode byte-order assumption is live), and
**linux/arm64** (round-1 addition: free hosted runners exist, it is the
top deployment ISA after amd64, and it exercises gcc-on-arm64 codegen the
macOS/clang job does not). Any failure found is a genuine bug fixed via
the escalation rule in the Slices preamble — budgeted as real work, not
smoke. The s390x architecture decision is recorded now, not discovered
in-slice: cross-compile (`--cpu:s390x --os:linux` + cross-gcc in the
pinned image) with test binaries run under qemu-user — not the whole
toolchain under emulation — with a pre-authorized fallback scope of
unit+KATs only if property wall-clock proves prohibitive, and an
endianness canary test that fails if the binary is actually little-endian.
Every matrix leg carries a platform-identity canary (see the red-then-green
rule above — the i386 pointer-width assert generalized). Exclusions are as
deliberate as inclusions (see Non-goals: armv7, riscv64, WASM — the latter
flagged unsupported-for-secrets in README, since `private/ct.nim`'s
barrier and `std/sysrand` do not exist there).

**A5. Fuzz campaign continuity.** Mechanism decided (the original draft's
accumulation claim silently contradicted the no-bots non-goal): the
*working* corpus carries run-to-run via the Actions cache/artifact chain —
so nightly campaigns genuinely accumulate — while the *committed* corpus
(`tests/fuzz/corpus/`, small, minimized, reviewed, the Wycheproof-vendoring
precedent) is a periodic human-reviewed snapshot seeding cold starts. The
nightly emits a corpus-delta summary, and the notification channel flags
"uncommitted corpus growth > N nightlies" — the snapshot commit is the one
standing manual duty the no-bots rule imposes, with the staleness canary as
its compensating control (recorded in Non-goals). Crash artifacts upload
from CI. **The fuzz build itself is merge-gated (round-2 — a harness that
only compiles at the nightly is discovered broken nights later, the S07
class verbatim):** the build-smoke check (Part B) compiles the
instrumented external target + driver and runs one iteration on every
push.

**A6. Toolchain canary.** A non-blocking nightly job builds and runs the
suite against Nim devel and latest-stable — and (round-1 extension)
against **newest-gcc and newest-clang**, run *through the disasm gate*:
the C compiler inside the pinned image is at least as load-bearing for the
CT properties (branch materialization, `asm volatile` barrier survival,
`{.noinline.}`) as the Nim version, and a distro compiler bump is the
historically likelier source of a new secret-dependent branch.
**Canary-disasm semantics (round-2 — diffing a new compiler's output
against the pinned backend's baseline differs on benign codegen churn
essentially always, making the leg perpetually red or quietly ignored,
either of which kills it):** each canary compiler keeps its **own rolling
baseline** — the leg regenerates a fresh profile and alerts only on
root-level conditional-branch-count *increases* relative to that same
compiler's previous canary profile, with the first-run bootstrap recorded
as such. A **milpa leg** (round-2) builds milpa@HEAD nightly, so the
resolver every job's integrity routes through has a drift watcher like
every other pin. All compiler pins (Nim + gcc + clang versions, image
digest) are recorded in a committed file. Failures notify, never gate —
the pins are bumped only by deliberate commit. The empirically verified
version-sensitive behaviors (sink occurrence-count analysis, the
negative-compile fixtures, assert stripping) are exactly what the Nim leg
watches.

**A7. Secret-target register.** "Which entry points hold secrets" is one
fact currently enumerated independently by the dudect harness, the taint
harness, and the disasm root list. A new secret-holding API would join one
and silently miss the others, invisibly, because every list stays green.
Round 2 resolves round 1's open disjunction and closes the register's own
silent-miss mode:

- **"Drive from or assert against" resolves to assert-against (round-2 —
  settled empirically against `ct_main.nim`):** each dudect target is
  irreducibly bespoke (four class designs, three input widths, deliberate
  non-entries with recorded rationale); a register that could *generate*
  them would re-encode the harness as data — a worse programming
  language. The instruments stay hand-built; the register is the checked
  fact-set they are asserted complete against. The one legitimate
  drive-from is identity: harness targets derive their printed names from
  register ids, so coverage assertions are set comparisons, not string
  matching.
- **The register carries per-instrument coverage columns — the round-2
  redesign that makes it actually close its gap.** As round 1 left it,
  the only check was membership (exported secret-typed proc ⊆ register);
  a new entry could sit in the register with no dudect target, no taint
  target, no disasm root, every gate green — the original defect rebuilt
  one level up. Now: a `const` table (deliberately the same shape as A1's
  register — they are two columns of one audited fact-set) where each
  entry records its secret-input shape and, per instrument, a coverage
  cell: `direct(name)` | `coveredBy(entry)` | `exempt(rationale)`. Each
  instrument asserts its own column (dudect: every `direct` cell has a
  report; taint: likewise; disasm: the entry's roots appear in the
  baseline's root set — containment direction register→roots ⊆, per A2).
  `coveredBy`/`exempt` make the existing recorded rationales
  (ephemeral-covered-by-static; `ristrettoDecode`-is-public-input)
  first-class data instead of grep-excludes in a shell script. The
  new-secret-proc journey becomes five-touch-*honest*: every touch is
  demanded by a specific named red.
- **Location:** `tests/registers/secret_targets.nim` — validation
  metadata, not shippable library code (`src/sello/` carries effect
  discipline and a surface gate; a test-coverage ledger doesn't belong
  under it). `DeclassId` stays core-resident by necessity (call sites are
  in library code); the cross-link is data — each register entry may list
  the `DeclassId`s its taint run is expected to exercise, which also
  gives the exercise check per-target granularity.
- **Completeness check, honestly scoped (round-2 — "grep over signatures
  is sufficient" was false against the RFC's own target list):** rule 1,
  every exported proc accepting a secret-role type appears in the
  register — with `Keypair` added to the enumerated type list (`sign`
  takes `Keypair`; the flagship secret-holding entry point was invisible
  to the round-1 check). Rule 2, every exported secret-*import*
  constructor (`to*Secret*`/`toSeed*`-pattern procs taking bare arrays —
  the boundary where bytes *become* secrets, which no role type can
  type-match) appears in the register. Raw-byte intakes outside both
  patterns (`ristrettoFromUniformBytes`, sha512's message) are
  register-curated with review as the control — **stated as such, not
  claimed mechanical.** A missing entry under either rule is a red gate.

**A8. API-surface gate.** A generated public-symbol dump of the facade
(`import sello` surface) diffed against committed baselines (the
regenerable-baseline idiom). `test_facade.nim` pins reachability and
effects, but nothing today detects an accidentally *added* export — and
for the deliberately-unexported symbols (`ristrettoUnchecked`,
`scalar.SecretScalar`) a surface leak is a security event, not just a
semver one. Round-2 corrections: **(i) the generator is named work, not a
stock tool** — `src/sello.nim` is pure `import`+`export` re-export
statements, and `nim doc`/`jsondoc` enumerate a module's own declarations,
not re-exported symbols with signatures; the slice's first task is a
verify-first spike choosing between parsing the facade's `export`
statements + resolving signatures via a compiled probe module, or
`nim doc --index` over the transitive modules filtered to re-exported
names — whichever, its blind spots (wildcard export forms, converter
visibility) are recorded with it. **(ii) The surface is build-config-
dependent:** under `-d:selloLibsodium` the facade legitimately widens
(`SodiumInitError`, widened `{.raises.}`), so the gate pins **two**
baselines (plain + `-d:selloLibsodium`), diffed in the respective jobs;
the delta between them becomes itself a pinned, reviewed fact — and the
libsodium adapter is exactly where FFI symbols could bleed through, so
the flag-gated surface is the one it would be worst to leave unwatched.
The project has litigated its surface symbol-by-symbol twice; this makes
that litigation mechanically standing.

**A9. Nightly memcheck.** Plain, untainted Valgrind memcheck over the
unit suite: uninitialized reads and invalid accesses are the class ASan
cannot see (and the class MSan was declined over), the Valgrind setup cost
is already paid by A1, and the ~20-50× slowdown is nightly-shaped. TSan is
a recorded non-goal with the reason named: the codebase's sole concurrency
is `backend_sodium`'s `std/atomics` once-guard.

### Part B — CI structure (grill decisions 2–4, 6–7)

**The build-path invariant (round-1 addition — the original draft never
reconciled CI against the podman-wrapped local scripts, and a bare CI
checkout cannot even compile: `nim.cfg` is gitignored and milpa-generated).**
Every CI job's run step is exactly one `scripts/` invocation — CI is never
a snowflake build path, which is round-2 finding 25's lesson one level up.
Linux jobs run inside `container:` pinned by digest and call the committed
scripts in a new `SELLO_IN_CONTAINER=1` mode that skips the podman wrapper
and host preflight (one code path, two entrypoints; **the in-container
branch is audited OS-portable — no Linux-isms — as part of its own DoD**,
so the macOS/Windows jobs run the same scripts natively; on Windows the
execution model is stated: run steps use `shell: bash` (Git Bash) and the
scripts ARE the entry point — no PowerShell snowflake steps). `ct.sh`'s
host-side preflight banner is explicitly assigned to the host side of the
split (the timing tier needs it; CI compile-smoke doesn't). A tiny
checked-in `scripts/ci-setup.sh` writes the zero-dep `nim.cfg`
(`--path:"src"`) on bare checkouts — note the core zero-dep jobs need no
milpa at all.

**The gates manifest is a data file (round-2 — round 1 specified bash in
slice 1 and then applied the one-source-across-consumers lesson to a
different list in a later slice; the manifest has more consumers and the
stronger case):** `scripts/lib/gates.txt`, one line per gate:
`check-name  script-invocation` — the two-column schema from day one,
because the second column is `merge-gate.sh`'s interface and the first is
the ruleset's, and the file is also the previously-unstated binding
between check names (a stable public interface) and gate scripts.
Consumers: (i) `scripts/merge-gate.sh` runs the required set locally —
with a **subset mode** (gate names as arguments) and an honest help-text
claim (the linux set; macOS/Windows legs are hosted-only residuals) —
so the maintainer can always run what CI runs; (ii)
`scripts/ruleset-apply.sh` **generates** the ruleset's required-check
array from the manifest's name column (generation deletes one of the
three pairwise drift checks outright); (iii) the drift check asserts
workflow job list == manifest (the workflow YAML stays hand-written —
jobs are heterogeneous, and generating YAML means building a templater
with no customer — so this one pairwise check remains, honestly). Every
job carries an explicit `name:` equal to its manifest check-name, and
`matrix:` is not used for required jobs (round-2 — ruleset required
checks match *check-run names*, which matrix-expand; a fixed no-matrix
naming convention is the simplest model that cannot diverge from what
the ruleset engine sees). The fan-in-aggregate alternative (one required
check `needs:`-ing everything) was considered and declined, recorded in
Non-goals. No `scripts/gate.sh <name>` dispatcher — a name→script map
over an already-clean per-script surface is shallow indirection.

**The regenerable-baseline idiom is code, not convention (round-2 — three
gates independently transcribing a prose contract is the finding-25
failure mode verbatim):** a shared `scripts/lib/baseline.sh`
(`baseline_check`, `baseline_update`) implements the contract once:
location `tests/<gate>/expected/`; failure shape = print the diff, print
the exact regeneration command (read from the pin's header), exit
nonzero; `--update` rewrites the pin — and **hard-fails when `CI` is
set** (regeneration is by definition a local deliberate act; without the
guard, a compromised action could run the gate with `--update` and
convert the pin into a self-approving no-op). `baseline_update` writes
the header itself: kind (regenerable), generator, regeneration command,
and the image digest + compiler versions the pin was generated under
(load-bearing for A2's bump journey). A `merge-gate.sh
--update-baselines` convenience regenerates all pins in one invocation.
This idiom is distinct from **curated** artifacts (the mutation catalog;
A3's justification ledger): hand-written, never machine-regenerated —
the original draft's conflation of the two rituals invited hand-editing
a disasm profile or auto-regenerating the mutant catalog, both wrong.
Each pin's file header says which kind it is — written by the tool for
regenerable pins, by hand for curated ones. Vocabulary, fixed (round-2):
these are **baselines** (one noun — "expectations"/"pins" retired);
"register" is reserved for checked artifacts with a drift check (the
DeclassId register, the secret-target register); A3's down-path artifact
is a **ledger**; A5's Wycheproof-vendoring reference is a **precedent**.

**milpa in CI (resolved 2026-08-23 — verified, not assumed; integrity
hole closed in round 2):** `milpa`, `proptest` (repo since renamed
`nelli` — the redirect resolves; the canonical URL is pinned at
implementation), `nim-z3`, and `softlink` are all public;
`ghcr.io/coreyleavitt/nim:2.2.10` is anonymously pullable. CI installs
milpa pinned at a recorded commit, **built from that commit inside the
pinned container** (milpa publishes no release artifact; the install
mechanics are a named slice deliverable, not a line). **Round-2
correction — the property-suite dependency chain was a mutable-branch
supply-chain hole inside required gates:** `milpa.kdl` pins proptest at
`ref="main"` and property jobs *skip* `milpa verify` (milpa 0.0.1 has no
`--features` flag on verify), so the code that executes in required jobs
(property suites, fuzz driver, symex) floated with no integrity check —
"trust our transcripts" relocated into the one dependency left. **This
RFC mandates the repo change:** `milpa.kdl` pins proptest (and its
transitives, as milpa's resolution allows) by **commit SHA**, and the
property jobs' CI step asserts the fetched commit equals the committed
expected SHA (dag-sha256 identity where milpa exposes it) — the verify
skip stays (tool limitation, recorded), but the assertion replaces what
verify would have checked. Core jobs run plain `milpa fetch` +
`milpa verify` (zero-feature — verify is meaningful there); property
jobs run `milpa fetch --features proptest` + the SHA assertion. **The
property-suite jobs assert the proptest skip banner is ABSENT from the
run log — a silent skip is a red check, not a quietly weaker suite**;
the macOS/Windows jobs assert it PRESENT (the expected state there).

**Merge gate** (one workflow, push-triggered on all branches **except the
`evidence` branch** — `branches-ignore: [evidence]`, because the orphan
evidence branch has no source tree and every publication push would burn
a guaranteed-red full battery; this is a *branch* exclusion, compatible
with the no-*path*-filter rule below since required checks only matter
where the ruleset evaluates them, on pushes to `main`): linux/amd64
unit+property suite on gcc AND clang backends; linux/arm64 unit+property;
macOS-arm64 and windows/MinGW-gcc unit suite (proptest-skip loud and
asserted; vcc is explicitly unsupported, the `asm volatile` barrier rules
it out); `--cpu:i386` 32-bit; ASan/UBSan build of the unit suite;
libsodium differential (`test-libsodium.sh` in `sello-dev`); mutation
(full catalog); bmc (all symex files `sxUnsat`); taint CT gate (A1, gcc +
clang); disasm gate (A2); coverage ratchet (A3); API-surface gate (A8);
**build-smoke** (round-2: compiles the fuzz external target + driver and
runs one iteration, compiles `ct_main` and the taint/disasm binaries —
the harnesses that otherwise first compile at a nightly or a manual run;
red demo: a planted compile error); **policy-lint** (round-2: actionlint
plus assertions that every `uses:` is SHA-pinned, no `continue-on-error`
on required jobs, a `permissions` block is present, and `container:`
digests match the committed pin file — workflow *content* drift as a red
check, not a review hope); check-readme; validation-map check;
ruleset-sync; milpa-lock verify. Operational policy:

- `concurrency:` per-branch with cancel-in-progress — only the branch
  head ever needs green in the fast-forward model, so superseded runs are
  cancelled, and that is the whole cost policy. Runbook note (round-2):
  cancelled check runs on a superseded SHA block its fast-forward
  (non-success is non-success); recovery is re-running the workflow on
  that SHA, or fast-forwarding the newer head — not re-pushing.
- **Required checks are unconditional — no path filters, ever.** A
  filtered-out required check never reports and blocks the push (a known
  GitHub footgun); docs-only commits run the full battery, and
  concurrency-cancel absorbs the cost.
- **Check names are a stable public interface** — they are ruleset keys
  and README-table rows, bound to scripts by the gates manifest. A rename
  is a deliberate two-step (add new, retire old, manifest + regenerated
  ruleset JSON in the same commit pair), documented in CLAUDE.md.
- Infra failures (ghcr pull, runner provisioning) are distinguished from
  test failures: retry the former, never the latter.
- bmc's CI kill-timeout is calibrated from measured hosted-runner runs
  (Z3 queries can hang; hosted variance can push a query past a
  local-machine-calibrated limit). A timeout is triaged — retry once;
  twice is investigated as a solver regression — never green-washed.
- Wall-clock budget: the merge gate targets ≤ its longest matrix leg,
  aiming ≤15 min end-to-end — **flagged as probably already broken by
  mutation (round-2): 553s measured locally × typical 2–4× hosted-runner
  slowdown on this compile-heavy workload is 20–35 min.** The
  mutation/bmc slice's DoD measures real hosted times, records them in
  Ordering & risks, and makes the placement decision then. **The
  pre-authorized fallback is re-specified (round-2 — "requiring them on
  main-targeting branches only" is mechanically meaningless in a
  push-triggered no-PR model: there is no "target," and a check that
  runs only on main pushes can never satisfy a ruleset that evaluates at
  push time):** heavy gates run on a documented branch-name pattern
  (`rfc-*`/`release-*` — the only fast-forward-eligible branches, stated
  as policy), so their check runs exist on any SHA that can legally
  arrive at main.

**CI supply chain (round-1 addition; round-2 closes the workflow-content
and update-ritual gaps):** all third-party actions pinned by commit SHA;
workflow-level least-privilege `permissions` (default `contents: read`);
no cross-branch cache trust — images pull by digest, and the Actions cache
is used only for the fuzz working corpus, keyed so non-main branches
cannot seed main-consumed entries. **The pin-refresh ritual is named
(round-2 — SHA pins with no update path go stale forever, and the
Non-goals decline bots):** Dependabot is enabled for actions updates as a
**recorded, scoped exception** to the no-bots rule — it *proposes* PRs,
never merges; every update lands as a human-reviewed commit through the
full gate, which is the no-bots rule's actual substance (no
auto-*committing*). **The trust root is recorded (round-2):** everything
above the ruleset — ruleset edits, runner registration, ghcr push, repo
settings — resolves to the owner account; the security-posture line
(hardware-key 2FA, PAT inventory and scopes for ghcr push,
registration-credential custody) lives beside the runner-custody line as
one auditable paragraph. **Branch workflow definitions are the remaining
green-wash vector, closed structurally (round-2):** required checks are
name-keyed and a branch push runs *that branch's* workflow copy — a
gutted job body keeping its name produces green checks and ruleset-sync
(names only) passes. Mitigation: a **push ruleset restricting
`.github/workflows/**`, `.github/rulesets/**`, and
`scripts/lib/gates.txt`** so edits to the enforcement machinery force the
same loud ruleset-edit ritual the escape hatch uses (mechanics verified
against live GitHub at implementation; if push-rule path restriction
proves unavailable, the residual is recorded honestly instead) — plus the
policy-lint check above for content drift below that threshold. The
`Containerfile`'s `FROM` is pinned by digest (a mutable tag is "trust our
transcripts" one layer down), the base image's own build source (repo +
Containerfile) is publicly documented, and the digest lives in a
committed file so every bump is a reviewed diff. **`sello-dev` drift
model, re-specified (round-2 — "rebuild and compare digests" is
infeasible: container builds are not reproducible, so the rebuilt digest
never matches and the check is permanently red):** the pin file records
the pair (Containerfile content hash, published image digest); CI fails
if the Containerfile hash changed without a digest bump — checkable, and
it closes the same hole (a Containerfile edit silently testing the old
image).

**Contribution lane (round-1 addition; round-2 schedules it — it
previously existed in prose and no slice, while calling ambiguity "the
only unacceptable option"):** a `pull_request` trigger runs the cheap
hosted subset (unit suites, check-readme) under the "require approval
for **all** outside collaborators" setting (the non-default one —
GitHub's default approves first-timers only); **the approval setting
flips at go-public, in the go-public slice's checklist, because the
moment the repo is public a fork PR can add a workflow file and the
approval gate is the control** — it cannot wait for the runner slice;
the self-hosted runner is never targeted by PR events; the full gate
runs when the maintainer re-pushes the branch; CONTRIBUTING documents
exactly this and lands in the same slice. The lane's own DoD includes a
fork-PR-held-for-approval demonstration.

**Nightly** (scheduled, non-blocking; release qualification keys on an
enumerated subset — fuzz, s390x, memcheck, cranked properties —
**explicitly excluding the toolchain canary**, whose never-gate contract
the original draft accidentally violated by requiring "latest nightly
green"): long fuzz with persisted corpus (A5), s390x big-endian (A4), the
toolchain canary (A6, in its **own workflow** — round-2, so the nightly
badge never presents advisory canary state as failure), property tests at
cranked example counts (the crank factor is specified and recorded when
the job lands, not left as an adjective), and untainted memcheck (A9).
**Nightly budget (round-2 — the merge gate got a budget and the nightly
got none, against a 6-hour per-job limit that a qemu property suite or
20-50× memcheck could plausibly hit):** nightly jobs run as parallel
independent jobs, each under its own limit; the nightly slices record
measured per-job times; a job *timeout* is distinguished from a job
*failure* in the notification (a 6h kill looks like a finding otherwise).
**Notification mechanism:** a failure step opens/updates a pinned GitHub
issue — publicly visible, self-documenting, immune to email-settings
drift; the notification slice's DoD includes one forced failure
demonstrably producing the notification (earlier nightly slices state
their canaries fail-the-job-only until the notification wiring lands).
GitHub's 60-day scheduled-workflow auto-disable is recorded in Ordering &
risks with its mitigation.

**Timing tier** (grill #1, #3): the dedicated Ryzen 5 3500U as a
self-hosted runner — quiet-box configuration is part of the slice (boost
disabled, frequency pinned at/below the 2.1 GHz base so throttling is
physically impossible, `performance` governor, SMT off, isolated core, IRQ
steering, nothing co-scheduled) — plus the affinity plumbing, specified
concretely (round-2 — "taskset on the invocation" under-specifies a
podman-wrapped process tree): **`podman run --cpuset-cpus=<isolated>`
inside `ct.sh`'s invocation plus `CPUAffinity` on the runner's systemd
service unit** (two config surfaces, both named), and the preflight
banner **asserts the effective affinity mask** alongside its existing
governor/co-tenant checks — an isolated core nothing is pinned to is idle
decoration. The runner invokes `scripts/ct.sh` directly on the host; the
harness's own podman container IS the per-job isolation (stated — no
nested containers). Workflow triggers: schedule (weekly) and
`workflow_dispatch` ONLY — the original draft's release-tag trigger is
removed (a tag-triggered run races the release workflow's own freshness
check; the ritual is dispatch-before-tag when the window is stale). Never
`pull_request`, never branch pushes. Runner hardening, rewritten for what
a **user-owned** repo can actually enforce (workflow-restricted runner
groups are an organization feature): ephemeral registration
(deregistered after each job); "require approval for all outside
collaborators" (flipped at go-public, per the contribution lane); fork
pushes run in the fork's context without upstream runners; the residual
attack is a fork PR *adding* a workflow file targeting the runner labels,
which runs only on approval — **the approval click is the load-bearing
control, recorded as such, and demonstrated (round-2): the runner slice's
DoD includes a test-account fork PR adding a runner-targeting workflow,
shown held for approval and not executing before it.** **The
"fresh environment per job" claim is deleted (round-2 — it was false):
ephemeral registration deregisters the runner; it does not reset a
bare-metal host.** An approved malicious workflow executes on the timing
box and can persist beyond its job — poison the podman image store, plant
a bias in future timing evidence; secretless-host limits credential
theft, not evidence integrity. Recorded honestly as the residual, with
the approval click as its only control and evidence-poisoning named as
the consequence; per-job VM isolation was considered and declined for now
(revisitable — see Non-goals). The timing workflow's `GITHUB_TOKEN` is
read-only and the runner host is secretless; registration-credential
custody is covered by the trust-root paragraph above. Migrating to an
org to get true workflow-scoping was considered and declined (recorded;
revisitable). A CI concurrency group makes a running battery exclusive on
the box. **Degraded mode:** the box is the RFC's only physical dependency
and hardware death is a *when* — the provisioning checklist is written
box-agnostic for re-provisioning, and a release may proceed on stale
timing evidence only through an **explicit stale-accept input on the
release workflow that machine-checks the `timing-evidence: stale`
notation is present in the release-notes body (round-2 — the notation
was previously an unenforced convention, i.e. a crowned-property
violation on the RFC's most contested instrument); the stale-accept
input is the only path past a red freshness gate.** Quiet weakening of
the freshness gate is not an option. **Evidence durability:** raw
results (compressed percentile summaries + t-tables, keyed by SHA + run
id) are published to an orphan `evidence` branch as part of the
deliberate post-run commit ritual — the same human-reviewed register as
`docs/ct-results.md`, which cites the permanent artifact; the release
freshness gate checks the durable record, **and (round-2) additionally
asserts `docs/ct-results.md` cites the run-id/SHA of the
evidence-branch artifact satisfying the window** — otherwise the public
carve-out record the README links can go permanently stale against an
adjudication the evidence branch already recorded. **The evidence branch
is itself protected (round-2 — an unprotected branch is durable only by
convention):** a second branch ruleset blocks force-push and deletion on
`evidence`, and the first-publication DoD includes the rejected
force-push demonstration. Hosted CI runs the dudect harness in
compile-smoke mode only — no verdict authority, stated in the workflow
name (this job is part of the build-smoke check above).

**Rulesets** (grill #4; plural as of round 2): required status checks =
the merge-gate check names; NO pull-request requirement; force-push and
deletion blocked on `main`; **a tag ruleset blocking tag update/deletion
(round-2 — "tag immutability" was asserted as the integrity story while
nothing enforced it: GitHub tags are freely force-updatable without
one); and the `evidence` branch ruleset above.** Bypass list EMPTY
(round-1 correction — the original "bypass = repo admin" made the entire
gate advisory for the only person who pushes: a listed admin bypasses
required checks silently on ordinary `git push`). The emergency hatch is
editing the ruleset itself — loud, auditable, and reviewable, because
the rulesets are **committed JSON definitions** (`.github/rulesets/`)
applied by an idempotent `scripts/ruleset-apply.sh` (`gh api` PUT, one
file per ruleset, the required-check array generated from the gates
manifest): every check-adding slice edits the manifest in the same
commit as the workflow change and regenerates. **Ruleset-sync
(strengthened in round 2 — a names-only comparison left the empty
bypass list and force-push flags unenforced after day 1, silently
regressing round-1 finding 3 the first time a "temporary" live edit was
never reverted):** the check asserts the **full canonicalized live
ruleset equals the committed JSON — names, bypass list, enforcement
flags, all rulesets** — plus the name-equality leg against the manifest
and workflow job list. A live edit turns the next push red until
reverted or committed; committing IS the recorded-in-history
requirement, enforced instead of hoped. **The hatch no longer deadlocks
(round-2 — as round 1 left it, dropping a flaky required check from the
live ruleset turned ruleset-sync itself red, blocking the very push the
hatch exists to unblock; discovery scheduled for 2 a.m. during a real
outage):** the manifest supports a committed **waiver entry** (check
name, reason, expiry SHA-or-date) that ruleset-sync validates instead of
failing on — the hatch is a one-file reviewed commit with built-in
expiry, legitimate only for infra outage, never for a genuinely red
gate. The ruleset slice's DoD exercises the waiver path end-to-end and
demonstrates a live-edit red, in addition to the rejected-then-accepted
push pair. The merge flow: slices land on the RFC branch, CI greens the
branch head, `git push origin <branch>:main` fast-forwards main to a SHA
whose checks already passed (the ruleset engine's acceptance of
branch-run check runs on the arriving SHA is in the verify-against-live-
GitHub list). A locally created merge commit is a new SHA and gets
rejected — merges are fast-forward by policy.

**Release workflow** (tag-triggered): verifies (i) the tagged SHA's merge
gate is green; (ii) the qualification nightly subset is green on a SHA
that is an ancestor of the tag **with no diff under `src/sello/` since
(round-2 — round 1 added exactly this scoping to the timing gate and
left the nightly gate with the vulnerable ancestry-only form: a tag cut
the day after a core merge would qualify on fuzz/s390x/memcheck evidence
that never saw the released code; when the latest nightly predates a
core diff, the ritual is `workflow_dispatch`-ing the qualification
subset on the candidate SHA)**; (iii) a timing-tier run exists within
the freshness window (14 days) whose SHA is an ancestor of the tag with
no diff under `src/sello/` since, checked against the durable
evidence-branch record including the `docs/ct-results.md` citation
assert (above). Then: version-consistency check — nimble version ==
CHANGELOG heading == tag name **== `milpa.kdl`'s version field
(round-2: a third copy the check missed)** — and a **clean-environment
consumer test (round-2 — the release IS the tag for a source library,
and the resolution path was otherwise never tested end-to-end): a
post-tag job in a bare container runs `nimble install` against the tag
and compiles a trivial `import sello` consumer, the zero-dependency
claim's only end-to-end proof.** The release artifact is defined: a
**signed tag** (enforced immutable by the tag ruleset) plus a
checksummed source tarball attached to the GitHub release. **The
release gate's red demos are per-clause (round-2 — one stale-window red
cannot witness four independently-wired clauses, and a miswired
ancestry check passes releases on evidence that doesn't cover the code
while the one demonstrated red keeps "proving" the workflow can fail):**
five scratch tags — stale window; in-window non-ancestor timing SHA;
in-window ancestor with a subsequent `src/sello/` diff; missing nightly
qualification; version mismatch. The registry PR lands once the first
release passes this gate.

### The evidence story (README, SECURITY.md)

README gains a validation section with live badges and a hand-curated
table mapping every claim in the validation bar to the mechanism that
enforces it — hand-curated because the prose is the value, but **its
load-bearing columns are mechanically checked**. **Round-2 corrections:
(i) rows carry a category — required-check / nightly / manual-ritual —
with per-category assertions** (required rows: job exists in the
workflows AND the ruleset's required set; nightly rows: the nightly job
exists; ritual rows: the named freshness canary exists) — the round-1
check as written ("every job name in the table is in the required set")
would have gone red on the honest table or forced omitting exactly the
rows the validation-bar dichotomy exists to label. **(ii) Badge
semantics are pinned:** every badge URL carries `?branch=main` (an
unpinned badge reflects the latest run on any branch), the canary
workflow is separate and unbadged (advisory state never renders as
public failure), and the badge-URL branch pin joins the validation-map
check. **(iii) Until the table and its drift check land (they co-land,
late), the README's go-public validation section makes no job-name
claims** — prose pointing at the existing `docs/` evidence corpus plus
the first badge only, so no unchecked claims sit published in the gap.
Each row links claim → enforcing mechanism → gate script → the honest
carve-out record in `docs/`. CT claims are scoped in as many words:
"verified on the CI-pinned toolchains (gcc X, clang Y, image digest Z)"
— the consumer-compiles-their-own residual is disclosed, not elided. The
platform-support claim becomes exactly the CI matrix, in those words
(grill #5), including the WASM unsupported-for-secrets note. SECURITY.md
is updated at go-public (it currently instructs public-issue disclosure,
written for a private repo): GitHub private vulnerability reporting
enabled, intake path rewritten, scope section pointed at the evidence
map.

## Slices

Each one `/tdd`-sized; infra slices verify by running the thing, and every
gate slice's DoD includes its red-path demonstration plus, for matrix
legs, the platform-identity canary (the red-then-green rule above), plus
the per-slice doc rule. **Escalation rule, standing for all
matrix/platform slices:** a surfaced core-arithmetic bug closes the infra
slice red and spawns its own fix slice with regression test plus the full
affected-gate battery (mutation anchors, dudect, symex scope as
applicable) — never fixed inline under an infra label. *(Round-1
restructuring: 12 → 24. Round-2 restructuring: 24 → 32 — slice 1 was
three slices, taint part 2 was three, release/close-out was three; the
ruleset now precedes go-public; the contribution lane, build-smoke, and
several orphaned deliverables got homes.)*

**Phase 0 — bootstrap (repo still private; private-repo free minutes cover
this, and the workflow gets debugged out of public view):**

1. **CI build path, minimal.** `SELLO_IN_CONTAINER=1` mode in `test.sh`
   (the in-container branch audited OS-portable as part of this DoD),
   `scripts/ci-setup.sh`, `.github/workflows/merge-gate.yml` with ONE
   linux/amd64 gcc unit job (container by digest, one script invocation —
   the core zero-dep job needs no milpa at all); per-branch concurrency
   group; actions SHA-pinned and least-privilege `permissions` from the
   first line. DoD: a green run AND a deliberate red run on a scratch
   branch — fail-ability through the real entry point (enforcement
   arrives with slice 4; stated honestly).
2. **milpa-in-CI + remaining bootstrap jobs.** milpa install from the
   pinned commit built inside the pinned container (mechanics recorded);
   `milpa.kdl` re-pinned: proptest by commit SHA (the mandated repo
   change) + the fetched-commit CI assertion; the property-suite job with
   skip-banner-ABSENT assertion; the check-readme job (its own
   `SELLO_IN_CONTAINER` retrofit — `check-readme.sh` currently hardcodes
   podman and skips the preflight lib).
3. **Gates manifest + local runner.** `scripts/lib/gates.txt` (two-column
   schema from day one), `scripts/merge-gate.sh` with subset mode +
   honest help text, the workflow-vs-manifest drift check.
4. **Rulesets + branch model (still private).** Committed
   `.github/rulesets/` (main + `evidence` + tag rulesets) + idempotent
   `scripts/ruleset-apply.sh` generating required checks from the
   manifest; empty bypass list; full-JSON ruleset-sync into the required
   set; the waiver mechanism; the push ruleset on
   `.github/workflows/**`/rulesets/manifest (mechanics verified live,
   residual recorded if unavailable); the policy-lint check. DoD:
   rejected-then-accepted push pair, a live-edit red, and the waiver path
   exercised end-to-end. Grind mechanics, the check-rename two-step, and
   the no-path-filter rule added to CLAUDE.md (slices commit to RFC
   branches henceforth).
5. **Go public.** One-time history secret/PII scan (gitleaks-class)
   before the flip; GitHub private vulnerability reporting enabled +
   SECURITY.md intake rewritten; **"require approval for all outside
   collaborators" flipped and verified**; CONTRIBUTING landed; minimal
   README validation section (prose pointing at the existing `docs/`
   evidence corpus + the first badge with `?branch=main` — NO job-name
   claims until the table + drift check land); the trust-root/security-
   posture paragraph recorded; ghcr anonymous-pull re-verified from a
   logged-out session; flip visibility; the already-green,
   already-enforced workflow re-runs green under public/anonymous
   conditions.
6. **Contribution lane.** The `pull_request` cheap-subset workflow;
   CONTRIBUTING cross-checked against it; DoD: a test-account fork PR
   demonstrably held for approval (and not executing before it).

**Phase 1 — matrix (7 precedes its consumers; 8–13 independent after 7;
every leg: identity canary + demonstrated red):**

7. **Image consolidation (`sello-dev`; the base image is untouched —
   round-2 placement decision, since the base image's build source lives
   outside this repo and is only *documented* here).** Enumerate every
   package the whole RFC needs (32-bit multilib, valgrind, lcov,
   binutils/objdump, s390x cross-gcc, qemu-user-static — availability in
   the zypper base verified here) **plus verify clang is present**
   (round-2: four consumers and it was missing from the list); publish
   `sello-dev` to ghcr by digest (the push mechanism + credentials are
   named deliverables — it has only ever been built locally); convert
   `test-libsodium.sh`/`bmc.sh` from build-if-missing to pull-by-digest;
   the (Containerfile-hash, digest) drift check; **verify the base
   image's arch manifest for arm64** — if amd64-only, the arm64 job's
   image story (multi-arch build vs. direct Nim install) is decided and
   recorded here, before slice 11 discovers it; record image size +
   cold-pull time, with a two-image split (lean core / heavy gates)
   pre-authorized if pull cost breaks the wall-clock budget. One pin
   event, not one per consumer slice.
8. **clang-backend job.**
9. **ASan/UBSan job.** Red: a planted overflow in a scratch test goes red
   (proving `--passC` actually reached the C compile).
10. **`--cpu:i386` job.** Identity canary: pointers are 4 bytes.
11. **linux/arm64 job.** (Image story per slice 7's decision.)
12. **macOS-arm64 job.** Nim install mechanism named and version-pinned
    (no digest-pinnable container on macOS runners — the pin story is
    explicit); proptest-skip asserted PRESENT in the log. *(Round-2: the
    former unit-test-file-list-to-data-file rider is dropped — under the
    build-path invariant every OS runs `scripts/test.sh` via bash, so no
    YAML step ever reads the file list and the sourced bash array already
    is the single source; if a YAML consumer ever emerges, the conversion
    becomes its own slice.)*
13. **Windows/MinGW job.** Run steps use `shell: bash` (Git Bash); the
    scripts are the entry point — no PowerShell snowflake. MinGW pinned
    (runner-bundled MinGW drifts — pin story explicit); vcc-unsupported
    recorded in README; proptest-skip asserted PRESENT.

**Phase 2 — heavy deterministic gates:**

14. **libsodium differential job.** `sello-dev` by digest; the interop
    suite's skip paths made fatal under a CI env var; red demo: the suite
    run with libsodium absent shown red.
15. **Mutation + bmc jobs.** Red: one deliberate surviving mutant and one
    deliberately broken symex query each shown red in CI; bmc CI timeout
    calibrated from measured hosted runs + the timeout-triage policy
    recorded; **DoD: measured per-job hosted times recorded in Ordering &
    risks and the heavy-gate placement decision made (the branch-pattern
    fallback if the ≤15-min claim is broken, as expected).**
16. **Build-smoke check.** Fuzz external target + driver compiled and run
    one iteration; `ct_main` compiled (the hosted dudect compile-smoke,
    named in the workflow as no-verdict-authority); extended in phase 3
    to the taint/disasm binaries. Red: planted compile error.
17. **Coverage ratchet (A3).** `scripts/lib/baseline.sh` lands here (its
    interface proof-spiked against the disasm gate's needs — the
    digest-bearing header — before freezing on coverage alone);
    instrumented build mechanics (`--lineDir:on`, per-binary object dirs,
    lcov merge/extract, fixed seeds), aggregate + per-file baseline from
    the current suite's real numbers; the justification ledger as curated
    sibling; CI job. Red: a deliberate coverage-drop commit through the
    real entry point; determinism check (two runs, identical numbers).
18. **API-surface gate (A8).** FIRST task: the generator verify-first
    spike (the facade is pure re-exports; no stock tool dumps its
    effective surface — mechanism chosen and its blind spots recorded).
    Then: dual baselines (plain + `-d:selloLibsodium`), CI jobs; red: a
    scratch extra export shown red in both configs.

**Phase 3 — CT instruments (19→20→21→22→23 is a chain):**

19. **Taint CT harness (A1) — mechanism.** FIRST task: the two-sided
    go/no-go (zero errors on the tainted masked-select toy AND exactly
    one resolvable error on a planted branch; either failing activates
    the MSan fallback here, before any register exists). Then: the shim
    TU (`src/sello/private/taint_shim.c`, conditional `{.compile.}`,
    by-address contract) + `private/taint.nim` (`declassify`
    buffer/scalar overloads + the `DeclassId` enum + `const` register
    table + exercise counters); targets `signDetached` + `x25519` static
    via the zero-annotation red→green arc (run undeclassified, the
    harness MUST error at every documented disclosure point; converting
    those errors into cited register entries IS the register's
    construction and the red demonstration). A planted secret-dependent
    branch lands as a permanent negative fixture. **DoD includes the
    schema proof-spike (round-2): the register entries for the sha512
    tainted-message/declassified-digest case and one import-path reject
    arm are written on paper against the frozen schema before this slice
    closes — if they don't fit, the schema changes while two entries
    exist instead of twelve.**
20. **Secret-target register (A7).** `tests/registers/secret_targets.nim`
    with per-instrument coverage columns (`direct`/`coveredBy`/`exempt`);
    the two-rule completeness check (role types incl. `Keypair`;
    secret-import constructors) with the honest curated-annex scope
    statement; **the existing dudect harness retrofitted to
    assert-against the register** (round-2 — previously the one A7
    consumer no slice implemented, in the instrument A7 was motivated
    by), red: a register entry deliberately absent from the dudect list
    shown red; the disasm root-list containment assert prepared for
    slice 23.
21. **Taint targets.** Every remaining target: the remaining dudect
    carve-out targets (`` ristretto.`==` ``, `sha512` compress), the
    ristretto scalarmults and encode/map, `derivePublic`, `x25519Base` +
    ephemeral role (harness-side cast route, stated), the import paths,
    wipe paths per the re-specified scope; both verdict arms per target;
    the per-target zero-annotation arc + taint-washout rule; `declassify`
    call sites + module-doc citations land together per module (the
    mechanical ~5-module sweep, each module one commit).
22. **Taint CI + doc drift.** The doc-anchor drift check; taint CI jobs
    on BOTH gcc and clang backends into the required set + manifest +
    regenerated ruleset; taint binaries added to build-smoke.
23. **Disasm gate (A2).** `{.noinline.}` on every root (the recorded
    shipped-codegen change, with the standard full-battery evidence
    refresh for a `src/sello/` touch); nimcache-C resolver with the
    source-relocate step and clone-suffix handling; root-granularity
    per-backend baselines (defined artifact shape) under
    `tests/ct_disasm/expected/`; CI job into the required set; verified
    red against a deliberately reintroduced feSqrtRatioM1-class branch
    (the stage-4 finding as its own regression test); root list asserted
    ⊇ the A7 register's roots; disasm binaries added to build-smoke.

**Phase 4 — nightly, timing, release:**

24. **Nightly part 1 — fuzz continuity (A5).** Corpus carry mechanism
    (cache/artifact chain), snapshot-commit ritual documented, corpus
    staleness canary (fails-the-job-only until slice 26 wires
    notifications — stated); crash-artifact upload; measured job time
    recorded.
25. **Nightly part 2 — s390x (A4).** Cross-toolchain per the recorded
    architecture decision; endianness canary red-path; property-count
    fallback pre-authorized; measured job time recorded.
26. **Nightly part 3 — canaries + notifications.** Nim + C-compiler
    canary (A6) in its own unbadged workflow, incl. the rolling-baseline
    disasm leg semantics and the milpa@HEAD leg; cranked properties
    (crank factor recorded); untainted memcheck (A9, measured);
    pinned-issue notification wiring with DoD = one forced failure
    demonstrably producing the notification, timeout-vs-failure
    distinguished; the nightly badge (`?branch=main`).
27. **Timing tier part 1 — provisioning (Corey-owned, physical).**
    Quiet-box checklist executed and committed *box-agnostic* (it is the
    re-provisioning document); verifiable output: `ct.sh`'s preflight
    banner reporting performance governor, zero co-tenants, low load,
    **and the effective cpuset/affinity mask**.
28. **Timing tier part 2 — runner + workflow.** Ephemeral registration +
    the hardening set as specified (approval-for-all verified,
    read-only token, secretless host; the host-persistence residual
    recorded in as many words); `timing.yml` (weekly + dispatch,
    exclusivity group); `--cpuset-cpus` + runner-service `CPUAffinity`
    plumbing; runner→`ct.sh` direct execution model; **the
    timing-freshness canary moves here (round-2 — it queries this
    workflow, which did not exist at its former slice)**: nightly
    `gh api` for the latest successful timing run, notify when older
    than 10 days. DoD includes the fork-PR-targeting-the-runner
    held-for-approval demonstration.
29. **Timing tier part 3 — first quiet-box battery + adjudication.** Full
    battery run; every dudect carve-out target's verdict re-adjudicated
    in `docs/ct-results.md` (retired or confirmed — either is a result)
    citing the evidence-branch artifact; the evidence-branch publication
    ritual exercised for the first time, including the rejected
    force-push demonstration against its ruleset.
30. **Release workflow.** Ancestry-and-no-src-diff freshness on BOTH the
    nightly-qualification and timing clauses; the stale-accept input
    machine-checking the `timing-evidence: stale` notation; signed tag +
    tag-ruleset verification; version-consistency (nimble == CHANGELOG ==
    tag == `milpa.kdl`); the clean-environment `nimble install` +
    consumer-compile job. Red: **one per clause** — five scratch tags
    (stale window; non-ancestor timing SHA; ancestor-with-subsequent-core-
    diff; missing nightly qualification; version mismatch).
31. **README evidence table + drift check.** The categorized
    validation-map table (required-check / nightly / manual-ritual rows
    with per-category assertions), badge-URL branch-pin check, platform
    claim as the exact CI matrix, WASM unsupported-for-secrets note, CT
    claims compiler-scoped in as many words. Red: a fabricated table row
    shown red.
32. **Registry + close-out.** nimble registry PR (after the first release
    passes slice 30's gate); CLAUDE.md/CHANGELOG final sweep; version
    bump; close-out audit of every validation-bar line against the
    definition-of-done dichotomy.

## Ordering & risks

- Slices 1–4 bootstrap the model everything else assumes; the ruleset
  (4) precedes go-public (5) so enforcement exists before the evidence
  story is public. 7 precedes 8–23's image consumers; **8–18 are
  independent of each other after 7; 19→20→21→22→23 is a chain (round-2
  correction — the round-1 "independent after 4" claim was false for the
  taint/disasm sequence)**; 24–26 are independent; 27–29 are the only
  physical-world dependency and can slide without blocking anything
  except 30's timing-freshness gate — which the recorded degraded mode
  covers if the box is the blocker.
- **Merge-gate wall clock:** mutation at 553s local × 2–4× hosted was
  projected at 20–35 min against the ≤15-min aim — slice 15 measured the
  real hosted cost instead of trusting the projection, and the
  projection did not hold: `mutation` (84-mutant catalog, cold nimcache,
  the full checkout+milpa+proptest+catalog run) completed in 475s
  (7m55s) on a real GitHub-hosted runner, and `bmc-symex` (all four Z3
  symex proof files) completed in ~165s (two consistent runs: 164s and
  167s) — both comfortably inside the 15-minute budget with real margin
  to spare. Both land as PLAIN, UNCONDITIONAL required checks; neither
  the matrix-sharded `mutation-{i}of{N}` remedy nor the branch-pattern
  (`rfc-*`/`release-*`-only) fallback was needed. The sharding mechanism
  (`tests/mutation/run_mutation.py --shard i/N`, a deterministic
  round-robin catalog partition) was still built and is kept in reserve,
  unwired from any job, for a future catalog-growth push that revisits
  this budget — see CLAUDE.md's own "Mutation + bmc jobs" CI paragraph
  and the handoff doc's slice 15 entry for the full run-id record.
- **Disasm-gate brittleness:** Nim's symbol mangling is convention, not
  contract — mitigated by resolving from nimcache C per-signature with
  the at-gate-time source-relocate step, clone-suffix matching, and
  fail-loud on unknown suffixes; the pins live under the
  regenerable-baseline idiom with digest-bearing headers.
- **Valgrind + ORC / masking arithmetic:** expected clean (Valgrind runs
  the uninstrumented binary), but slice 19's first task is the two-sided
  empirical go/no-go, with the MSan fallback as the recorded decision
  point — before the register is built, not after.
- **QEMU s390x wall-clock:** cross-compile + qemu-user bounds it; the
  unit suite + KATs are the non-negotiable core, property fallback
  pre-authorized. Nightly jobs run parallel and individually measured
  against the 6-hour limit, timeout distinguished from failure.
  **MEASURED (RFC-005 slice 25, 2026-08-30):** the property fallback was
  genuinely needed, not merely pre-authorized-and-unused -- a single
  property suite file run under `qemu-s390x` had not completed after
  9m30s of real CPU time (killed at that point), versus ~82s for the
  ENTIRE 14-file unit/KAT suite under the identical cross-compile+qemu
  setup. The `s390x` nightly job (unit+KAT scope only) completed in
  1m54s on real hosted CI (run `33316911555`, job id `99271931270`),
  comfortably inside its `timeout-minutes: 20` budget and nowhere near
  the 6-hour hosted-job limit. See the handoff doc's slice 25 entry for
  the full record.
- **Valgrind memcheck wall-clock (A9):** the RFC's own "~20-50x
  slowdown is nightly-shaped" estimate, re-measured for real rather than
  assumed (RFC-005 slice 25/A9, 2026-08-30) -- the full 14-file unit
  suite under `valgrind --tool=memcheck` ran clean (0 errors on every
  binary) in 5m34s locally and 5m17s on real hosted CI (run
  `33316911555`, job id `99271931310`), well inside the `memcheck`
  job's own `timeout-minutes: 30` budget.
- **Hosted-runner variance:** none of the merge gate is timing-sensitive
  by design; dudect authority lives on the 3500U only. bmc's Z3-hang
  failure mode is the exception and carries its own timeout/triage
  policy.
- **Grind latency:** the full battery runs on every push; per-branch
  cancel-in-progress plus slice 15's measured-budget decision guard the
  feedback loop, with the branch-pattern fallback pre-authorized for
  mutation/bmc if needed. Cancelled-run recovery is a re-run on the SHA,
  not a re-push (recorded in the merge-gate policy).
- **GitHub 60-day scheduled-workflow auto-disable:** recorded; the
  release cadence plus ordinary push activity resets it, and the
  timing-freshness canary catches the dead-schedule case regardless of
  cause.
- **Proptest repo rename (`proptest` → `nelli`):** the redirect works
  today; the commit-SHA pin (slice 2) plus the canonical URL mean a
  future rename-reuse cannot silently retarget or drift the dependency.
- **Push-ruleset path restriction** (the workflow-protection mechanism)
  is verified against live GitHub at slice 4; if unavailable, the
  residual (branch workflow copies are editable without a loud ritual)
  is recorded honestly and policy-lint remains the compensating control.
- **Carve-out risk:** the quiet box may *confirm* rather than retire a
  carve-out — a valid outcome producing a stronger record, not a failure
  of the slice.

## Non-goals (considered and declined)

- **CI-authoritative dudect verdicts on hosted runners** — the environment
  is the pathological version of the shared-host problem already
  documented.
- **MSan-based taint** — declined for now (clang-backend + full-TU
  instrumentation cost); the recorded fallback, with slice 19's go/no-go
  as its activation point.
- **Whole-input-space binary CT verification (binsec/rel, ct-verif)** —
  relational symbolic execution would upgrade A1's per-executed-path
  verdicts to all-paths proofs, and it is the on-brand next rung above
  this RFC's taint+disasm+dudect triad. Declined for this RFC on tooling
  maturity/cost; recorded here so the decline is visible, revisitable as
  a future nightly experiment (the `symex_reduce`
  attempted-and-inconclusive register shows how to hold such a tool
  honestly).
- **A fan-in aggregate required check** (one required check `needs:`-ing
  every real job) — considered in round 2: it would collapse the
  check-rename two-step and most of ruleset-sync's surface. Declined:
  per-gate check names are the evidence story's public interface (README
  table rows, per-claim traceability), and collapsing them to one
  opaque check trades away exactly the public per-claim visibility this
  RFC exists to create. Revisitable if check-name ceremony proves
  costlier than expected.
- **A fixed coverage threshold** — ratchet only; thresholds invite
  theater. (Diff-coverage is the recorded future upgrade beyond the
  per-file floors.)
- **TSan** — the codebase's sole concurrency is `backend_sodium`'s
  `std/atomics` once-guard; nothing for it to test.
- **Windows vcc** — the `asm volatile` barrier rules it out; MinGW is the
  supported Windows toolchain, documented.
- **A supported-Nim-version range** — one pinned version + canary;
  "supports latest stable" claims arrive only when the canary has
  history.
- **armv7, riscv64** — i386 covers the ILP32/register-pair class and
  s390x the byte-order class; all secret and wire buffers are
  byte-granular fixed arrays, so armv7's stricter alignment adds no live
  assumption (verified at implementation time, one line in the platform
  doc). Nothing stops a port; CI claims only what it runs.
- **WASM** — not merely untested but **unsupported-for-secrets**, stated
  in README: `private/ct.nim`'s barrier and `std/sysrand` do not exist
  there, so the wipe and keygen guarantees are void; the verify-only path
  may well compile, and the README says exactly that much.
- **arm64 disasm profiles** — the linux/arm64 job runs the suite, but CT
  branch-profile evidence (A2) is amd64-only for now; the README claim
  says so. Revisitable once the amd64 gate has history.
- **Org migration for runner workflow-scoping** — the user-owned-repo
  hardening set above is judged sufficient with the approval click as the
  named (and demonstrated) load-bearing control; revisitable if
  contribution volume grows.
- **Per-job VM isolation for the timing runner** — would restore the
  fresh-environment property ephemeral registration alone does not
  provide; declined for now on provisioning complexity for a
  single-maintainer box, with the host-persistence residual recorded in
  the timing-tier section instead of claimed away. Revisitable.
- **SBOM / SLSA provenance attestation** — the core dependency count is
  zero, NOTICE carries vendored-corpus provenance, and the image chain is
  digest-pinned with documented build source; a full attestation
  framework adds ceremony without closing a live gap. Signed tags (the
  release integrity story, enforced by the tag ruleset) are in scope.
- **BSDs, Android/iOS, bare-metal targets** — nothing stops a port; CI
  claims only what it runs.
- **Auto-committing bots** (results docs, coverage baselines, corpus
  snapshots, evidence branch) — every committed artifact stays a
  deliberate human-reviewed change. Two recorded, scoped clarifications:
  the fuzz-corpus snapshot is the one standing manual duty this creates
  (named in A5 with its staleness canary as the compensating control),
  and Dependabot *proposing* action-pin updates is compatible with this
  rule (it never commits; every update is a human-reviewed merge through
  the full gate) — recorded as the pin-refresh ritual, not an exception
  swallowed silently.

## Open questions

- None. (Round-1 resolutions: ghcr base-image anonymous pullability
  verified 2026-08-23; `milpa`/`proptest`(`nelli`)/`nim-z3`/`softlink`
  repo visibility verified public 2026-08-23; RFC-006 ordering resolved
  by shipment; the CI-milpa design is recorded in Part B. Round-2
  resolutions: A7's drive-from/assert-against disjunction settled;
  the fan-in alternative considered and declined; the slice-9 data-file
  rider dropped for having no consumer under the build-path invariant.)

## Round-1 review record (2026-08-23)

Five-lens architect review (depth, breadth, design/ergonomics,
feasibility, liveness); 77 raw findings consolidated. Headline
corrections:

1. **A1's harness-only declassification could not work** (sanctioned
   branches are interior to library code) → in-core no-op `declassify`
   template + first-class `DeclassId` register, BoringSSL pattern. The
   no-FFI/zero-cost invariants hold for all normal builds.
2. **A2's per-primitive symbol profiles could not survive inlining** →
   out-of-line secret-path roots, nimcache-C signature-keyed resolver,
   per-backend expectations.
3. **Bypass-list = admin voided the entire gate** for the only pusher →
   empty bypass list; committed ruleset JSON + apply script + ruleset-sync
   drift check.
4. **"Registered to this one workflow" is an org-only feature** → runner
   hardening rewritten around controls a user-owned repo actually has.
5. **Release/nightly/timing gates had silent-death modes** (canary
   red blocks release; artifacts expire; dead schedule unnoticed; no
   ancestry on freshness) → subset-keyed qualification, evidence branch,
   freshness canary, ancestry-scoped windows, degraded mode.
6. **CI build path was unreconciled with the podman-wrapped scripts** (a
   bare checkout cannot compile) → the build-path invariant,
   `SELLO_IN_CONTAINER` mode, gates manifest, run-what-CI-runs.
7. **CT claims were unscoped by compiler** → gates bound to pinned
   gcc+clang, C-compiler canary leg, README scoping language.
8. Slices restructured 12 → 24 (blast-radius splits; go-public isolated
   after CI works and preceded by a history scan + SECURITY.md fix;
   red-then-green DoDs throughout; one image-consolidation slice).
9. New capabilities added: secret-target register (A7), API-surface gate
   (A8), nightly memcheck (A9), linux/arm64, contribution lane, supply-
   chain hygiene, regenerable-baseline idiom.
10. Stale-against-RFC-006 text swept (dated amendment): three carve-outs,
    unconditional SHA-512 targets, zero-dep build path.

## Round-2 review record (2026-08-23)

Second five-lens review of the round-1-amended document; ~65 raw findings
consolidated. Headline corrections:

1. **The escape hatch deadlocked against ruleset-sync** (dropping a flaky
   check from the live ruleset turned the sync check red, blocking the
   unblocking push) → committed waiver mechanism with expiry; and
   ruleset-sync upgraded from names-only to **full live-vs-committed-JSON
   equality**, without which the empty bypass list and force-push flags
   were unenforced after day 1 — round-1 finding 3's silent regression
   path.
2. **The property-suite dependency chain was a supply-chain hole inside
   required gates** (proptest at `ref="main"`, verify skipped) →
   commit-SHA pin in `milpa.kdl` (mandated repo change) + CI
   fetched-commit assertion + a milpa canary leg; milpa's own install
   mechanics specified.
3. **A7 only checked register membership** — the instrument edges (dudect
   /taint/disasm coverage) were silently optional, rebuilding the defect
   it was created to kill → per-instrument coverage columns
   (`direct`/`coveredBy`/`exempt`), `Keypair` + import-constructor rules
   in the completeness check, the dudect retrofit given a slice, and the
   register relocated to `tests/registers/`.
4. **A2's roots' out-of-line survival was empirical** (intra-TU inlining
   could leave a stale audited copy — the gate's own false-negative mode)
   → `{.noinline.}` on every root, a recorded shipped-codegen change; the
   pinned artifact defined (address-free branch mnemonics + count);
   clone-suffix handling; the A6 disasm-canary leg given implementable
   semantics (per-compiler rolling baseline).
5. **A1's "magic asm, not a linked call" over-promised** — the taint
   build calls a shim TU and is a third *source* variant → invariant
   restated honestly, shim placed (`src/sello/private/`, conditional
   compile), by-address contract recorded, secret *outputs* excluded
   from the register (harness-side post-return definedness), two-sided
   go/no-go, per-target red arc + taint-washout rule; the DeclassId
   register became a `const` table with compile-forced completeness and
   an actual exercise mechanism.
6. **Green-but-inert modes in the liveness story**: the crowned property
   restated (first true at end of phase 0, ruleset now BEFORE
   go-public); contribution lane, build-smoke, dudect retrofit, and the
   budget decision point were producer orphans — all assigned slices;
   the stale-release notation and ct-results.md citation became
   machine-checked; matrix legs got identity canaries + reds; the
   release gate got one red per clause.
7. **Branch workflow definitions could green-wash required checks**
   (gutted job body, same name) → push ruleset on the enforcement paths
   + policy-lint check; tag ruleset and `evidence`-branch ruleset added
   (immutability was asserted, not enforced); account trust root and
   Dependabot pin-refresh ritual recorded.
8. **Infeasibilities fixed**: the image drift check (rebuild-and-compare
   can never match — replaced by Containerfile-hash/digest pairing);
   image placement decided (all in `sello-dev`, base untouched); clang
   added to the enumeration; arm64 image verification named; the
   mutation/bmc fallback re-specified for the no-PR model
   (branch-pattern); nightly budget + 6h-limit handling; A8's generator
   named as a verify-first spike with dual build-config baselines;
   Windows Git-Bash execution model stated; slice-9 data-file rider
   dropped (no consumer exists under the build-path invariant).
9. **Design consolidation**: gates manifest as a two-column data file
   with the ruleset required-check array *generated* from it; the
   regenerable-baseline idiom became shared code (`baseline.sh`) with a
   CI-guarded `--update` and tool-written digest-bearing headers; the
   coverage ratchet gained per-file floors and an honest claim; the
   justification ledger split out of the regenerable file; vocabulary
   fixed (baseline/register/ledger/precedent); the fan-in aggregate
   check considered and declined.
10. Slices restructured 24 → 32 (slice 1, taint part 2, and
    release/close-out each split three ways; ruleset before go-public;
    contribution lane, build-smoke, and the timing-freshness canary
    given correct homes; per-slice doc rule added).
