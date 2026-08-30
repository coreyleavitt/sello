# Contributing to sello

sello is a solo-maintained, security-sensitive cryptography library. That
shapes everything below: the bar for a change to land is higher than for
most Nim libraries, review bandwidth is one person's, and the parts of
the codebase that hold a secret (signing, keygen, X25519, ristretto255
secret-role types) get more scrutiny than the parts that don't (`verify`).
None of this is meant to discourage contributions -- issues, small fixes,
and well-scoped features are welcome -- just to set honest expectations
before you invest time in a patch.

## The validation bar

sello does not ask you to trust a claim of correctness; it publishes the
evidence. `CLAUDE.md`'s "The validation bar" section is the authoritative
description of what every change is expected to clear: RFC 8032/RFC 7748
vector conformance, Wycheproof adversarial vectors, a dudect-style timing
harness for every secret-holding target, curated mutation testing,
differential testing against libsodium, property-based testing, coverage-
guided fuzzing, and (for the recoding/masking/reduction primitives) a
machine-checked Z3 proof. The evidence itself lives in `docs/`:
`ct-results.md` and `mutation-results.md` are the standing records, and
`docs/rfc-001-signing.md` through `docs/rfc-006-sha512.md` are the design
docs each slice of that evidence was built against. A change that touches
`src/sello/` is expected to extend the relevant piece of this corpus, not
just add a unit test.

## Running the gates locally

`scripts/merge-gate.sh` runs the same required checks CI runs, reading
`scripts/lib/gates.txt` (the single source of truth for what "the gates"
are):

```sh
milpa fetch                    # populate _deps/, write nim.cfg (run once, and again after editing milpa.kdl)
scripts/merge-gate.sh          # every required gate
scripts/merge-gate.sh unit-linux-amd64-gcc   # a single named gate
scripts/merge-gate.sh --help   # exact gate list, prerequisites, scope caveats
```

Every gate script is dual-mode: run on a bare host it wraps itself in the
pinned `ghcr.io/coreyleavitt/nim` container automatically (needs `podman`
on `PATH`); there is nothing container-specific a contributor has to set
up by hand. Property-based tests need the optional `proptest` dependency
(`milpa fetch --features proptest`) -- without it, `scripts/test.sh` still
passes and prints a loud skip banner instead of failing.

Beyond the merge-gate set, `scripts/ct.sh` (timing harness),
`scripts/fuzz.sh` (coverage-guided fuzzing), `scripts/mutation.sh`
(curated mutation testing), and `scripts/bmc.sh` (Z3 proofs) are not part
of the required push-time gate -- they are longer-running or
statistical/open-ended rather than a fixed pass/fail suite -- but changes
to the secret-holding paths are expected to be checked against the
relevant ones before you open a PR (see "Crypto contributions" below).

## Branch model

`main` is fast-forward-only and protected by required status checks:
direct pushes are rejected by GitHub's ruleset enforcement, and a merge
commit is rejected too (a fast-forward is the only accepted update). This
is the maintainer's own workflow, not something a contributor needs to
reproduce -- it's documented here so a `git push` failure against `main`
that you might hit while experimenting against a personal fork remote
doesn't read as broken tooling.

For contributors, the practical flow is the ordinary GitHub one: fork,
branch, commit, open a pull request against `main`. The maintainer
rebases or fast-forwards the accepted change through the branch model
described above; you don't need to.

## Fork PR CI

Opening a pull request against `main` runs `.github/workflows/pr-checks.yml`
(the `pull_request` trigger) -- a cheap hosted subset of the full merge
gate: the unit suite and the README-fence check (`pr-unit-linux-amd64-gcc`
and `pr-check-readme` -- named distinctly from the six push-triggered
required checks on purpose, since they mean something different: a
non-required pre-screen, not a required gate; see
`.github/workflows/pr-checks.yml`'s own header comment). It deliberately
does **not** run the property suite or the repo-governance checks
(`gates-manifest-sync`, `ruleset-sync`, `policy-lint`) -- those stay on
the push-triggered `merge-gate.yml` only. Neither `pr-checks.yml` job is a
GitHub required status check and neither enters
`scripts/lib/gates.txt` -- they gate nothing on `main` directly; they are
a fast signal on the PR itself.

The repository's fork-PR-workflow-run approval policy requires maintainer
approval for all outside contributors before their workflow runs execute
(`all_external_contributors`) -- if you're not the maintainer or an
existing collaborator, GitHub holds your PR's checks as "waiting for
approval" until the maintainer clicks approve; nothing runs unattended.
Once approved, `pr-unit-linux-amd64-gcc` and `pr-check-readme` run and
report directly on your PR.

Passing `pr-checks.yml` is a good sign but is not the bar your change
merges on. The real bar is the full `merge-gate.yml` battery --
`scripts/lib/gates.txt` is the source of truth for exactly which checks
that is and how many (do not trust a hardcoded number here, including
this sentence's own past versions -- run `scripts/merge-gate.sh --help`
or `grep -vc '^#\|^$' scripts/lib/gates.txt` for the current count;
`scripts/merge-gate.sh` above runs the identical set locally) -- the
maintainer runs that by pushing your accepted branch (or a rebase of it)
directly to a branch in this repository, which triggers the full gate via
`push`. That full gate, green, is what actually has to pass before your
change reaches `main`; the fork PR's cheap checks are a pre-screen, not a
replacement for it.

## Crypto contributions specifically

Changes to `src/sello/` (as opposed to docs, scripts, or CI config) are
held to a higher bar than "it compiles and the existing tests still
pass":

- **New behavior needs new tests, and new tests need a citable source.**
  A new code path with no RFC vector, no Wycheproof/CAVP vector, or no
  independent oracle to check it against is the kind of change this
  project's whole validation story exists to avoid.
- **Constant-time discipline is not optional on the secret-holding
  paths.** If your change touches signing, keygen, X25519, or a
  ristretto255 secret-role type, it needs to preserve the existing
  invariants: `{.push checks: off.}` cores, secrets confined to
  fixed-size stack arrays (never `seq`/`string`), every secret-dependent
  selection done by arithmetic masking rather than a branch, and
  `private/ct.wipe` (or the `secretHooks`/`secretHooksMoveOnly`
  templates) discipline for every secret and secret-derived intermediate.
  See CLAUDE.md's "The load-bearing design decision: VERIFY is split from
  SIGN" section before touching any of this.
- **A secret-path change needs the full affected-gate battery, not just
  `scripts/test.sh`.** In practice that means: the dudect timing harness
  (`scripts/ct.sh`) for any target you touched or added, the mutation
  suite (`scripts/mutation.sh`) if you touched arithmetic/boundary logic
  it already covers or should cover, and the Z3 proofs (`scripts/bmc.sh`)
  if you touched masking, recoding, or carry-propagation logic in
  `field.nim`/`scalar.nim`. Say in the PR description which of these you
  ran and what the result was; if you couldn't run one (e.g. no access to
  a quiet host for timing), say so instead of omitting it silently.
- **Several of the instruments above now run as required merge-gate
  checks rather than maintainer-only rituals (RFC-005) -- a secret-path
  PR will hit these automatically once it reaches `main`, but running
  them yourself first (via `scripts/merge-gate.sh <name>`) catches a
  regression before the maintainer's own push does:**
  - `taint-ct-linux-amd64-gcc`/`taint-ct-linux-amd64-clang`
    (`scripts/ct-taint.sh [--cc clang]`) -- a deterministic, per-executed-
    path Valgrind-memcheck proof that a secret-dependent selection never
    reaches a branch or an index, on BOTH the gcc and clang backends (the
    clang leg matters: this project has one real, fixed finding where gcc
    and clang compiled the identical masked-select source into different
    code, one of them branching on the secret -- see CLAUDE.md's
    `private/ct.nim` entry). A new secret-holding target needs a new
    entry in `tests/registers/secret_targets.nim` (see A7 below) before
    this instrument can cover it.
  - `disasm-gate-gcc`/`disasm-gate-clang` (`scripts/disasm-gate.sh [--cc
    clang]`) -- a per-root conditional-branch-count profile compared
    against a committed baseline; a new CT-critical function generally
    needs `{.noinline.}` (so it resolves to one disassemblable C symbol)
    and a baseline entry.
  - `secret-target-register` (`scripts/secret-target-register-check.sh`)
    -- a completeness check: every exported proc accepting a secret-role
    type, and every exported secret-import constructor, needs an entry in
    `tests/registers/secret_targets.nim` recording which instrument(s)
    cover it.
  - `coverage-ratchet` (`scripts/coverage.sh`) -- per-file line coverage
    must not regress; a legitimate drop needs an entry in
    `tests/coverage/expected/justifications.md`.
  - `mutation` (`scripts/mutation.sh`) -- the full curated catalog now
    runs on every push (not maintainer-only); see the paragraph above for
    when to add to it.
  See CLAUDE.md's CI section (the "Taint CT jobs," "Disasm gate (A2),"
  "Secret-target register," and "Coverage ratchet" paragraphs) for the
  full mechanism of each.
- **`verify`-only changes carry no constant-time obligation** (it touches
  no secret) but do still need RFC/Wycheproof-level scrutiny -- it's the
  part of the library everyone's trust rests on most directly.

## Commit messages

Professional tone, no emojis, no mention of AI/agent tooling regardless
of what wrote the patch. Describe the change and its rationale (the
"why", not a restatement of the diff); match the terse, direct register
of the existing log (`git log --oneline`) rather than a conventional-
commits prefix scheme. No `Co-Authored-By` bot trailers.

## Conduct

Be direct and be respectful; this is a small, solo-maintained project,
not a venue for a heavier code-of-conduct process. Reports of a security
vulnerability go through [`SECURITY.md`](SECURITY.md), not a public
issue.
