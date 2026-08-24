# RFC-005 (validation infrastructure) — handoff

- **Stage:** 3 (tdd slice grind)   •   **Round:** n/a
- **Resume:** `/loop /tdd rfc-005 til done`
- Stage 3 opened 2026-08-24 (sign-off = grind launch). Slices 1–3 committed
  to `main` directly. Slice 4 (DONE 2026-08-24) established the branch
  model and turned on enforcement -- as of slice 4's own close-out commit,
  `main` rejects direct pushes; slices 5+ land on `rfc-*` branches, green
  CI, then `git push origin <branch>:main` to fast-forward. Slice 5 (DONE
  2026-08-24) closed out the remaining go-public deliverables (see the
  Slices list and Open forks below). Slice 6 (DONE 2026-08-24 except one
  Corey-owned leg, see Open forks) landed the `pull_request` contribution
  lane. Slice 7 (DONE 2026-08-24 except the ghcr push itself, see Open
  forks -- everything credential-independent is complete, including a
  real red-then-green demo of the new drift check) closed out image
  consolidation. Slice 8 (DONE 2026-08-24) landed the clang-backend
  matrix leg -- `unit-linux-amd64-clang`/`property-linux-amd64-clang`,
  the `--cc <name>` backend-selection mechanism in `scripts/test.sh`/
  `scripts/ci-property.sh`, and `scripts/lib/toolchain-canary.sh`'s
  platform-identity canary, with a real red-then-green demo (canary
  inversion) through the actual new check names. Eight required jobs
  total. Next up: slice 9 (ASan/UBSan job).

## Slices (32 — see RFC "Slices" section for full DoDs)

Phase 0 — bootstrap (private repo):
- [x] 1. CI build path, minimal — DONE 2026-08-24. Code `c3ca4cc` + exec-bit
      fix `a07a1ae`; green run 32703201531 (SKIPPED banner confirmed in CI
      log); red demo run 32703306363 (planted test_field failure), scratch
      branch deleted. TRAP for all future slices: `core.filemode=false` on
      this working copy (FS reports 777) — new scripts MUST get
      `git update-index --chmod=+x` explicitly or CI fails with exit 126.
- [x] 2. milpa-in-CI + property/check-readme jobs (proptest SHA pin, skip-banner-ABSENT assert) --
      DONE 2026-08-24. Code `5f0f312`. milpa itself pinned at commit
      `6efed43311e415a0ea3b5a2867a2d40581e69e15` (its own main HEAD as of
      this slice), built from source inside the pinned Nim image via an
      isolated venv (`scripts/lib/milpa-install.sh` -- milpa has no
      release artifact; mechanics verified empirically: the image ships
      python3 + stdlib `venv` but no `uv`). `milpa.kdl`'s `proptest` dep
      re-pinned from `ref="main"` to commit SHA
      `ec7a405c354e79c30717b0692ad548bc8bee7414` at the canonical
      (post-rename) `nelli` URL; `nim-z3`'s own `ref="main"` closed the
      same way via a top-level `overrides` block pinned at
      `7d9abdaefecce2e4175354a73b047e2548dd2a19`. **Discovered mid-slice,
      not anticipated by the RFC text:** the upstream rename
      proptest -> nelli was two renames, not one -- the GitHub repo
      (which the RFC's "pin the canonical URL" note already covered) AND
      the Nim source tree itself (`src/proptest.nim` -> `src/nelli.nim`,
      commit `785307c`, 2026-08-13). Every sello test file does
      `import proptest`, so the pinned commit is deliberately the newest
      one BEFORE that source-tree rename, not `nelli`'s current main HEAD
      -- judged a confident, documented, in-scope call (not a blocker):
      following the rename would demand a project-wide
      `import proptest` -> `import nelli` sweep, its own deliberate
      migration RFC-005 slice 2 has no mandate to do. Recorded in
      `milpa.kdl`'s own comments and CLAUDE.md's "RFC-005 slice 2 re-pin"
      paragraph; a future slice/RFC owns the eventual nelli migration.
      `scripts/ci-property.sh` runs `milpa fetch --features proptest
      --locked` (milpa's own built-in resolve-vs-committed-lockfile
      assertion, identity + provenance -- the replacement for
      `milpa verify`, which milpa 0.0.1 cannot run against a non-default
      feature selection) then asserts the proptest SKIPPED banner is
      absent from the test log. `scripts/check-readme.sh` retrofitted
      with the same `SELLO_IN_CONTAINER` split `scripts/test.sh` already
      had. Green run 32705557309 (check-readme 31s, unit-linux-amd64-gcc
      1m4s, property-linux-amd64-gcc 9m40s -- the property suite's real
      wall-clock cost, driven by `test_properties_x25519`/`_ristretto`'s
      heavy random-sample counts on a DEBUG build); red demo run
      32706465557 on scratch branch `rfc-005-slice2-red-demo` (deleted
      after, both locally and on origin) -- one push, two independent
      reds through the real entry point: `property-linux-amd64-gcc` red
      via `RES-LOCKED-DRIFT` (drifted `milpa.kdl` ref, unchanged
      `milpa.lock`) and `check-readme` red via a planted undeclared-
      routine call in a README fence; `unit-linux-amd64-gcc` stayed green
      on the same push, confirming the reds are targeted, not incidental.
      CLAUDE.md updated in the same commit as the code (per-slice doc
      rule).
- [x] 3. Gates manifest + local runner -- DONE 2026-08-24. Code `bb77b05`
      + fix `9cbab5c`. `scripts/lib/gates.txt` (two-column check-name /
      script-invocation data file, not executable), `scripts/lib/gates.sh`
      (shared parser, `load_gates()`), `scripts/merge-gate.sh` (full or
      named-subset local runner, honest linux-only help text, per-gate
      PASS/FAIL/wall-time summary, does not stop at the first failure),
      `scripts/gates-manifest-check.sh` (the new `gates-manifest-sync`
      job -- light awk scan over the workflow YAML, cross-checks its own
      job-key and `name:`-value extractions against each other before
      trusting either, fails loud on a parse surprise). Manifest's
      script-invocation column is the PLAIN script name (no
      `SELLO_IN_CONTAINER=1`, no `ci-setup.sh` chaining) for all four
      gates -- required retrofitting `scripts/ci-property.sh` with the
      same dual-mode split `test.sh`/`check-readme.sh` already had (host:
      wraps itself in podman and recurses with SELLO_IN_CONTAINER=1,
      byte-identical to the CI job, not a parallel host-side
      reimplementation). `gates-manifest-sync` runs on a plain
      `ubuntu-latest` runner, no container (pure text scan, no toolchain
      dependency) -- still exactly one `scripts/` invocation.
      **Bug found and fixed via the first green-run attempt, not
      anticipated in the plan:** the dual-mode retrofit made
      `ci-property.sh` check `SELLO_IN_CONTAINER`, but
      `merge-gate.yml`'s `property-linux-amd64-gcc` job never set that
      variable (the pre-retrofit script assumed container context
      unconditionally, so it was never needed) -- the job's own
      `container:` field puts the step inside the pinned image already,
      but the script's new host branch doesn't know that without the
      variable, so it tried to `podman run` from inside a container with
      no podman binary (exit 127). Fixed by prefixing that job's run
      step with `SELLO_IN_CONTAINER=1`, matching the other two container
      jobs' existing pattern. First push (`bb77b05`, run `32710672161`)
      caught this red for real; the fix (`9cbab5c`) went green on run
      `32710858177` (all four jobs: gates-manifest-sync 3s,
      unit-linux-amd64-gcc 57s, property-linux-amd64-gcc 9m32s,
      check-readme 20s). Red demo on scratch branch
      `rfc-005-slice3-red-demo` (commit `b2cacfe`, run `32711805163`):
      removed `check-readme` from `gates.txt` with no matching workflow
      edit -- `gates-manifest-sync` failed exactly as designed
      ("DRIFT -- job(s) present in .github/workflows/merge-gate.yml with
      no scripts/lib/gates.txt entry: check-readme", exit 1) while the
      other three jobs stayed green (unit 55s, property 9m31s,
      check-readme 23s); branch deleted locally and on origin after
      (confirmed via `gh api .../branches/rfc-005-slice3-red-demo` ->
      404). Local validation: `scripts/merge-gate.sh` full battery
      8m50.973s wall clock (unit 48s / property 473s / check-readme 10s /
      gates-manifest-sync 0s); subset invocations
      (`unit-linux-amd64-gcc`, `check-readme gates-manifest-sync`,
      `property-linux-amd64-gcc` standalone) also run and pass
      individually. CLAUDE.md updated in the same commits as the code
      (per-slice doc rule).
      TRAP for slice 4+ (ruleset-apply.sh, mutation.sh/other future
      manifest entries): a script's CI `run:` step and its
      `scripts/lib/gates.txt` entry are NOT required to be textually
      identical (the manifest column is deliberately the plain,
      host-runnable form) -- but whatever the workflow step's own env/
      flags are, they must still make the script behave correctly INSIDE
      the container it already carries a `container:` field for. Adding
      or changing a script's dual-mode check is a two-file edit (the
      script AND the workflow step that invokes it), not just the
      script -- this slice's own red/fix pair is the concrete example to
      point at.
- [x] 4. Rulesets + branch model -- DONE 2026-08-24. Code `8957c2d` (direct
      to `main`, pre-enforcement, still allowed): `.github/rulesets/{main,
      evidence,tags}.json` (committed, reviewed ruleset bodies -- `main`'s
      `required_status_checks` array committed EMPTY by design, spliced
      in from `scripts/lib/gates.txt` at use time), `scripts/ruleset-
      apply.sh` (maintainer-run, dry-run-by-default, `--apply` to mutate;
      `PUT` not `PATCH` for updates -- `PATCH .../rulesets/{id}` verified
      live to be a bare 404, not documented anywhere, found by testing
      before writing the real script), `scripts/ruleset-sync-check.sh`
      (new `ruleset-sync` CI check, three legs: workflow-vs-gates.txt,
      main-required-checks-vs-gates.txt waiver-adjusted, full canonical
      live-vs-committed diff over all three rulesets -- plain `curl`+`jq`,
      no `gh` dependency, live ruleset reads confirmed to work
      anonymously against this public repo before the script was
      written), the waiver hatch (`scripts/lib/waivers.txt`/`.sh`, ISO-
      date or commit-SHA expiry, fail-safe-active on an unverifiable SHA),
      `scripts/policy-lint.sh` (new `policy-lint` CI check: actionlint
      v1.7.12 self-fetched and SHA-256-verified inside the script, plus
      four content assertions -- SHA-pinned `uses:`, no
      `continue-on-error`, a `permissions:` block, `container:` digests
      matching new `scripts/lib/image-pins.txt`), and a refactor pulling
      `gates-manifest-check.sh`'s workflow-job-name awk scan out into
      shared `scripts/lib/workflow-job-names.sh` so `ruleset-sync-check.sh`
      reuses it. `merge-gate.yml` grows to six jobs; `gates.txt` updated
      in the same commit. CLAUDE.md's full Rulesets section landed in the
      same commit (per-slice doc rule).

      **Push ruleset: verified unavailable, not faked.** Two independent
      live 422s from disposable probe rulesets (created `enforcement:
      "disabled"`, confirmed to fail, deleted), BEFORE any committed file
      was written: (1) `target: "push"` itself --
      `"Source public repos cannot have push rules"` /
      `"Source only org-owned repos can have push rules"` -- push
      rulesets need an ORG-owned repo regardless of visibility;
      `coreyleavitt/sello` is a personal-account repo. (2)
      `file_path_restriction`, tested independently against a
      `target: "branch"` ruleset to isolate the question --
      `"Invalid rule 'file_path_restriction': "` -- plan-gated
      independent of target. The intended design is preserved, inert, at
      `.github/rulesets/unavailable/push-workflow-and-policy-paths.json`
      (excluded from both scripts' top-level-only `*.json` glob by its
      subdirectory placement) with the findings recorded in its own JSON
      fields. Compensating control: `scripts/policy-lint.sh`, exactly as
      the RFC's own text names it.

      **Sequencing note, resolved as a confident documented call, not a
      fork:** the RFC's "get a green six-job run on `main`, ONLY THEN run
      `ruleset-apply.sh`" reads as strictly sequential, but `ruleset-sync`
      cannot be green before rulesets exist live, and applying `main`
      immediately activates enforcement -- so a green run genuinely
      *before* any `--apply` call is impossible by construction once
      `ruleset-sync` is one of the six jobs. Resolved as: push the code
      (red `ruleset-sync`, expected and itself the slice's first red demo
      through a real push) -> `ruleset-apply.sh --apply` (creates all
      three rulesets, `main` immediately active) -> re-run the workflow on
      that SAME already-landed SHA so it ends up fully green before any
      of the enforcement-dependent demos begin. "Before enforcement" in
      the DoD is satisfied in spirit (a fully green baseline exists prior
      to the reject/accept/live-edit/waiver demos that actually exercise
      enforcement), not in the stricter (impossible) literal ordering.

      **Green run (initial, pre-demos):** run `32716513583` on `main` @
      `8957c2d`. First pass: `check-readme` 21s, `policy-lint` 6s,
      `unit-linux-amd64-gcc` 56s, `property-linux-amd64-gcc` 9m31s,
      `gates-manifest-sync` 6s all green; `ruleset-sync` red in 3s (job
      `97398806145`, log: `DRIFT (leg 2) -- no live ruleset named "main"
      exists...` + three `DRIFT (leg 3)` lines, one per committed file --
      the red demo). After `ruleset-apply.sh --apply` created ids
      `evidence=21282944`, `main=21282945`, `tags=21282947`, the
      `ruleset-sync` job (job `97401384641`) was re-run via
      `gh api .../jobs/{id}/rerun` -- GitHub reran the WHOLE workflow (not
      a single-job rerun; the API accepted the single-job rerun call but
      re-triggered every job, ~9.5 min again) -- final result: all six
      green, run conclusion `success`.

      **Rejected-then-accepted push pair.** Before the pair: `policy-lint`
      manually removed from the live `main` ruleset's required-check
      array via `gh api .../rulesets/21282945 -X PUT` (outage
      simulation), and a waiver entry for it committed to
      `scripts/lib/waivers.txt` (commit `91ea18c`). (a) `git push origin
      main` with `91ea18c` -> **REJECTED**:
      ```
      remote: error: GH013: Repository rule violations found for refs/heads/main.
      remote: - 5 of 5 required status checks are expected.
      ! [remote rejected] main -> main (push declined due to repository rule violations)
      ```
      (the "5 of 5" reflects the live ruleset's already-reduced array,
      confirming the rejection reasons from the LIVE state, not a stale
      copy). (b) same commit pushed to branch `rfc-005-slice4-close-out`
      -> accepted (branches carry no ruleset). CI run `32717450388`: all
      six jobs green, including `ruleset-sync` (job `97401614935`, log:
      `WAIVER ACTIVE -- check='policy-lint' expiry='2026-09-15'
      reason='RFC-005 slice 4 DoD: waiver mechanism end-to-end
      demonstration...'` then `leg 2 OK`/`leg 3 OK` x3) -- the waiver
      ACTIVE leg through a real push, satisfying that DoD requirement
      directly. `git push origin rfc-005-slice4-close-out:main` (the
      final fast-forward, below) is the (b)-accepted half of this pair in
      its complete form.

      **Live-edit red, then green.** `policy-lint` restored via
      `ruleset-apply.sh --apply`; `gates-manifest-sync` then manually
      removed live (a fresh, unwaived gap) and the `policy-lint` waiver
      entry removed from `waivers.txt` in the same commit (`0b6309e`,
      same branch). Pushed -> CI run `32718282320`: `ruleset-sync` job
      `97404081306` RED --
      `DRIFT (leg 2...) -- ... missing from the live main ruleset:
      gates-manifest-sync` plus a `DRIFT (leg 3) -- "main" ...` unified
      diff; other five jobs green. After the whole run completed (a
      single-job rerun while the run is still in progress is rejected by
      GitHub's API with a 403, `"The workflow run containing this job is
      already running"` -- an operational finding, not anticipated),
      `gates-manifest-sync` was restored via `ruleset-apply.sh --apply`
      and the `ruleset-sync` job re-run alone (job `97406519393`) ->
      green (`leg 1/2/3 OK` x-all), flipping the whole run's conclusion to
      `success` without a second full push+9.5-minute cycle.

      **Waiver end-to-end, EXPIRED leg (local, per the DoD's own
      allowance).** With the live ruleset again missing
      `gates-manifest-sync` and a crafted `waivers.txt` entry
      (`gates-manifest-sync 2020-01-01 LOCAL EXPIRED-WAIVER DEMO...`),
      `scripts/ruleset-sync-check.sh` run locally FAILED loudly:
      `WAIVER EXPIRED -- check='gates-manifest-sync' expiry='2020-01-01'
      ... this waiver no longer excuses a missing required check` followed
      by the same `DRIFT (leg 2/leg 3)` diagnostics as an unwaived gap --
      confirming an expired waiver provides no cover. Both the crafted
      waiver line and the live edit were reverted afterward
      (`ruleset-apply.sh --apply`).

      **Operational finding, not anticipated by the RFC text:** GitHub's
      ruleset list/detail read endpoints show a brief (single-digit-
      second) propagation lag after a live `POST`/`PUT`/`DELETE` --
      several local verification runs immediately after a live mutation
      observed stale (pre-mutation) state before a repeat run, seconds
      later, showed the correct post-mutation state. Recorded in
      `scripts/ruleset-sync-check.sh`'s own header and CLAUDE.md; every
      demo above budgeted a short sleep between a live `gh api` mutation
      and the next check.

      **Cleanup and final state.** After the live-edit-red/green
      confirmation, the handoff-doc update was committed as a third
      commit on the same branch (`rfc-005-slice4-close-out`) and pushed;
      CI run TBD-green (see below), then `git push origin
      rfc-005-slice4-close-out:main` fast-forwarded `main` -- the final
      accepted half of the reject/accept pair, and this slice's own
      close-out landing through the exact branch model it just turned on.
      Scratch branch deleted locally and on `origin` after
      (`gh api repos/.../branches/rfc-005-slice4-close-out` -> 404
      confirmed). Local `scripts/merge-gate.sh` full battery run BEFORE
      enforcement (all six gates read from the manifest, no container
      needed for the two new ones): `unit-linux-amd64-gcc` PASS 45s,
      `property-linux-amd64-gcc` PASS 455s, `check-readme` PASS 10s,
      `gates-manifest-sync` PASS 0s, `ruleset-sync` FAIL 0s (expected,
      pre-apply), `policy-lint` PASS 0s -- re-confirmed fully green after
      `--apply` in follow-up local runs during the demo sequence.

      TRAP for slice 5+ (now living under the branch model): every push
      from here on, including doc-only commits, goes `rfc-*` branch ->
      green -> `git push origin <branch>:main`. A single-job
      `gh api .../rerun` 403s with `"already running"` if the parent
      workflow run has not fully completed -- wait for the whole run
      first, THEN rerun the specific job; this cost one extra ~9.5-minute
      wait in this slice's own live-edit-red demo. Also: `gh api
      .../rulesets/{id} -X PUT` needs the FULL ruleset body (name,
      target, enforcement, bypass_actors, conditions, rules) every time --
      there is no partial-field PATCH-style update for rulesets (`PATCH`
      itself 404s outright, per the finding above).
- [x] 5. Go public -- DONE 2026-08-24. Pre/post-flip safety items (history
      scan, private vulnerability reporting, SECURITY.md intake rewrite,
      fork-PR approval-for-all flip) were already recorded under
      "Resolved forks" from the earlier front-run flip. This entry closes
      the remaining deliverables. Code `a341f40` (branch
      `rfc-005-slice5`), handoff/CLAUDE.md doc commit `<this commit>`:
      - **`CONTRIBUTING.md`** (new): validation-bar pointer (back to
        CLAUDE.md's own section + `docs/`), local gate instructions
        (`scripts/merge-gate.sh`, `milpa fetch`), the branch model stated
        honestly for contributors (fast-forward-only `main` is the
        maintainer's own flow), the fork-PR CI current state disclosed
        honestly (approval policy is live repo-wide today, but the
        `pull_request`-triggered workflow itself does not exist yet --
        that is slice 6, not this one), crypto-contribution expectations
        (tests+vectors, CT discipline, full affected-gate battery for
        secret-path changes), and commit-message conventions.
      - **README `## Validation` section** (minimal, per the RFC's
        gap-closing rule): prose pointing at `docs/ct-results.md`,
        `docs/mutation-results.md`, and `docs/rfc-001-signing.md` through
        `docs/rfc-006-sha512.md`, plus the `merge-gate` badge (added under
        the title) pinned `?branch=main`. Verified zero job-name claims
        and exactly one badge in the section by direct re-read after
        writing it -- the hand-curated claim table and its drift check
        are explicitly deferred to slice 31, not built here.
      - **SECURITY.md "Trust root / security posture" section** (new):
        states everything upstream of the ruleset resolves to the owner
        account (`coreyleavitt`, a personal `User`, not an org), split
        into independently-API-verified facts and owner-attested facts.
        Verified live before writing: `gh api repos/coreyleavitt/sello`
        -> `visibility: "public"`, `owner.type: "User"`; `gh api
        repos/coreyleavitt/sello/actions/runners` -> `total_count: 0`
        (zero self-hosted runners registered -- there is no
        runner-registration credential to custody yet, contrary to the
        RFC's implicit assumption that this line always applies; noted
        honestly rather than writing a custody claim with nothing behind
        it). `gh api user`'s `two_factor_authentication` field returns
        `null` unconditionally (GitHub's API no longer exposes this for
        privacy reasons, confirmed by the field being present-but-null
        rather than absent) -- hardware-key 2FA, ghcr PAT scope/custody,
        and other-credential-custody are therefore recorded as
        owner-attested, not fabricated; see "Open forks" below for the
        confirmation request filed against them.
      - **ghcr anonymous-pull re-verification**: lighter-weight
        token+manifest proof (no image pull, avoiding this host's /tmp
        podman trap entirely) --
        `curl -sf https://ghcr.io/token?scope=repository:coreyleavitt/nim:pull`
        (no `Authorization` header sent, i.e. a logged-out/anonymous
        request) returned a bearer token; that token against
        `GET https://ghcr.io/v2/coreyleavitt/nim/manifests/2.2.10`
        returned `HTTP/2 200` (`docker-content-digest:
        sha256:dfc376d37354901b68d31960657d71eef9fdd5f15b2e8d9acd492d999693935a`,
        an OCI image index); the same token against the exact pinned
        digest from `scripts/lib/image-pins.txt`
        (`GET .../manifests/sha256:cd4708fb29d16ec4256a0bdcf8a4873b1f5a7a7200e32890ed52d5893227e780`)
        also returned `HTTP/2 200` with a matching
        `docker-content-digest`. Both requests carried no credential of
        any kind -- anonymous pull by tag and by the exact CI-pinned
        digest both confirmed.
      - **Fork-PR approval-for-all readback**: the RFC-suggested
        `.../actions/permissions/fork-pr-workflows` endpoint 404s (wrong
        endpoint name); the correct one, found via docs lookup and
        confirmed live, is `GET
        repos/coreyleavitt/sello/actions/permissions/fork-pr-contributor-approval`
        -> `{"approval_policy": "all_external_contributors"}` -- reads
        back exactly as the earlier flip recorded. The end-to-end
        held-for-approval demo (an actual fork PR run pausing for
        approval) stays slice 6's DoD, not re-demonstrated here.
      - **Re-run-green-under-public-conditions**: every `merge-gate` run
        on `main` since the visibility flip earlier today (2026-08-24)
        has run under public/anonymous-fork conditions by construction
        (the repo has been public since before any of them started). This
        slice's own branch run (`32722396766`, branch `rfc-005-slice5`,
        SHA `f4de89d`, all six jobs green, `property-linux-amd64-gcc`
        completed in 8m52s) and the post-fast-forward run on `main`
        (`32723188647`, same SHA `f4de89d`, `status: completed`,
        `conclusion: success`) are cited as the concrete verification --
        the fast-forward itself succeeded before the main-ref run even
        finished, confirming live the slice-4 finding that the ruleset
        engine accepts check-runs already reported against the arriving
        SHA rather than blocking on a fresh main-ref run. The most recent
        pre-existing green main run under public conditions before this
        slice started was `32720085738` (push, `c6f6246`, 2026-08-24
        11:05:45Z).
      - **No red demo** (stated explicitly per the DoD): this slice is
        docs/verification, not a new gate -- there is no natural red path
        to demonstrate, and slice 4's enforced-rejection-of-a-direct-push
        evidence already covers the branch model this slice's own commits
        flow through. Not re-demoed here.
      - Commits: `a341f40` (code: CONTRIBUTING/README/SECURITY/CLAUDE.md),
        `f4de89d` (handoff-doc update recording the above). Branch
        `rfc-005-slice5` green run: `32722396766`. Fast-forward to `main`
        (`c6f6246..f4de89d`): main run `32723188647`, green. A small
        follow-up commit landed the exact run ids above into this file
        (matching slice 4's own precedent of a final record-keeping
        commit whose own CI run isn't further self-cited); branch deleted
        after landing (locally and on `origin`).
- [x] 6. Contribution lane -- DONE 2026-08-24 except the fork-PR
      held-for-approval demo itself, which is filed Corey-owned (see Open
      forks below; everything else in the slice completed). Code `cabc161`
      (branch `rfc-005-slice6`):
      - **`.github/workflows/pr-checks.yml`** (new): a second,
        `pull_request`-triggered workflow, deliberately separate from
        `merge-gate.yml` (RFC-005 Part B's own build-path-invariant
        wording is scoped to "every CI job's run step," not "one workflow
        file total," and a `pull_request` lane with non-required checks
        under the six required check names would be exactly the name
        collision Part B's "check names are a stable public interface"
        line warns against). Two jobs, `pr-unit-linux-amd64-gcc` and
        `pr-check-readme` -- the cheap subset only (unit suite +
        check-readme; NOT the ~9.5-minute property job, NOT the three
        repo-governance checks). Same supply-chain posture as
        `merge-gate.yml`: SHA-pinned `uses:`, workflow-level
        `permissions: {contents: read}`, per-PR `concurrency` with
        `cancel-in-progress`, `container:` digest identical to
        `scripts/lib/image-pins.txt`, hosted `ubuntu-latest` runners only
        (the self-hosted timing-tier runner, not yet built, is never
        targeted by `pull_request` events). Verified locally before
        pushing: `scripts/policy-lint.sh` clean (it globs
        `.github/workflows/*.yml`, so this file is in scope), and both
        `scripts/gates-manifest-check.sh` and
        `scripts/ruleset-sync-check.sh` clean -- confirmed by reading
        both scripts (and their shared
        `scripts/lib/workflow-job-names.sh`) that each hard-codes its
        workflow scan to `.github/workflows/merge-gate.yml` specifically,
        not a directory-wide glob, so `pr-checks.yml`'s two job names
        never enter either drift comparison and correctly need no
        `scripts/lib/gates.txt` entry -- the TRAP note's premise
        ("verify the scan isn't directory-wide") held, no design change
        needed.
      - **`CONTRIBUTING.md`** cross-checked: the "Fork PR CI (honest
        current state)" section rewritten to describe the real workflow
        (what the two jobs are, that neither is a required check, the
        approval-hold behavior for outside contributors, and that the
        full six-job `merge-gate.yml` battery -- not this lane -- is what
        a change actually merges on, triggered by the maintainer pushing
        the accepted branch).
      - **`CLAUDE.md`** gains a "Contribution lane" paragraph in the CI
        section (naming decision, manifest-exemption mechanics, approval-
        gate story) plus a one-sentence amendment to the preceding
        paragraph noting `pr-checks.yml` as the one deliberate exception
        to "widen `merge-gate.yml`, never fork a second workflow."
      - **Branch flow.** Branch `rfc-005-slice6` push -> run `32726115419`
        green (all six jobs; `property-linux-amd64-gcc` 9m36s) ->
        `git push origin rfc-005-slice6:main` fast-forward
        (`102b5b9..cabc161`) -> post-fast-forward `main` run `32726991976`
        green (all six jobs) -> branch deleted, `.../branches/
        rfc-005-slice6` confirmed 404.
      - **Same-account PR smoke test (DoD item 3).** Scratch branch
        `pr-lane-smoke` (one commit, a new inert
        `.github/PR_LANE_SMOKE_TEST.md` scratch file, never intended to
        land), PR #1 opened same-account against `main`. Both the
        `pull_request`-triggered run (`32727886569`) and the
        simultaneously-triggered `push`-triggered `merge-gate.yml` run
        (`32727878225`, since a same-repo branch push satisfies both
        workflows' own triggers) appeared on the PR's checks list as
        eight independent check-runs -- `pr-unit-linux-amd64-gcc` and
        `pr-check-readme` distinct from `unit-linux-amd64-gcc` and
        `check-readme`, confirming the naming decision holds in practice,
        not just on paper. Neither PR-lane check was held for approval
        (same-account -- expected, not a gap). `pr-check-readme` green in
        24s, `pr-unit-linux-amd64-gcc` green in 53s, both job IDs
        `97433198669`/`97433199046`. PR #1 closed unmerged, branch deleted
        via `gh pr close --delete-branch`, `.../branches/pr-lane-smoke`
        confirmed 404.
      - **Red demo (DoD's red-path requirement).** Investigated both
        candidate targets first, per the TRAP note: the unit suite's file
        list (`scripts/lib/unit-test-files.sh`) is a fixed, hand-written
        bash array, not a directory glob -- a new scratch test file placed
        under `tests/unit/` would NOT be "picked up" by
        `pr-unit-linux-amd64-gcc` without also editing that shared array
        (infrastructure also used by the real required
        `unit-linux-amd64-gcc` gate), which is more invasive than
        necessary for a demo confined to the PR lane. Chose the README-
        fence target instead: scratch branch `pr-lane-red-demo`, one
        commit appending a deliberately-broken ` ```nim ` fence (an
        undefined-identifier call) to `README.md`, PR #2 opened
        same-account. `pr-check-readme` (job `97433648961`) failed in 22s
        with the expected Nim compiler error
        (`Error: undeclared identifier: 'thisIdentifierDoesNotExist'`,
        confirmed via `gh run view --job ... --log`); `pr-unit-linux-amd64-gcc`
        (job `97433649121`, same run `32728034097`) stayed green on the
        same push, confirming the red is targeted, not incidental. PR #2
        closed unmerged, branch deleted via `gh pr close --delete-branch`,
        `.../branches/pr-lane-red-demo` confirmed 404 -- the broken fence
        never reached `main` (it existed only on the deleted scratch
        branch/commit).
      - **Fork-PR held-for-approval demo (DoD item 4) -- NOT demonstrated,
        filed Corey-owned.** See Open forks below for the full
        investigation and the exact instructions filed for Corey to run
        the demo from a genuine second account.
- [x] 7. Image consolidation -- DONE 2026-08-24 except the real ghcr push
      (blocked on credentials, filed Corey-owned; see Open forks). Branch
      `rfc-005-slice7`.

      **Fail-fast checks (done first, per the task's own instruction).**
      Network: ghcr.io and download.opensuse.org both reachable. Credentials:
      `gh auth status` shows scopes `delete_repo, gist, read:org, repo,
      workflow` -- no `write:packages`; `curl -sI -H "Authorization: token
      $(gh auth token)" .../user` confirmed the same scope list from the
      live token itself, not just the cached CLI state; `podman login
      --get-login ghcr.io` -> "not logged into ghcr.io". No push-capable
      credential exists in this session -- per the task's own escalation
      rule, did all credential-independent work and filed the push as an
      open fork rather than parking.

      **Package enumeration (verified via `zypper search -s`/dry-run
      install/real install inside the pinned base image, alt-root podman,
      not assumed):**
      | need | package | status |
      |---|---|---|
      | libsodium adapter | `libsodium-devel` | already present (pre-slice-7) |
      | Z3 symex | `z3-devel` | already present (pre-slice-7) |
      | 32-bit multilib (`--cpu:i386`, slice 10) | `gcc-32bit` + `glibc-devel-32bit` + `libstdc++6-32bit` | added -- pulls `gcc16-32bit`/`glibc-32bit` transitively |
      | Valgrind (slice 19) | `valgrind` | added |
      | coverage (slice 17) | `lcov` | added -- drags in a large perl (DateTime et al.) dependency chain, ~82 new packages transitively; accepted, no lighter substitute exists on this base |
      | s390x cross-gcc (slice 25) | `cross-s390x-gcc16` | added -- version-numbered per openSUSE's per-major naming; `gcc16` picked to match the base image's own native `gcc16`; binary name is `s390x-suse-linux-gcc`, verified via `--version` |
      | qemu-user (slice 25) | `qemu-linux-user` | added -- **substitution finding**: `qemu-user-static` (Debian/Ubuntu naming, what the RFC text names) does not exist under that name on this zypper base; `qemu-linux-user` is openSUSE's package, confirmed via `zypper search` and a working `qemu-s390x --version` inside the built image |
      | disasm gate (slice 23) | `binutils`/`objdump` | **already present in the base image** -- NOT added; would have been a no-op duplicate |
      | clang (slices 8/9/19/22, round-2 finding "missing from the list") | `clang`/`clang22` | **already present in the base image** -- the round-2 finding does not hold empirically as of this slice's verification (`which clang` / `rpm -qa | grep clang` both confirm); recorded rather than silently dropped, since a future base-image change could reintroduce the real gap |

      Verified functionally, not just "installed": `gcc -m32 -x c -o ...`
      compiled and ran; `valgrind --version`; `lcov --version`;
      `s390x-suse-linux-gcc --version`; `qemu-s390x --version`; `clang
      --version`; `objdump --version` -- all run inside the built
      `sello-dev` image via direct `podman run ... bash -c` (no volume
      mounts involved -- see the local-run-validation finding below for
      why that distinction matters).

      **Containerfile.** Extended with the enumerated packages (one
      `zypper install` line, `gcc-32bit glibc-devel-32bit
      libstdc++6-32bit valgrind lcov cross-s390x-gcc16 qemu-linux-user`
      added to the existing `libsodium-devel z3-devel`), plus a fully
      rewritten header comment enumerating what's added/why per package
      and what's deliberately NOT added (binutils, clang) with the
      empirical-verification note. **`FROM` is now digest-pinned**
      (`ghcr.io/coreyleavitt/nim@sha256:cd4708fb...`, matching
      `scripts/lib/image-pins.txt`'s base-image section) -- it was still
      on the `2.2.10` tag before this slice, which the task's own
      instructions flagged as a gap against the RFC's digest-pin
      requirement. Fixing it turned out to matter immediately, not just
      procedurally -- see the mutable-tag finding below.

      **Live finding: the base image tag genuinely moved mid-session.**
      While iterating on this Containerfile, `ghcr.io/coreyleavitt/nim`'s
      `2.2.10` TAG's own linux/amd64 sub-manifest digest was observed to
      change (`sha256:1cad5bad8a47...` -> `sha256:a24f7590e660...`, both
      confirmed via anonymous-token `curl` against the real ghcr.io API,
      real GitHub IP resolution, at two different points in the same
      session) with no action taken by this session against that repo --
      an unplanned, live demonstration of exactly the risk RFC-005 Part
      B's digest-pinning rule exists to close ("a mutable tag is 'trust
      our transcripts' one layer down"). The manifest-LIST digest already
      recorded in `scripts/lib/image-pins.txt`
      (`sha256:cd4708fb29d16ec...`) stayed stable and resolvable to the
      correct, original content throughout, confirmed by re-pulling it
      directly after the tag had already moved. This directly motivated
      digest-pinning the Containerfile's own `FROM` line in this same
      slice (see above) rather than treating it as a separate future
      cleanup.

      **Local build + verification.** Built `sello-dev` locally
      (alt-root podman, see the environment findings below) three times
      across the session as the Containerfile/pin evolved; final image:
      Containerfile hash `806abfce49ffbbe88798043770b2698fc8ca1b7e88558946bc8c077d07ede932`,
      uncompressed size ~1.98 GB (`podman image inspect --format
      '{{.Size}}'` -> 2078946545 bytes), compressed (manifest layer sizes
      summed) ~709.6 MiB. The compressed size is larger than an earlier
      (superseded) build against the then-current `2.2.10` tag (~605 MiB)
      because the digest-pinned base is a 2026-08-09 snapshot and the
      live zypper repos have moved since -- more packages upgrade to
      satisfy today's dependency graph. Accepted as the honest cost of
      digest-pinning against a rolling-release (Tumbleweed) upstream; not
      large enough to justify the RFC's pre-authorized lean-core/heavy-
      gates image split (that stays available if a future slice's
      pull-cost measurement changes this call).

      **Publish attempt and the credential-independent digest.** Real
      `podman push` to `ghcr.io/coreyleavitt/sello-dev` was not
      attempted given the confirmed absence of push credentials (see
      fail-fast above). Instead: pushed the built image to a disposable,
      throwaway local registry (`docker.io/library/registry:2`,
      `--tls-verify=false`, deleted after) to compute the REAL manifest
      digest the same way a real ghcr push would (digest computation is
      destination-independent -- it's a property of the manifest/layer
      content, not the registry). Final digest:
      `sha256:dc39f87a10ab555b2e5234bbba02faab7c7875be578b6f27bb6ca2580991f9f4`.
      Confirmed stable across `podman save`/`load` (re-pushing a
      loaded-from-tar copy reproduced the identical layer digests) --
      the exact built image, not the Containerfile alone, is what
      reproduces this digest; a fresh `podman build` might not (container
      builds are not reproducible, per the RFC's own stated assumption).
      Preserved as a portable artifact for the eventual real push:
      `/home/corey/.cache/sello-dev-image/sello-dev-806abfce.oci-archive.tar`
      (710 MB, OCI archive format, untracked -- outside the repo, not
      committed). `scripts/lib/image-pins.txt`'s new `sello-dev` section
      records the pair (Containerfile hash, this digest) and documents
      this provenance directly in its own comment, including the
      not-yet-live status.

      **Consumer conversion.** New `scripts/lib/sello-dev-image.sh`
      (`resolve_sello_dev_image`): default path pulls
      `ghcr.io/coreyleavitt/sello-dev@sha256:...` per the pin file (fails
      loudly with a pointer to the escape hatch on pull failure -- e.g.
      not-yet-published, as is true right now); `SELLO_DEV_LOCAL_BUILD=1`
      escape hatch builds fresh from the committed Containerfile (for
      iterating on the Containerfile itself before a new pin is
      published); `SELLO_DEV_IMAGE_REF=<ref>` escape hatch pulls an
      arbitrary reference instead, bypassing the pin file (used during
      this slice's own testing to point at the scratch registry above --
      a real network pull-by-digest, 605 MiB over loopback in 11.2s,
      confirmed working end to end before the base-image-tag/registry
      confusion below). `scripts/test-libsodium.sh` and `scripts/bmc.sh`
      both replace their old `podman image exists "$img" || podman build
      ...` with `source scripts/lib/sello-dev-image.sh &&
      resolve_sello_dev_image` (`bmc.sh` doesn't `set -e`, so its call
      site checks the return explicitly, matching its existing preflight
      pattern).

      **Drift check: extended `scripts/policy-lint.sh` (the RFC's own
      recommended placement, chosen over a new required check -- avoids
      the slice-4 check-name machinery for a content-drift check with no
      natural CI trigger of its own).** New fifth assertion: `sha256sum
      Containerfile` must match the hash recorded on
      `image-pins.txt`'s `sello-dev` line -- "rebuild and compare
      digests" is explicitly infeasible per the RFC's own text (builds
      aren't reproducible), so this checks the cheap, exact, checkable
      proxy instead (has the Containerfile changed since the pinned
      image was actually built). **Red-then-green demo, done locally
      (per the DoD's own allowance -- policy-lint's CI wiring was already
      proven in slice 4):** appended a comment to `Containerfile`
      without updating the pin -> `scripts/policy-lint.sh` FAILED with
      the expected message and exit code 1 (verified via `$?` directly,
      not through a pipe that would mask it); reverted; re-ran ->
      green, hash match confirmed. `scripts/gates-manifest-check.sh`
      re-verified green (no required-check surface changed).

      **arm64 manifest verdict.** Queried
      `ghcr.io/coreyleavitt/nim`'s manifest LIST via anonymous
      token+curl (the slice-5 method): two platform entries only --
      `linux/amd64` and `windows/amd64` (the Windows entry is itself
      still amd64). **No arm64 variant exists.** Decision for slice 11
      (linux/arm64 job), recorded now per the task's own instruction so
      slice 11 doesn't rediscover this: **recommend direct Nim toolchain
      install on a GitHub-hosted `ubuntu-24.04-arm` runner, not a
      multi-arch extension of the base image.** Rationale: the base
      image's build source is explicitly OUT OF SCOPE for this repo (the
      RFC's own slice-7 title parenthetical: "the base image is untouched
      -- ... since the base image's build source lives outside this repo
      and is only documented here") -- asking that separate repo to grow
      an arm64 leg is not this slice's or this repo's call to make.
      Direct-install also mirrors the ALREADY-PLANNED macOS-arm64 job's
      own pattern (slice 12: "Nim install mechanism named and
      version-pinned (no digest-pinnable container on macOS runners)")
      -- one consistent non-container-pin story for both non-amd64-Linux
      hosted-runner legs, not two different mechanisms invented
      independently in later slices.

      **Local-run-validation finding: a NEW, distinct environment
      blocker (not the pre-existing /tmp trap), blocking the DoD's
      "run scripts/test-libsodium.sh / scripts/bmc.sh green locally"
      legs.** Isolated via a long sequence of controlled tests, down to
      the exact root cause: the base image ships `/home` at mode `555`
      (`dr-xr-xr-x`, root:root -- no write bit for anyone, confirmed via
      `stat` inside a working no-mount container). Every one of
      `test.sh`/`test-libsodium.sh`/`ct.sh`/`fuzz.sh`/`bmc.sh`'s shared
      `-v "$HOME/.cache/milpa:$HOME/.cache/milpa"` mount (pre-existing
      design since RFC-001, unrelated to this slice's own changes) needs
      `crun` to auto-`mkdir` the nonexistent `$HOME` (`/home/corey`)
      inside the container's overlay view to serve as the mount target --
      under THIS session's ROOTLESS podman + `fuse-overlayfs` stack (no
      real root, no `CAP_DAC_OVERRIDE`), that `mkdir` fails outright
      (`crun: mkdir \`/home/corey\`: Permission denied`), 100%
      reproducibly, isolated down to the single mount flag alone on a
      pristine store (confirmed: a no-mount run succeeds; adding back
      just this one `-v` breaks it; other top-level dirs the same image
      ships writable, e.g. `/tmp` and `/var/tmp` at `1777`, mount fine).
      Also confirmed NOT fixable by pre-creating the directory via an
      extra `Containerfile` `RUN mkdir /home/corey` layer -- `buildah`'s
      `RUN` step hits the identical rootless permission wall building on
      this exact base image. **This does not affect CI**: every CI job
      runs `SELLO_IN_CONTAINER=1`, which skips the whole podman-wrapper
      and mount-construction branch entirely (see `scripts/test.sh`'s own
      header comment) -- CI never evaluates this code path. It also does
      not indicate any defect in this slice's own Containerfile/script
      changes: every added package was independently verified functional
      via direct (no-mount) `podman run ... bash -c` execution (see the
      package-enumeration table above). The DoD's two "runs green
      locally" legs are therefore NOT demonstrated in this session and
      are filed Corey-owned below, alongside the credential blocker --
      Corey's own host may not share this exact rootless/fuse-overlayfs
      combination (a privileged Docker daemon, or a different podman
      storage configuration with real root, would not hit this).
      Multiple scratch `/home/corey/.podman-alt*` storage roots were
      created and torn down chasing this diagnosis (via `podman unshare
      rm -rf`, per the standing TRAP, with several needing an extra
      `podman unshare chmod -R u+w` first to clear permission-broken
      whiteout markers this same bug leaves behind) -- all cleaned up by
      the end of the session; `df -h /home` confirmed no lasting
      space impact (981G free throughout).

      **Image size + cold-pull time.** Uncompressed 1.98 GB, compressed
      ~709.6 MiB (see above). Real cold-pull rate measured against actual
      ghcr.io earlier in this same session (pulling the BASE image, not
      sello-dev, before any credential/mount issues arose):
      ~370 MiB in 20.1s (~18.5 MiB/s). Extrapolated sello-dev cold-pull
      estimate from ghcr: ~38s (709.6 MiB / 18.5 MiB/s) -- an ESTIMATE,
      not a measurement, since the image isn't live yet. A loopback pull
      of the full image against the scratch registry (real bytes
      transferred, blobs removed first) measured 66.8s on a busy shared
      host mid-session -- noted as a rough sanity bound only (loopback +
      contention makes it a poor proxy for a real network number), not
      cited as the headline figure. **Two-image split: NOT adopted.**
      ~40s estimated cold pull is well inside any reasonable per-job
      budget for the heavy gates this image serves (libsodium interop,
      bmc/symex, and later the `-m32`/valgrind/lcov/s390x/qemu-user
      matrices) -- the RFC's pre-authorization for a lean-core/heavy-gates
      split is recorded as available but not exercised this slice.

      **CLAUDE.md.** Updated in the same commits: the Containerfile/
      sello-dev paragraph rewritten (full package list, what's NOT
      added and why, the pull-by-digest + two-escape-hatch story, the
      digest-pinned `FROM` + live mutable-tag finding), and
      `policy-lint.sh`'s paragraph updated from "four assertions" to
      "five," naming the new sello-dev drift check.

      **Not done / filed Corey-owned (see Open forks below):** the real
      `ghcr.io/coreyleavitt/sello-dev` push (blocked on `write:packages`
      credentials); the two DoD "runs green locally" legs for
      `scripts/test-libsodium.sh`/`scripts/bmc.sh` (blocked on the
      rootless-podman `/home`-mode-555 finding above, on THIS host/
      session specifically). Everything else in the slice -- package
      enumeration, Containerfile, drift check + real red/green demo,
      arm64 verdict + decision, image size/pull-time record, CLAUDE.md --
      is complete and committed via the branch model.

Phase 1 — matrix (7 first, then 8–13 independent):
- [x] 7. Image consolidation (sello-dev to ghcr by digest; package enumeration; arm64 manifest check) -- DONE 2026-08-24 except the real ghcr push (blocked on credentials, filed Corey-owned; see Open forks and the full slice entry below).
- [x] 8. clang-backend job -- DONE 2026-08-24. Code `60d7d02` (mechanism +
      jobs), red demo `cc6e3be`, revert+doc commit `<this commit>`. See
      the full slice entry below (after slice 7's) for mechanism design,
      run ids, canary evidence, and the red-then-green sequence.
- [ ] 9. ASan/UBSan job (red: planted overflow)
- [ ] 10. --cpu:i386 job (canary: 4-byte pointers)
- [ ] 11. linux/arm64 job
- [ ] 12. macOS-arm64 job (pin story explicit; proptest-skip PRESENT)
- [ ] 13. Windows/MinGW job (shell: bash; MinGW pinned)

Phase 2 — heavy deterministic gates (independent after 7):
- [ ] 14. libsodium differential job (skip paths fatal under CI env var)
- [ ] 15. Mutation + bmc jobs (measure hosted times; heavy-gate placement decision)
- [ ] 16. Build-smoke check (fuzz target + ct_main compile; red: planted compile error)
- [ ] 17. Coverage ratchet A3 (baseline.sh lands here, proof-spiked against disasm needs)
- [ ] 18. API-surface gate A8 (generator verify-first spike; dual baselines)

Phase 3 — CT instruments (19→20→21→22→23 chain):
- [ ] 19. Taint CT harness A1 mechanism (go/no-go FIRST; shim TU; declassify; 2 targets; schema proof-spike)
- [ ] 20. Secret-target register A7 (per-instrument columns; dudect retrofit; red demo)
- [ ] 21. Taint targets (all remaining; both verdict arms; zero-annotation arc per target)
- [ ] 22. Taint CI + doc drift (gcc+clang jobs required; anchor drift check)
- [ ] 23. Disasm gate A2 ({.noinline.} roots + full battery refresh; nimcache-C resolver; per-backend baselines)

Phase 4 — nightly, timing, release:
- [ ] 24. Nightly fuzz continuity A5
- [ ] 25. Nightly s390x A4
- [ ] 26. Nightly canaries + notifications (A6, A9, pinned-issue wiring)
- [ ] 27. Timing tier provisioning (**Corey-owned, physical** — will pause loop)
- [ ] 28. Timing tier runner + workflow
- [ ] 29. First quiet-box battery + carve-out re-adjudication
- [ ] 30. Release workflow (5 per-clause red demos)
- [ ] 31. README evidence table + drift check
- [ ] 32. Registry + close-out audit

## Open forks (awaiting Corey)
- **Trust-root owner-attestation confirmation (filed 2026-08-24, slice
  5).** `SECURITY.md`'s new "Trust root / security posture" section
  records three items as owner-attested because they cannot be checked
  from an API session (GitHub's `two_factor_authentication` API field is
  unconditionally `null` for privacy reasons, and there's no endpoint
  enumerating PAT scopes or custody practices): (1) the `coreyleavitt`
  account's GitHub sign-in uses hardware-key 2FA; (2) the personal access
  token(s) used to push to `ghcr.io/coreyleavitt/*` are scoped minimally
  (package-write only, not a broad/classic token) and are periodically
  reviewed/rotated; (3) no other long-lived credential with write access
  to this repository/its packages/its Actions configuration exists
  outside the owner's own custody. Please confirm or correct these three
  in `SECURITY.md` directly (or reply here for the next session to make
  the edit) — not a blocker for this slice's own close-out, per the RFC's
  escalation rule for owner-attested items.

- **Fork-PR held-for-approval demo (filed 2026-08-24, slice 6).** Slice
  6's DoD calls for demonstrating that a PR from a genuine outside
  contributor gets its `pull_request` checks held pending maintainer
  approval (`all_external_contributors`, live-verified in slice 5) rather
  than running unattended. This requires a SECOND GitHub account with no
  write access to `coreyleavitt/sello` opening the PR -- investigated and
  confirmed NOT satisfiable from this session:
  - `gh auth status` shows exactly one authenticated account,
    `coreyleavitt` (the repo owner).
  - `gh api user/orgs` shows two orgs Corey belongs to (`knurlsoft`,
    `Ulysses-Power`). Investigated whether forking into one of these
    (rather than a personal fork) would count as "external" for the
    approval policy -- it would NOT: GitHub's approval-policy check keys
    off the identity of the PR's author/triggering actor (specifically,
    whether that GitHub user account has write access to the upstream
    repo), not the namespace the fork lives in. A PR opened by the
    `coreyleavitt` account from a `knurlsoft`-owned fork is still opened
    by an account with admin access to `coreyleavitt/sello` -- it would
    NOT be held, and so would not demonstrate anything (confirmed against
    GitHub's own documentation on repository Actions settings; see
    "Managing GitHub Actions settings for a repository" at
    docs.github.com and community discussion #49048, both consulted
    2026-08-24 -- not literally re-tested live, since doing so would
    require the very second account this fork is about, but the
    documented mechanism is unambiguous on this point). Creating a new
    personal GitHub account to serve as the "outside" tester is
    explicitly out of scope (ToS; the credentials would not be Corey's
    own) -- per the task's own instruction, this is filed rather than
    worked around.
  - **Everything else in slice 6 is done regardless** (see the slice 6
    entry above) -- this is the one DoD leg that stays open.

  **Instructions for Corey to run this demo from any second GitHub
  account** (a personal account with no collaborator/owner relationship
  to `coreyleavitt/sello` -- a throwaway free account is fine, it never
  needs to push anything real):
  1. Sign in to GitHub as the second account (a private/incognito browser
     window avoids session collision with your primary `coreyleavitt`
     session).
  2. Go to `https://github.com/coreyleavitt/sello` and click **Fork**
     (top right) -- fork it into the second account's own namespace, not
     an org. Default settings are fine.
  3. In the fork, create a new branch (e.g. `external-pr-checks-demo`)
     and make a trivial change -- editing `README.md` directly in the
     GitHub web UI (e.g. append one harmless sentence) is enough; no
     local clone needed.
  4. Commit directly to the new branch (the GitHub web editor's "Commit
     directly to the `external-pr-checks-demo` branch" option), then open
     a pull request from `<second-account>/sello:external-pr-checks-demo`
     into `coreyleavitt/sello:main`.
  5. **Observe, on the PR's checks list:** both `pr-checks.yml` jobs
     (`pr-unit-linux-amd64-gcc`, `pr-check-readme`) should show as
     **"workflow awaiting approval"** (GitHub's own status text for a
     held run) rather than queued/running -- confirm no run for either
     job has started (no log content, no "in progress" state; the
     workflow run is created but paused before its first job). A yellow
     "First-time contributors need a maintainer to approve running
     workflows" (or "outside collaborator") banner should appear near the
     top of the PR's checks section for the `coreyleavitt` account viewing
     it, with an **Approve and run** button.
  6. Take a screenshot or copy the exact banner text and the check-run
     state for the handoff record -- this is the DoD's evidence artifact.
  7. Either click **Approve and run** to also observe the held run
     complete normally once approved (optional, closes the loop end to
     end), or leave it unapproved -- either way, do NOT merge the PR.
  8. Close the PR (do not merge) and delete the branch/fork afterward
     (the fork itself can also just be left or deleted from the second
     account's settings; it never touched `main`).
  9. Report back (or edit this handoff entry directly) with: the PR
     number/URL, the exact "awaiting approval" state observed, and
     confirmation the checks did not execute before the approval click
     (or were never approved).

  **Runner-targeting-workflow variant (RFC-005 Part B ~line 787, forward-
  looking):** once the self-hosted timing-tier runner lands (slice 28,
  not yet built), that slice's own DoD calls for the SAME second-account
  mechanism, but with the fork PR instead ADDING a new workflow file that
  targets the runner's labels (e.g. `runs-on: [self-hosted, ...]`) rather
  than editing `README.md` -- the point there is showing that even a
  workflow-file-adding attack from an approved-but-untrusted PR is held
  for the identical approval click, since "the approval click is the
  load-bearing control" for the runner (RFC-005 Part B's own wording).
  Steps 1-4 above are identical except step 3 adds a new
  `.github/workflows/*.yml` file targeting the runner label instead of
  editing `README.md`; steps 5-9 are unchanged. Filed here now (rather
  than only in a future slice 28 handoff) since the second-account
  mechanics are identical and worth recording once — slice 28 should
  reuse this playbook, not rediscover it.

- **`ghcr.io/coreyleavitt/sello-dev` push (filed 2026-08-24, slice 7).**
  No push-capable credential exists in this session: `gh auth status`
  scopes are `delete_repo, gist, read:org, repo, workflow` -- no
  `write:packages`; no `podman login ghcr.io` session either. The image
  is fully built, verified, and its real publish digest already computed
  (via a disposable scratch registry, not a placeholder --
  `sha256:dc39f87a10ab555b2e5234bbba02faab7c7875be578b6f27bb6ca2580991f9f4`,
  recorded in `scripts/lib/image-pins.txt`), and preserved EXACTLY (not
  just its Containerfile) as a portable artifact so the eventual real
  push reproduces this same digest byte-for-byte rather than depending on
  a fresh rebuild (builds aren't reproducible):
  `/home/corey/.cache/sello-dev-image/sello-dev-806abfce.oci-archive.tar`
  (710 MB, untracked, outside the repo).

  **To unblock, either:**
  1. `gh auth refresh -h github.com -s write:packages` (interactive --
     needs a browser/device-code approval only Corey can complete), then
     `echo "$(gh auth token)" | podman login ghcr.io -u coreyleavitt
     --password-stdin`, or
  2. Create a classic PAT (or fine-grained token) scoped to
     `write:packages` only and `podman login ghcr.io` with it directly
     (per SECURITY.md's existing trust-root guidance: minimally scoped,
     periodically rotated -- this would be the FIRST credential of this
     specific kind on record; flag it for the trust-root list alongside
     the existing open ghcr-PAT-custody confirmation request from slice
     5, since it's the same category of secret that entry already
     covers, not a new one).

  **Once either exists, the exact unblock command (do not rebuild):**
  ```sh
  podman load -i /home/corey/.cache/sello-dev-image/sello-dev-806abfce.oci-archive.tar
  podman tag localhost/sello-dev:latest ghcr.io/coreyleavitt/sello-dev:latest
  podman push ghcr.io/coreyleavitt/sello-dev:latest
  ```
  Then confirm the pushed digest matches the pin file's recorded
  `sha256:dc39f87a10ab555b2e5234bbba02faab7c7875be578b6f27bb6ca2580991f9f4`
  exactly (`podman image inspect
  ghcr.io/coreyleavitt/sello-dev:latest --format '{{.Digest}}'` after the
  push, or read `docker-content-digest` off a manifest `GET`) -- if it
  does not match, something about the push path altered the manifest
  (e.g. a registry-side re-tag/re-manifest step) and `image-pins.txt`
  needs the ACTUAL resulting digest, not the one recorded here.

- **`scripts/test-libsodium.sh`/`scripts/bmc.sh` "runs green locally" DoD
  legs (filed 2026-08-24, slice 7).** Blocked by a newly-discovered,
  thoroughly-isolated environment limitation distinct from the
  pre-existing /tmp-podman trap: the base image ships `/home` at mode
  `555` (no write bit for anyone), and this session's ROOTLESS podman +
  `fuse-overlayfs` stack cannot auto-`mkdir` the nonexistent
  `$HOME`(`/home/corey`) these scripts' shared `-v
  "$HOME/.cache/milpa:$HOME/.cache/milpa"` mount needs as its target --
  confirmed down to the single flag on a pristine store, and confirmed
  NOT fixable via an extra `Containerfile` layer (buildah's own `RUN`
  hits the identical wall). Full diagnosis in the slice 7 entry above.
  Does not affect CI (`SELLO_IN_CONTAINER=1` skips this code path
  entirely) and does not indicate a defect in this slice's own changes
  (every added package verified functional via direct, no-mount
  execution). **Ask:** on a host without this specific rootless/
  fuse-overlayfs limitation (a privileged Docker daemon, a different
  podman storage/idmap configuration, or simply a host where `/home` is
  writable or `$HOME` is not under `/home`), run
  `scripts/test-libsodium.sh` and `scripts/bmc.sh` once each and confirm
  green -- both already default to pull-by-digest per this slice's own
  code; once the push above lands, no further change is needed for
  either script to exercise the real path. If the SAME `/home`-mode-555
  wall reproduces on Corey's own machine too, that's a finding worth its
  own follow-up (e.g. patching the base image to ship a writable `/home`,
  or moving these scripts' mount target off `$HOME` entirely) rather than
  a one-session fluke -- report back either way.

## Resolved forks
- **GitHub Actions billing gate (2026-08-24):** resolved by Corey's
  direction to make the repo public (public repos get free hosted
  minutes). Flip executed 2026-08-24 with the RFC's pre-flip safety
  items: gitleaks full-history scan (5 findings, all false positives —
  Nim identifiers containing "Secret" + the published RFC 8032 TEST-1024
  vector), private vulnerability reporting enabled, fork-PR approval
  policy set to all_external_contributors, SECURITY.md intake rewritten.
  NOTE: this front-ran slice 5 out of RFC order (rulesets in slice 4 did
  not exist yet at flip time — checks were advisory-only while public,
  until slice 4 turned enforcement on). The remaining slice-5 items
  (CONTRIBUTING, README validation section, trust-root paragraph, ghcr
  anonymous-pull verification, re-run-green-under-public-conditions) are
  now DONE — see the slice 5 entry in the Slices list above for the full
  record.

## Key decisions (this session)
- 2026-08-24: stage 3 opened; RFC status → ACCEPTED. Stage-2 amendments
  committed together with this doc's creation.
- 2026-08-24: repo made PUBLIC on Corey's direction (resolves the Actions
  billing blocker; front-runs part of slice 5 — see Resolved forks).
- 2026-08-24: slice 1 done end-to-end (green + red through real pushes).
- 2026-08-24: slice 2 done end-to-end. Discovered/resolved in-slice (not
  escalated as a blocker): the proptest->nelli upstream rename turned out
  to be two renames (GitHub repo, already anticipated by the RFC, AND the
  Nim source tree itself, not anticipated) -- resolved by pinning the
  newest pre-source-rename commit rather than current main HEAD, keeping
  every existing `import proptest` call site unchanged. A future
  slice/RFC owns migrating to `import nelli` if/when that's wanted.
- 2026-08-24: slice 3 done end-to-end (green + red through real pushes).
  Discovered/resolved in-slice (not escalated as a blocker): the
  `ci-property.sh` `SELLO_IN_CONTAINER` dual-mode retrofit needed a
  matching one-line workflow edit (the property job's `run:` step never
  set the variable) -- caught by the first real push going red on the
  actual required check, not by local validation (local validation
  exercises the script's own two branches directly, never the workflow
  YAML that decides which branch a given CI job takes -- see the
  handoff's slice-3 TRAP note).
- 2026-08-24: slice 4 done end-to-end -- rulesets applied, enforcement
  live on `main`, branch model in effect from this point forward.
  Resolved in-slice (not escalated as a fork): the RFC's literal
  "green run, ONLY THEN apply" ordering is impossible once `ruleset-sync`
  is itself one of the six required jobs (it cannot be green before
  rulesets exist live) -- resolved by treating the code push's initial
  `ruleset-sync` red as the slice's own expected first red demo, applying
  immediately after, then re-running the same landed SHA to green before
  any enforcement-dependent demo began (full reasoning in the slice-4
  entry above). Push rulesets confirmed unavailable on this repo (personal
  account, not org-owned) independent of the separately-confirmed
  Enterprise-only `file_path_restriction` gate -- both verified live
  against disposable probe rulesets before writing any committed file,
  recorded honestly rather than faked, compensated by `policy-lint`.
  `PATCH .../rulesets/{id}` 404s outright (undocumented); `PUT` is the
  real update verb -- discovered by testing before the script was
  written, not from GitHub's docs.
- 2026-08-24: slice 5 done end-to-end -- CONTRIBUTING.md, README
  Validation section + badge, SECURITY.md trust-root section. Resolved
  in-slice (not escalated as a fork): the RFC's suggested
  `.../actions/permissions/fork-pr-workflows` endpoint name is wrong
  (404s) -- the real endpoint is
  `.../actions/permissions/fork-pr-contributor-approval`, found via a
  docs lookup and confirmed live before writing anything that depended on
  it. Owner-attested trust-root items (hardware-key 2FA, ghcr PAT
  scope/custody) filed as an open fork per the escalation rule, not
  treated as a blocker.
- 2026-08-24: slice 6 done end-to-end except one leg. `pr-checks.yml`
  landed via the branch flow (green branch run, green post-fast-forward
  main run), `CONTRIBUTING.md`/`CLAUDE.md` cross-checked, a same-account
  PR smoke test showed both PR-lane checks trigger and go green
  side-by-side with the independently-triggered push-lane checks
  (confirming the naming decision holds in practice), and a second
  same-account PR with a deliberately-broken README fence showed
  `pr-check-readme` go red while `pr-unit-linux-amd64-gcc` stayed green
  (targeted red demo). Resolved in-slice (not escalated, per the TRAP
  note's own instruction to verify first): read
  `scripts/gates-manifest-check.sh`/`scripts/ruleset-sync-check.sh`
  before writing anything -- both hard-code their workflow scan to
  `merge-gate.yml` specifically, confirming the new workflow file
  correctly needs no `scripts/lib/gates.txt` entry with no design change.
  The one leg NOT completed -- an actual fork PR from a genuinely
  external account shown held for approval -- requires a second GitHub
  account with no write access to the repo; none exists in this
  environment (`gh auth status` shows only the owner account; the two
  orgs the owner belongs to don't help, since GitHub's approval check
  keys off the PR author/actor's own collaborator status, not the fork's
  namespace, so a PR opened by the same `coreyleavitt` account from an
  org-owned fork would still not be held). Filed as a Corey-owned open
  fork with exact click-by-click instructions (including the forward-
  looking runner-targeting-workflow variant for the eventual slice 28),
  not worked around by creating a new account (explicitly out of scope
  per the task's own instruction).
- 2026-08-24: slice 7 done end-to-end except the real ghcr push (blocked
  on `write:packages` credentials, filed Corey-owned with the exact
  unblock artifact/commands) and the two "runs green locally" DoD legs
  for `scripts/test-libsodium.sh`/`scripts/bmc.sh` (blocked by a
  newly-diagnosed rootless-podman `/home`-mode-555 limitation, also filed
  Corey-owned). Two significant discoveries made and resolved/documented
  in-slice rather than silently worked around: (1) `clang`/`binutils`
  turned out to already be present in the base image, contrary to the
  RFC's round-2 finding -- verified empirically rather than assumed, and
  recorded as a finding rather than silently adding a redundant package;
  (2) the `ghcr.io/coreyleavitt/nim:2.2.10` TAG was observed to genuinely
  move mid-session (its linux/amd64 sub-manifest digest changed, no
  action by this session against that repo) while the already-pinned
  manifest-list digest stayed stable throughout -- a live, unplanned
  vindication of the RFC's own digest-pinning rationale, which directly
  motivated digest-pinning the Containerfile's own `FROM` line in the
  same slice rather than leaving it on the tag as found. arm64: no
  variant exists for the base image; recommended (not yet built)
  direct-Nim-install on a hosted `ubuntu-24.04-arm` runner for slice 11,
  mirroring the already-planned macOS-arm64 pattern, since the base
  image's build source is explicitly out of this repo's scope.
- 2026-08-24: slice 8 (clang-backend job) DONE end-to-end, first matrix
  leg, no core-arithmetic bug surfaced (the escalation rule was not
  triggered).

  **Mechanism.** `scripts/test.sh` gained one optional leading argument,
  `--cc <name>` (must be first if present -- a bespoke two-token check,
  not `getopts`, since this script has exactly one flag-with-value),
  threading `--cc:<name>` into every `nim c` invocation the script's
  `cmd` string builds; unset, Nim resolves its own gcc default unchanged.
  `scripts/ci-property.sh` accepts and forwards `--cc <name>` verbatim to
  `scripts/test.sh` with no parsing of its own -- in its in-container body
  via `"$@"`, and in its host-mode podman recursion via a `printf %q`-
  requoted reconstruction of the recursive command line (previously
  argument-less). The ARGUMENT form (not an env var like `SELLO_CC`) was
  chosen specifically so `scripts/lib/gates.txt`'s two new lines read as
  literal, self-documenting commands (`scripts/test.sh --cc clang`,
  `scripts/ci-property.sh --cc clang`) -- a reviewer sees exactly which
  backend each check exercises with no side-channel lookup, and
  `merge-gate.sh`/the workflow's `run:` steps stay the same one-code-path
  shape they always were (RFC-005 Part B's build-path invariant: one
  script serves both backends, no forked clang-flavored script). No
  sello-dev dependency: slice 7 already verified clang/clang22 present in
  the base `ghcr.io/coreyleavitt/nim:2.2.10` image, re-confirmed live by
  this slice's own green run.

  **Platform-identity canary.** New `scripts/lib/toolchain-canary.sh`
  (executable bit set via `git update-index --chmod=+x`, the standing
  slice-1 trap). `scripts/test.sh` routes the FIRST unit test file's
  compile through it instead of a bare `nim c`: the helper runs the given
  `nim c ... --listCmd -f -r <file>` invocation (`--listCmd` prints every
  command Nim executes; `-f`/`--forceBuild` guarantees a fresh compiler
  invocation line even against a warm nimcache), captures the combined
  output, greps it for the actual C-compiler-invocation line, and asserts
  the requested compiler's name appears in it -- proof Nim really invoked
  that binary, not merely that the flag was accepted (a bare `clang
  --version` check would only prove clang exists on `PATH`). Runs
  unconditionally, gcc included ("for free" per the task brief: the cost
  is one already-necessary compile, not an extra one). Live evidence, run
  `32739472628` (below): `unit-linux-amd64-gcc`'s canary line reads `CC:
  system/exceptions.nim: gcc -c -w -fmax-errors=3 ...`; `unit-linux-amd64-
  clang`'s reads `CC: system/exceptions.nim: clang -c -w -ferror-limit=3
  ...` -- the two compilers' own distinct diagnostic-limit flag spellings
  (`-fmax-errors` vs `-ferror-limit`) are independent confirmation these
  are genuinely different binaries, not a renamed/aliased one.

  **Two new jobs**, same digest-pinned container as their gcc siblings:
  `unit-linux-amd64-clang` (`scripts/ci-setup.sh && SELLO_IN_CONTAINER=1
  scripts/test.sh --cc clang`) and `property-linux-amd64-clang`
  (`SELLO_IN_CONTAINER=1 scripts/ci-property.sh --cc clang`), plus their
  `scripts/lib/gates.txt` entries -- eight required jobs total.

  **Ruleset ordering, as executed (matches the brief's predicted
  ordering exactly):** `scripts/ruleset-apply.sh` (dry run first, printed
  the expected two-line diff adding `unit-linux-amd64-clang`/`property-
  linux-amd64-clang` to `main`'s required-check array and nothing else)
  then `scripts/ruleset-apply.sh --apply`, run LOCALLY on the already-
  committed branch BEFORE the branch was pushed -- `ruleset-apply.sh`
  reads only local files (`scripts/lib/gates.txt`) and mutates live
  GitHub state via `gh api`, so it needs no push to run. This meant the
  branch's own first `ruleset-sync` run compared an ALREADY-updated live
  ruleset against an ALREADY-updated committed manifest and passed clean
  on the very first push -- no red/apply/re-run cycle was needed this
  time (unlike slice 4's bootstrap, where the ruleset didn't exist live
  at all yet). The ordering held because `main`'s ruleset only enforces
  on `refs/heads/main` pushes (`target: "branch"`, condition scoped to
  `main`) -- branch pushes to `rfc-005-slice8` were never blocked by the
  live edit regardless of ordering; applying first only mattered for
  `ruleset-sync`'s own drift comparison, which it satisfied immediately.

  **Runs and evidence.**
  - Push 1 (mechanism + jobs, commit `60d7d02`): run `32739472628`, ALL
    EIGHT jobs green on the first push, including `ruleset-sync` (the
    apply-before-push ordering above). Timings: `unit-linux-amd64-gcc`
    59s, `unit-linux-amd64-clang` 54s, `property-linux-amd64-gcc` 9m7s,
    `property-linux-amd64-clang` 9m45s (clang's property leg ran ~38s
    slower than gcc's -- the one clang-vs-gcc timing difference observed;
    everything else was within noise) -- the two property jobs ran in
    parallel, so wall-clock cost of adding the clang leg was the DELTA
    between the two property jobs' durations, not their sum. No other
    clang-vs-gcc behavioral difference observed (no new warnings, same
    test results) -- sello's C surface (through Nim's own generated C) is
    evidently clean under clang's stricter defaults too.
  - Push 2 (red demo, commit `cc6e3be`): run `32740549790`. Hardcoded the
    canary's expected-compiler argument to the literal `"gcc"` in
    `scripts/test.sh` (was `$cc_name`) -- "claims gcc always" per the
    task brief's own suggested cleanest red (canary inversion), a
    one-line, trivially-revertible change to the ONE script both backends
    share. Result: `unit-linux-amd64-clang` RED (job `97473701331`, 31s)
    and `property-linux-amd64-clang` RED (job `97473701198`, 1m15s) --
    the real actual-compiler-vs-claimed-compiler mismatch the canary
    exists to catch, on the real new check names, through a real push;
    all six other jobs (both gcc legs, both docs jobs, all three
    governance jobs including `ruleset-sync`) stayed green, confirming
    the red was scoped exactly to the inverted assertion and nothing
    else. Captured failure line (`unit-linux-amd64-clang`, job
    `97473701331`): `toolchain canary: FAIL -- expected the C compiler
    invocation to contain 'gcc', but observed: CC: system/exceptions.nim:
    clang -c -w -ferror-limit=3 ...`.
  - Push 3 (revert `scripts/test.sh` to `$cc_name` -- confirmed
    byte-identical to `60d7d02` via `git diff` before committing -- plus
    this handoff/CLAUDE.md doc commit): run id and result recorded in the
    slice's own close-out note below once landed.
  - Fast-forward to `main`: run id recorded below once landed.

  **Traps for slices 9–13 (recorded per this slice's own findings, not
  the RFC's a priori text):**
  - The `--cc <name>` / canary pattern generalizes directly to slice 10's
    `--cpu:i386` job (Nim's own `--cpu:` flag, same "thread one argument
    through `scripts/test.sh`, assert an identity fact from the build's
    own output" shape) -- that slice's own canary ("pointers are 4 bytes")
    is a runtime assertion inside the compiled test binary instead of a
    grep over `--listCmd` output, but the design principle (prove the
    claim from something the build/run itself produced, not from the
    flag alone) carries over unchanged.
  - `--listCmd -f` on the canary's forced first-file rebuild adds a few
    seconds per run (a full rebuild of `field.nim`/`scalar.nim`/etc.,
    once) -- negligible against the ~9-10 minute property-job floor, but
    worth knowing before assuming a leg's wall-clock is 100% test time.
  - Applying `scripts/ruleset-apply.sh --apply` BEFORE pushing (rather
    than after, as slice 4's bootstrap had to) is safe and simpler
    whenever the ruleset already exists live and only its required-check
    SET is changing (not its existence) -- do this by default for future
    slices adding required checks; only fall back to the push-then-apply-
    then-rerun dance slice 4 used if a ruleset itself doesn't exist yet.
  - `gh run watch <id>` without `--exit-status` still exits nonzero when
    the underlying run fails but does not itself raise a shell error worth
    treating as a tool failure -- useful for deliberately observing a red
    demo run to completion without the exit code aborting a script; use
    `--exit-status` only when a nonzero run SHOULD stop the calling flow
    (i.e., for the real green-required pushes, not the deliberate red
    one).

## Notes for resuming sessions
- Environment: no host Nim; podman + ghcr.io/coreyleavitt/nim:2.2.10;
  network session-dependent — do network steps early. `rm` aliased
  interactive on host — use `rm -f`.
- gh authenticated as coreyleavitt (repo, workflow scopes; admin on the
  repo -- required for `scripts/ruleset-apply.sh`). Remote:
  git@github.com:coreyleavitt/sello.git (public since the go-public flip
  recorded above; owner account is a personal User, not an org -- see
  slice 4's push-ruleset finding, which depends on this).
- Slice-N DoDs include red-path demos through the real entry point (real
  push, real red check) — budget scratch branches for them.
- Trap (slice 6): `gh pr close --delete-branch` silently switches the
  local checkout to `main` as a side effect (it has to, to delete the
  branch you were on). Under the enforced branch model, a `git commit`
  issued right after a PR-close/smoke-test sequence with no explicit
  `git checkout -b` first lands directly on local `main` -- harmless
  until pushed (the ruleset rejects a direct push to `main` outright),
  but it's a wasted commit that has to be moved onto a real branch
  (`git branch <name> <sha>`, `git reset --hard origin/main`,
  `git checkout <name>`) before it can go through the flow. Caught this
  session before pushing; the fix cost one avoidable extra branch cycle.
  Always `git branch --show-current` (or just habitually `checkout -b`)
  immediately before any commit that follows a PR-close call.
- Trap (slice 1): this host's /tmp is a small shared tmpfs holding podman's
  default storage and was 100% full — local podman validation needed
  `podman --root <dir-under-/home> --runroot <dir-under-/home>
  --storage-driver overlay --storage-opt overlay.mount_program=/usr/bin/fuse-overlayfs`,
  torn down with `podman unshare rm -rf`. Expect the same in slices 3/7+.
- Note: pushing slice 1 also pushed 8 previously-unpushed local commits
  (RFC-006 slices + stage-3 open) to origin/main — expected, recorded.
- Trap (slice 7, NEW — distinct from the slice-1 /tmp trap above): actually
  RUNNING a container (`podman run`) with the project's standard `-v
  "$HOME/.cache/milpa:$HOME/.cache/milpa"` mount fails on this host with
  `crun: mkdir \`/home/corey\`: Permission denied` — the base image ships
  `/home` at mode 555 (no write bit for anyone), and this host's rootless
  podman + fuse-overlayfs cannot auto-mkdir a bind-mount target under it
  (confirmed: `--userns=keep-id`, `--mount` instead of `-v`, and an extra
  `Containerfile` `RUN mkdir` layer were all tried and all hit the same
  wall; other top-level dirs the image ships writable, e.g. `/tmp` at
  1777, mount fine). `podman build` is UNAFFECTED (only `run` hits this) —
  building/verifying tools via direct no-mount `podman run ... bash -c`
  also works fine; only the exact `$HOME`-path-mount pattern breaks. Also
  discovered: once this bug fires once on a given alt-root store, it
  leaves a permission-broken fuse-overlayfs whiteout marker
  (`.wh..wh..opq`) that poisons that blob's cached extraction for every
  future container on that SAME store (even unrelated images sharing the
  tainted blob) until manually fixed (`podman unshare chmod -R u+w
  <root>` before `podman unshare rm -rf`, or just abandon the store and
  use a fresh `--root`/`--runroot` pair — cheaper given /home's 981G
  free). Full diagnosis + the exact isolation sequence in slice 7's own
  handoff entry and its Open forks ask to Corey. Unknown yet whether this
  reproduces on Corey's own machine — treat as session-specific until
  confirmed otherwise, but do NOT assume `-v "$HOME/...":"$HOME/..."`
  mounts "just work" on this host without testing first in future
  slices (8+ don't need this mount pattern themselves, but any future
  local validation of test.sh/test-libsodium.sh/ct.sh/fuzz.sh/bmc.sh on
  THIS host should expect it).
