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
  lane. Next up: slice 7 (image consolidation, Phase 1).

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

Phase 1 — matrix (7 first, then 8–13 independent):
- [ ] 7. Image consolidation (sello-dev to ghcr by digest; package enumeration; arm64 manifest check)
- [ ] 8. clang-backend job
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
