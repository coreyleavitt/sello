# RFC-005 (validation infrastructure) — handoff

- **Stage:** 3 (tdd slice grind)   •   **Round:** n/a
- **Resume:** `/loop /tdd rfc-005 til done`
- Stage 3 opened 2026-08-24 (sign-off = grind launch). Slices 1–3 committed
  to `main` directly. Slice 4 (DONE 2026-08-24) established the branch
  model and turned on enforcement -- as of slice 4's own close-out commit,
  `main` rejects direct pushes; slices 5+ land on `rfc-*` branches, green
  CI, then `git push origin <branch>:main` to fast-forward. Slice 5 (DONE
  2026-08-24) closed out the remaining go-public deliverables (see the
  Slices list and Open forks below). Next up: slice 6 (contribution
  lane).

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
        (the repo has been public since before any of them started).
        This slice's own branch-then-fast-forward run pair (run ids
        below, once landed) is cited as the concrete verification rather
        than re-running anything for its own sake; the most recent
        pre-existing green main run under public conditions before this
        slice started was `32720085738` (push, `c6f6246`, 2026-08-24
        11:05:45Z).
      - **No red demo** (stated explicitly per the DoD): this slice is
        docs/verification, not a new gate -- there is no natural red path
        to demonstrate, and slice 4's enforced-rejection-of-a-direct-push
        evidence already covers the branch model this slice's own commits
        flow through. Not re-demoed here.
      - Branch `rfc-005-slice5` green run: `<RUN_ID_PENDING>`; fast-forward
        to `main`: `<MAIN_RUN_ID_PENDING>`. (Filled in below once the push
      lands -- see the closing paragraph of this entry.)
- [ ] 6. Contribution lane (pull_request cheap subset; fork-PR held-for-approval demo).
      Note: the fork-PR approval POLICY was live-verified as part of
      slice 5 above (`all_external_contributors`, via the corrected
      `fork-pr-contributor-approval` endpoint) -- but the `pull_request`
      workflow itself and its held-for-approval end-to-end demo remain
      entirely unstarted; slice 5 does not advance this slice.

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
- Trap (slice 1): this host's /tmp is a small shared tmpfs holding podman's
  default storage and was 100% full — local podman validation needed
  `podman --root <dir-under-/home> --runroot <dir-under-/home>
  --storage-driver overlay --storage-opt overlay.mount_program=/usr/bin/fuse-overlayfs`,
  torn down with `podman unshare rm -rf`. Expect the same in slices 3/7+.
- Note: pushing slice 1 also pushed 8 previously-unpushed local commits
  (RFC-006 slices + stage-3 open) to origin/main — expected, recorded.
