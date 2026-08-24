# RFC-005 (validation infrastructure) — handoff

- **Stage:** 3 (tdd slice grind)   •   **Round:** n/a
- **Resume:** `/loop /tdd rfc-005 til done`
- Stage 3 opened 2026-08-24 (sign-off = grind launch). Slices 1–3 commit to
  `main` directly (current practice); slice 4 establishes the branch model,
  after which slices land on `rfc-*` branches and fast-forward to `main`.

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
- [ ] 3. Gates manifest + merge-gate.sh local runner + workflow-vs-manifest drift check
- [ ] 4. Rulesets + branch model (committed JSON, apply script, waiver, policy-lint; red demos)
- [ ] 5. Go public (history scan, SECURITY.md, approval-for-all flip, CONTRIBUTING, minimal README section)
- [ ] 6. Contribution lane (pull_request cheap subset; fork-PR held-for-approval demo)

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
- (none)

## Resolved forks
- **GitHub Actions billing gate (2026-08-24):** resolved by Corey's
  direction to make the repo public (public repos get free hosted
  minutes). Flip executed 2026-08-24 with the RFC's pre-flip safety
  items: gitleaks full-history scan (5 findings, all false positives —
  Nim identifiers containing "Secret" + the published RFC 8032 TEST-1024
  vector), private vulnerability reporting enabled, fork-PR approval
  policy set to all_external_contributors, SECURITY.md intake rewritten.
  NOTE: this front-runs slice 5 out of RFC order (rulesets in slice 4 do
  not exist yet — checks are advisory-only while public). Remaining
  slice-5 items still due in order: CONTRIBUTING, README validation
  section, trust-root paragraph, ghcr anonymous-pull verification,
  re-run-green-under-public-conditions.

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

## Notes for resuming sessions
- Environment: no host Nim; podman + ghcr.io/coreyleavitt/nim:2.2.10;
  network session-dependent — do network steps early. `rm` aliased
  interactive on host — use `rm -f`.
- gh authenticated as coreyleavitt (repo, workflow scopes). Remote:
  git@github.com:coreyleavitt/sello.git (private).
- Slice-N DoDs include red-path demos through the real entry point (real
  push, real red check) — budget scratch branches for them.
- Trap (slice 1): this host's /tmp is a small shared tmpfs holding podman's
  default storage and was 100% full — local podman validation needed
  `podman --root <dir-under-/home> --runroot <dir-under-/home>
  --storage-driver overlay --storage-opt overlay.mount_program=/usr/bin/fuse-overlayfs`,
  torn down with `podman unshare rm -rf`. Expect the same in slices 3/7+.
- Note: pushing slice 1 also pushed 8 previously-unpushed local commits
  (RFC-006 slices + stage-3 open) to origin/main — expected, recorded.
