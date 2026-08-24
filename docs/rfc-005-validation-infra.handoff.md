# RFC-005 (validation infrastructure) — handoff

- **Stage:** 3 (tdd slice grind)   •   **Round:** n/a
- **Resume:** `/loop /tdd rfc-005 til done`
- Stage 3 opened 2026-08-24 (sign-off = grind launch). Slices 1–3 commit to
  `main` directly (current practice); slice 4 establishes the branch model,
  after which slices land on `rfc-*` branches and fast-forward to `main`.

## Slices (32 — see RFC "Slices" section for full DoDs)

Phase 0 — bootstrap (private repo):
- [~] 1. CI build path, minimal — CODE LANDED on main (`c3ca4cc`), local
      in-container validation green (12 unit files pass, proptest SKIPPED
      banner confirmed). DoD green-run/red-demo BLOCKED: GitHub Actions
      refuses all jobs at the account level (billing — "recent account
      payments have failed or your spending limit needs to be increased").
      Resume: fix billing, then `gh run rerun 32697367451` (green + banner
      check), then the scratch-branch red demo.
- [ ] 2. milpa-in-CI + property/check-readme jobs (proptest SHA pin, skip-banner-ABSENT assert)
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
- **GitHub Actions billing gate (2026-08-24):** every Actions job on the
  coreyleavitt account is refused before provisioning ("recent account
  payments have failed or your spending limit needs to be increased") —
  blocks the CI-run DoD of slice 1 and all remaining CI slices. Needs
  GitHub Settings → Billing & plans. The loop polls hourly via
  `gh run rerun` and resumes automatically once a run starts.

## Key decisions (this session)
- 2026-08-24: stage 3 opened; RFC status → ACCEPTED. Stage-2 amendments
  committed together with this doc's creation.

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
