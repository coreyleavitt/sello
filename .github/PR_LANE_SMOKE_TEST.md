# PR lane smoke test

Scratch file for RFC-005 slice 6's same-account PR smoke test: opening a
PR from this branch against `main` exists solely to prove
`.github/workflows/pr-checks.yml`'s two jobs (`pr-unit-linux-amd64-gcc`,
`pr-check-readme`) trigger and go green on a `pull_request` event. The PR
is closed unmerged and this branch is deleted immediately after; this
file never lands on `main`.
