#!/usr/bin/env bash
# scripts/lib/notify-failure.sh -- RFC-005 slice 26 (Nightly part 3:
# canaries + notifications). Shared "open or update a pinned GitHub
# issue" notification primitive, used by BOTH
# .github/workflows/nightly.yml's `notify` job (release-blocking
# failures: fuzz continuity, cranked properties) and
# .github/workflows/toolchain-canary.yml's own `notify` job (advisory-
# only compiler/resolver drift) -- one audited script, not two hand-typed
# copies of the same gh-issue-plus-GraphQL-pin dance (RFC-005 Part B's
# build-path invariant, extended here to the notification path). The two
# callers use DIFFERENT marker labels/issues (see each workflow's own
# `notify` job comment for the "separate issues, clear attribution"
# decision and its rationale) -- this script itself is label-agnostic,
# driven entirely by its arguments.
#
# Mechanism (RFC-005 Part B: "a failure step opens/updates a pinned
# GitHub issue -- publicly visible, self-documenting, immune to
# email-settings drift"):
#   1. Search for an OPEN issue carrying the marker label. Found: append a
#      comment (`gh issue comment`) with this run's own failure summary --
#      the issue's timeline becomes the failure history, satisfying "one
#      issue reused across repeat failures, not issue spam" (this slice's
#      own task text) without this script tracking any state of its own
#      between runs (GitHub's own issue/label state IS the state).
#   2. Not found: create a new issue (`gh issue create`) carrying the
#      marker label, then PIN it via the GraphQL `pinIssue` mutation
#      (`gh api graphql` -- REST has no issue-pin endpoint at all, verified
#      against the REST API reference before writing this script; GraphQL
#      is the only surface that exposes pinning).
#
# Pinning is BEST-EFFORT, by design (this slice's own task text: "if only
# the repo owner token can pin, record that and have the workflow
# ensure-pin best-effort"): the default Actions GITHUB_TOKEN, scoped
# `issues: write` on the calling job (a job-level `permissions:` override
# -- see each calling workflow's own job comment for why this is scoped
# per-job rather than widened at the workflow level), was empirically
# confirmed SUFFICIENT for this repo during this slice's own DoD demo (see
# docs/rfc-005-validation-infra.handoff.md's slice 26 entry for the run id
# and issue URL) -- but a pin failure (a future token-scope regression, or
# GitHub's own hard limit of 3 pinned issues per repo) is logged loudly
# and does NOT fail this script: the notification itself (issue created,
# labeled, publicly visible in the repo's Issues tab) is the load-bearing
# behavior this slice's DoD actually asks for; a missing PIN is a lesser,
# recoverable degradation on top of a notification that already landed,
# not a reason to make the calling job red for a second, unrelated
# reason.
#
# Usage:
#   scripts/lib/notify-failure.sh <marker-label> <issue-title> <body-file>
#
# Requires: `gh` authenticated (GH_TOKEN/GITHUB_TOKEN in the environment,
# as every Actions job already carries via `env: GH_TOKEN: ${{ github.token
# }}` on the calling step) with at least `issues: write` on the calling
# job.
set -euo pipefail

marker_label="${1:?usage: notify-failure.sh <marker-label> <issue-title> <body-file>}"
issue_title="${2:?usage: notify-failure.sh <marker-label> <issue-title> <body-file>}"
body_file="${3:?usage: notify-failure.sh <marker-label> <issue-title> <body-file>}"

if [[ ! -f "$body_file" ]]; then
  echo "notify-failure: body file '$body_file' does not exist -- nothing to post." >&2
  exit 1
fi

repo="${GH_REPO:-${GITHUB_REPOSITORY:-}}"
if [[ -z "$repo" ]]; then
  echo "notify-failure: no repo specified -- set GH_REPO or GITHUB_REPOSITORY." >&2
  exit 1
fi

# Idempotent label ensure: `gh label create` errors if the label already
# exists -- that specific failure is expected on every run after the
# first and is deliberately swallowed (not the script's job to track
# "did I create this label before").
gh label create "$marker_label" --repo "$repo" --color "B60205" \
  --description "RFC-005 nightly/canary notification marker (scripts/lib/notify-failure.sh)" \
  >/dev/null 2>&1 || true

existing_number="$(gh issue list --repo "$repo" --label "$marker_label" --state open --json number --jq '.[0].number // empty' 2>/dev/null || true)"

if [[ -n "$existing_number" ]]; then
  echo "notify-failure: found existing open issue #$existing_number (label '$marker_label') -- commenting rather than creating a new one."
  gh issue comment "$existing_number" --repo "$repo" --body-file "$body_file"
  echo "notify-failure: OK -- commented on https://github.com/$repo/issues/$existing_number"
else
  echo "notify-failure: no open issue labeled '$marker_label' -- creating one."
  issue_url="$(gh issue create --repo "$repo" --title "$issue_title" --label "$marker_label" --body-file "$body_file")"
  echo "notify-failure: created $issue_url"
  new_number="${issue_url##*/}"

  # --- Pin (best-effort; GraphQL only -- REST has no pin endpoint). -----
  node_id="$(gh api "repos/$repo/issues/$new_number" --jq '.node_id' 2>/dev/null || true)"
  if [[ -n "$node_id" ]]; then
    if gh api graphql -f query='mutation($id: ID!) { pinIssue(input: {issueId: $id}) { issue { id } } }' -f id="$node_id" >/dev/null 2>&1; then
      echo "notify-failure: OK -- pinned $issue_url"
    else
      echo "notify-failure: WARNING -- could not pin $issue_url (GraphQL pinIssue mutation failed -- the token may lack sufficient scope, or this repo already has the maximum of 3 pinned issues). The issue itself was still created and labeled; not failing this script over a best-effort pin (see this script's own header comment)." >&2
    fi
  else
    echo "notify-failure: WARNING -- could not resolve a GraphQL node_id for issue #$new_number -- skipping the pin attempt (best-effort)." >&2
  fi
fi
