#!/usr/bin/env bash
# scripts/ruleset-apply.sh — RFC-005 slice 4: the maintainer-run,
# idempotent applier for sello's committed GitHub rulesets
# (.github/rulesets/*.json). NOT a CI job (RFC-005 Part B's Rulesets
# paragraph: the ruleset JSON files are committed and reviewed; this
# script is what turns a reviewed diff into the live GitHub state) --
# needs an admin-scoped `gh` session (this repo's owner account), which no
# CI job carries.
#
# What it does, per committed file (.github/rulesets/*.json, sorted --
# today: evidence.json, main.json, tags.json):
#   1. Read the committed JSON.
#   2. If it has a `required_status_checks` rule (today: only main.json),
#      splice in the required-check array GENERATED from
#      scripts/lib/gates.txt via scripts/lib/gates.sh's load_gates() --
#      never hand-written here or in the committed file (RFC-005 Part B:
#      "the required-check array is generated, never hand-written"). The
#      committed file's own required_status_checks array is therefore
#      always an empty placeholder; this script (and
#      scripts/ruleset-sync-check.sh, on the read side) are the only two
#      places that ever fill it in, both from the same source.
#   3. Look up whether a live ruleset with that `name` already exists
#      (GET .../rulesets, match by name). CREATE (POST) if not; UPDATE
#      (PUT .../rulesets/{id} -- NOT PATCH, which returns a bare 404;
#      verified live against a disposable probe ruleset before this
#      script was written) if so -- so re-running this script after a
#      committed-JSON edit converges live state to match, and re-running
#      it with NO edit is a no-op (idempotent, per RFC-005 Part B: "every
#      check-adding slice edits the manifest in the same commit as the
#      workflow change and regenerates").
#
# The push ruleset (.github/rulesets/unavailable/push-workflow-and-
# policy-paths.json) is INTENTIONALLY not applied -- see that file's own
# header fields for the live-verified reason (push-target rulesets require
# an org-owned repo; file_path_restriction is plan-gated independent of
# target) and CLAUDE.md's Rulesets section for the compensating control
# (scripts/policy-lint.sh). This script glob-matches only
# .github/rulesets/*.json at the top level, which the unavailable/
# subdirectory placement deliberately excludes from, so there is no
# special-case skip logic to maintain here -- the directory boundary IS
# the skip.
#
# Safety valve (this script's own addition, not explicitly mandated by
# the RFC text but consistent with this codebase's standing caution
# culture -- e.g. baseline_update's CI guard, the release gate's stale-
# accept input): DEFAULT MODE IS DRY-RUN. It prints, per ruleset, whether
# it would CREATE or UPDATE, and (for UPDATE) a normalized diff between
# the current live state and what would be sent, but makes NO API
# mutation. Pass --apply to actually PUT/POST. This matters because
# applying the "main" ruleset for the first time is the exact moment
# direct pushes to main stop working (RFC-005 slice 4's own "CRITICAL
# SEQUENCING" -- get a green run on main FIRST, only then run this script
# with --apply).
#
# Usage:
#   scripts/ruleset-apply.sh              # dry run (default, no mutation)
#   scripts/ruleset-apply.sh --apply      # apply for real
#   scripts/ruleset-apply.sh -h | --help
#
# Requires: gh (authenticated, admin on the target repo), jq. Reads the
# target repo from `gh repo view --json nameWithOwner` (the checkout's own
# `origin` remote), not hand-typed, so this script has no hardcoded
# owner/repo string to drift from the actual remote.
set -euo pipefail
cd "$(dirname "$0")/.."

usage() {
  cat <<'EOF'
Usage: scripts/ruleset-apply.sh [--apply]

Applies sello's committed GitHub rulesets (.github/rulesets/*.json) to the
live repository. DEFAULT IS DRY-RUN -- prints the planned CREATE/UPDATE
per ruleset and a diff for updates, but makes no API mutation. Pass
--apply to perform the real gh api PUT/POST calls.

Idempotent: running --apply twice with no committed-file change in
between makes the same PUT/POST calls (GitHub's API has no partial-
update semantics here) but leaves live state unchanged -- a true no-op in
effect, if not in wire-call count.

The main ruleset's required_status_checks array is GENERATED from
scripts/lib/gates.txt on every run of this script -- never read literally
from the committed .github/rulesets/main.json, which carries an empty
placeholder for that field by design.

The push ruleset (workflow/rulesets/gates.txt path restriction) is NOT
applied -- see .github/rulesets/unavailable/push-workflow-and-policy-
paths.json's own header for the live-verified reason (unavailable on this
repo's plan/ownership tier) and CLAUDE.md's Rulesets section for the
compensating control.

Requires: gh (authenticated, admin on the target repo), jq.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

apply_mode=0
if [[ "${1:-}" == "--apply" ]]; then
  apply_mode=1
elif [[ -n "${1:-}" ]]; then
  echo "ruleset-apply: unknown argument '$1'. See --help." >&2
  exit 2
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "ruleset-apply: gh not found on PATH." >&2
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "ruleset-apply: jq not found on PATH." >&2
  exit 1
fi

source "$(dirname "$0")/lib/gates.sh"
load_gates

if [[ "${#gate_check_names[@]}" -eq 0 ]]; then
  echo "ruleset-apply: scripts/lib/gates.txt parsed to zero gates -- refusing to generate an empty required-check array." >&2
  exit 1
fi

repo="$(gh repo view --json nameWithOwner -q .nameWithOwner)"
echo "ruleset-apply: target repo = $repo"
if [[ "$apply_mode" -eq 1 ]]; then
  echo "ruleset-apply: mode = APPLY (live mutation)"
else
  echo "ruleset-apply: mode = DRY RUN (no mutation -- pass --apply to apply for real)"
fi

# Generated required-check array, [{"context": name}, ...], sorted -- the
# one place this script builds it, from gates.txt alone.
required_checks_json="$(printf '%s\n' "${gate_check_names[@]}" | sort | jq -R '{context: .}' | jq -s '.')"
echo "ruleset-apply: generated required-check array from scripts/lib/gates.txt (${#gate_check_names[@]} check(s)):"
printf '  %s\n' "${gate_check_names[@]}" | sort

canon_filter="$(dirname "$0")/lib/ruleset-canon.jq"
source "$(dirname "$0")/lib/jq-canon.sh"

overall_status=0

for file in .github/rulesets/*.json; do
  [[ -e "$file" ]] || continue

  name="$(jq -r '.name' "$file")"
  echo ""
  echo "======================================================================="
  echo "ruleset-apply: $file (name=\"$name\")"
  echo "======================================================================="

  # Splice the generated required-check array in (a no-op for rulesets
  # with no required_status_checks rule, e.g. evidence.json/tags.json).
  spliced="$(JQ_CANON_EXPR='set_required_checks($checks)' JQ_CANON_FILE="$file" jq_canon --argjson checks "$required_checks_json")"

  existing_id="$(gh api "repos/$repo/rulesets" --jq ".[] | select(.name == \"$name\") | .id" | head -n1)"

  if [[ -z "$existing_id" ]]; then
    action="CREATE"
  else
    action="UPDATE (id=$existing_id)"
  fi
  echo "ruleset-apply: planned action: $action"

  if [[ -n "$existing_id" ]]; then
    live="$(gh api "repos/$repo/rulesets/$existing_id")"
    live_canon="$(echo "$live" | JQ_CANON_EXPR='normalize' jq_canon | jq -S .)"
    spliced_canon="$(echo "$spliced" | JQ_CANON_EXPR='normalize' jq_canon | jq -S .)"
    if [[ "$live_canon" == "$spliced_canon" ]]; then
      echo "ruleset-apply: live already matches committed (no-op diff)."
    else
      echo "ruleset-apply: diff (live -> committed):"
      diff <(echo "$live_canon") <(echo "$spliced_canon") || true
    fi
  fi

  if [[ "$apply_mode" -eq 1 ]]; then
    if [[ -n "$existing_id" ]]; then
      # PUT, not PATCH -- verified live against a disposable probe ruleset
      # before this script was written: PATCH .../rulesets/{id} returns a
      # bare 404, PUT with the identical body succeeds and replaces the
      # ruleset's full definition (matching this deliverable's own "gh api
      # PUT (create-or-update by ruleset name)" wording).
      echo "$spliced" | gh api "repos/$repo/rulesets/$existing_id" -X PUT --input - >/dev/null
      echo "ruleset-apply: UPDATED ruleset \"$name\" (id=$existing_id)."
    else
      new_id="$(echo "$spliced" | gh api "repos/$repo/rulesets" -X POST --input - --jq '.id')"
      echo "ruleset-apply: CREATED ruleset \"$name\" (id=$new_id)."
    fi
  else
    echo "ruleset-apply: dry run -- no API mutation performed."
  fi
done

echo ""
echo "======================================================================="
echo "ruleset-apply: push ruleset NOT applied (unavailable on this repo's"
echo "plan/ownership tier -- see .github/rulesets/unavailable/push-workflow-"
echo "and-policy-paths.json's header and CLAUDE.md's Rulesets section)."
echo "======================================================================="

exit "$overall_status"
