#!/usr/bin/env bash
# scripts/ruleset-sync-check.sh — RFC-005 slice 4: the "ruleset-sync" CI
# check. Asserts the FULL canonicalized live ruleset state equals the
# committed .github/rulesets/*.json state -- names, bypass list,
# enforcement flags, ALL rulesets (RFC-005 Part B's Rulesets paragraph,
# strengthened in round 2 over a names-only comparison that "left the
# empty bypass list and force-push flags unenforced after day 1") -- plus
# two name-equality legs (main ruleset's required checks vs.
# scripts/lib/gates.txt, and gates.txt vs. the workflow's own job names)
# that give a specific, readable diagnostic for the single most common
# drift shape even though the full canonical diff above already covers
# it structurally.
#
# Container vs. plain runner: like gates-manifest-sync, this needs no Nim
# toolchain, no podman, no milpa -- it is a network read (the GitHub API)
# plus a text/JSON comparison against committed files, so it runs on a
# plain `ubuntu-latest` runner (see merge-gate.yml's own job comment).
# Still exactly one scripts/ invocation (the build-path invariant holds
# regardless of container vs. plain runner).
#
# Live ruleset reads work ANONYMOUSLY on a public repo -- verified
# empirically (curl with no Authorization header against both the list
# and single-ruleset GET endpoints succeeded, live, before this script
# was written) -- so this script never requires `gh auth login`. It DOES
# use a bearer token when GITHUB_TOKEN (or GH_TOKEN) is set in the
# environment (the CI job passes `GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN
# }}`), purely for the higher authenticated rate limit (5000/hr vs. 60/hr
# anonymous) on a check that runs on every push with no path filter --
# not because reads require it. Uses plain `curl` + `jq`, not `gh api`, so
# this script has no dependency on the `gh` CLI being installed OR
# authenticated at all, on either host or CI.
#
# Waiver mechanism (scripts/lib/waivers.txt via scripts/lib/waivers.sh):
# a live main ruleset missing a manifest-required check FAILS unless an
# ACTIVE (non-expired) waiver entry names it -- in which case this script
# excludes that check from the "expected" set for comparison purposes
# (so the canonical diff passes) but logs the waiver loudly (name,
# expiry, reason) on every run, so a waived gap is never silent. An
# EXPIRED waiver does NOT excuse a missing check -- this script fails
# loudly, naming the expired waiver specifically, in addition to the
# generic diff. See scripts/lib/waivers.txt's own header for the full
# design and rationale (why a separate file, not a gates.txt column).
#
# Usage:  scripts/ruleset-sync-check.sh
set -uo pipefail
cd "$(dirname "$0")/.."

if ! command -v jq >/dev/null 2>&1; then
  echo "ruleset-sync-check: jq not found on PATH." >&2
  exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "ruleset-sync-check: curl not found on PATH." >&2
  exit 1
fi

source "$(dirname "$0")/lib/gates.sh"
load_gates
source "$(dirname "$0")/lib/waivers.sh"
load_waivers
source "$(dirname "$0")/lib/workflow-job-names.sh"

# Determine owner/repo from the origin remote (works in CI too --
# actions/checkout leaves origin pointed at the repo being built), no
# hardcoded string to drift from the actual remote.
origin_url="$(git config --get remote.origin.url || true)"
repo_slug="$(echo "$origin_url" | sed -E 's#^(git@github\.com:|https://github\.com/)##; s#\.git$##')"
if [[ -z "$repo_slug" ]]; then
  echo "ruleset-sync-check: could not determine owner/repo from 'git config remote.origin.url' (got: '$origin_url')." >&2
  exit 1
fi

api_base="https://api.github.com/repos/$repo_slug"

auth_header=()
token="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
if [[ -n "$token" ]]; then
  auth_header=(-H "Authorization: Bearer $token")
fi

api_get() {
  curl -sf "${auth_header[@]}" -H "Accept: application/vnd.github+json" "$api_base/$1"
}

canon_filter="$(dirname "$0")/lib/ruleset-canon.jq"
source "$(dirname "$0")/lib/jq-canon.sh"

live_rulesets_json="$(api_get "rulesets")" || {
  echo "ruleset-sync-check: FAILED to list live rulesets from $api_base/rulesets (network or API error)." >&2
  exit 1
}

status=0

# ---------------------------------------------------------------------
# Leg 1: gates.txt vs. workflow job names (same comparison
# gates-manifest-check.sh runs, re-asserted here per RFC-005 Part B's
# Rulesets paragraph: "plus the name-equality leg against the manifest
# and workflow job list" is specified as part of THIS check's own scope,
# not solely delegated to the sibling job).
# ---------------------------------------------------------------------
workflow=".github/workflows/merge-gate.yml"
workflow_names="$(extract_workflow_job_names "$workflow")" || { status=1; workflow_names=""; }
manifest_names="$(printf '%s\n' "${gate_check_names[@]}" | sort)"

if [[ -n "$workflow_names" ]]; then
  missing_from_manifest="$(comm -23 <(printf '%s\n' "$workflow_names") <(printf '%s\n' "$manifest_names"))"
  missing_from_workflow="$(comm -13 <(printf '%s\n' "$workflow_names") <(printf '%s\n' "$manifest_names"))"
  if [[ -n "$missing_from_manifest" || -n "$missing_from_workflow" ]]; then
    echo "ruleset-sync-check: DRIFT (leg 1: workflow vs. gates.txt) --" >&2
    [[ -n "$missing_from_manifest" ]] && { echo "  job(s) in $workflow with no gates.txt entry:" >&2; printf '    %s\n' "$missing_from_manifest" >&2; }
    [[ -n "$missing_from_workflow" ]] && { echo "  gates.txt entry/entries with no matching job in $workflow:" >&2; printf '    %s\n' "$missing_from_workflow" >&2; }
    status=1
  else
    echo "ruleset-sync-check: leg 1 OK -- workflow job names == gates.txt check names."
  fi
fi

# ---------------------------------------------------------------------
# Waiver evaluation: build the ACTIVE-waiver-excluded name and
# EXPIRED-waiver name sets, logging every waiver loudly.
# ---------------------------------------------------------------------
declare -A waived_active=()
declare -A waived_expired=()
for i in "${!waiver_check_names[@]}"; do
  wname="${waiver_check_names[$i]}"
  wexpiry="${waiver_expiries[$i]}"
  wreason="${waiver_reasons[$i]}"

  waiver_expired "$wexpiry"
  rc=$?
  if [[ "$rc" -eq 0 ]]; then
    echo "ruleset-sync-check: WAIVER EXPIRED -- check='$wname' expiry='$wexpiry' reason='$wreason' -- this waiver no longer excuses a missing required check." >&2
    waived_expired["$wname"]=1
  elif [[ "$rc" -eq 2 ]]; then
    echo "ruleset-sync-check: WAIVER for check='$wname' has a SHA expiry ('$wexpiry') this checkout cannot verify (commit not found locally) -- treating as ACTIVE (fail-safe) but this needs a deeper checkout (fetch-depth: 0) or a corrected SHA. reason='$wreason'" >&2
    waived_active["$wname"]=1
  else
    echo "ruleset-sync-check: WAIVER ACTIVE -- check='$wname' expiry='$wexpiry' reason='$wreason'"
    waived_active["$wname"]=1
  fi
done

# ---------------------------------------------------------------------
# Leg 2: live main ruleset's required checks vs. gates.txt (adjusted for
# active waivers) -- a specific, readable diagnostic ahead of the generic
# full-canonical diff below.
# ---------------------------------------------------------------------
main_live="$(echo "$live_rulesets_json" | jq -r '.[] | select(.name == "main") | .id')"
if [[ -z "$main_live" ]]; then
  echo "ruleset-sync-check: DRIFT (leg 2) -- no live ruleset named \"main\" exists at $api_base/rulesets. Has scripts/ruleset-apply.sh --apply been run yet?" >&2
  status=1
else
  main_live_detail="$(api_get "rulesets/$main_live")" || {
    echo "ruleset-sync-check: FAILED to fetch live ruleset detail for \"main\" (id=$main_live) from $api_base/rulesets/$main_live (network or API error)." >&2
    exit 1
  }
  live_required_names="$(echo "$main_live_detail" | jq -r '.rules[] | select(.type == "required_status_checks") | .parameters.required_status_checks[]?.context' | sort)"

  expected_names=()
  for n in "${gate_check_names[@]}"; do
    if [[ -n "${waived_active[$n]:-}" ]] && ! printf '%s\n' "$live_required_names" | grep -qxF "$n"; then
      # Actively waived AND actually absent live -- exclude from expected.
      continue
    fi
    expected_names+=("$n")
  done
  expected_names_sorted="$(printf '%s\n' "${expected_names[@]}" | sort)"

  leg2_missing="$(comm -23 <(printf '%s\n' "$expected_names_sorted") <(printf '%s\n' "$live_required_names"))"
  leg2_extra="$(comm -13 <(printf '%s\n' "$expected_names_sorted") <(printf '%s\n' "$live_required_names"))"

  if [[ -n "$leg2_missing" || -n "$leg2_extra" ]]; then
    echo "ruleset-sync-check: DRIFT (leg 2: main ruleset required checks vs. gates.txt, waiver-adjusted) --" >&2
    [[ -n "$leg2_missing" ]] && { echo "  required by gates.txt (and not actively waived) but missing from the live main ruleset:" >&2; printf '    %s\n' "$leg2_missing" >&2; }
    [[ -n "$leg2_extra" ]] && { echo "  present in the live main ruleset but not in gates.txt:" >&2; printf '    %s\n' "$leg2_extra" >&2; }
    status=1
  else
    echo "ruleset-sync-check: leg 2 OK -- live main ruleset required checks == gates.txt (waiver-adjusted)."
  fi
fi

# ---------------------------------------------------------------------
# Leg 3: full canonicalized live-vs-committed diff, every ruleset file
# under .github/rulesets/*.json (top level only -- .github/rulesets/
# unavailable/ is deliberately excluded, see that directory's own
# contents for why).
# ---------------------------------------------------------------------
required_checks_json="$(printf '%s\n' "${expected_names_sorted:-}" | grep -v '^$' | jq -R '{context: .}' | jq -s '.')"

for file in .github/rulesets/*.json; do
  [[ -e "$file" ]] || continue

  name="$(jq -r '.name' "$file")"
  live_id="$(echo "$live_rulesets_json" | jq -r --arg n "$name" '.[] | select(.name == $n) | .id')"

  if [[ -z "$live_id" ]]; then
    echo "ruleset-sync-check: DRIFT (leg 3) -- committed $file (name=\"$name\") has no live counterpart at $api_base/rulesets." >&2
    status=1
    continue
  fi

  live_detail="$(api_get "rulesets/$live_id")" || {
    echo "ruleset-sync-check: FAILED to fetch live ruleset detail for \"$name\" (id=$live_id) (network or API error)." >&2
    status=1
    continue
  }
  live_canon="$(echo "$live_detail" | JQ_CANON_EXPR='normalize' jq_canon | jq -S .)"

  if [[ "$name" == "main" ]]; then
    spliced="$(JQ_CANON_EXPR='set_required_checks($checks)' JQ_CANON_FILE="$file" jq_canon --argjson checks "$required_checks_json")"
  else
    spliced="$(cat "$file")"
  fi
  committed_canon="$(echo "$spliced" | JQ_CANON_EXPR='normalize' jq_canon | jq -S .)"

  if [[ "$live_canon" == "$committed_canon" ]]; then
    echo "ruleset-sync-check: leg 3 OK -- \"$name\" live matches committed."
  else
    echo "ruleset-sync-check: DRIFT (leg 3) -- \"$name\" live ruleset does not match committed $file:" >&2
    diff <(echo "$live_canon") <(echo "$committed_canon") >&2 || true
    status=1
  fi
done

if [[ "$status" -eq 0 ]]; then
  echo "ruleset-sync-check: OK -- live ruleset state matches committed .github/rulesets/*.json (all legs)."
fi

exit "$status"
