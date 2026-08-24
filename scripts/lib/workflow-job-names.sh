#!/usr/bin/env bash
# scripts/lib/workflow-job-names.sh — RFC-005 slice 4: the light awk scan
# that extracts .github/workflows/merge-gate.yml's job-name set, factored
# out of scripts/gates-manifest-check.sh (RFC-005 slice 3) so
# scripts/ruleset-sync-check.sh can reuse the identical extraction instead
# of a second hand-typed copy (round-2 finding 25's own precedent — one
# source, multiple consumers). Not a standalone script — sourced only;
# declares `extract_workflow_job_names()` into the sourcing shell.
#
# Parse method and its own honesty requirement, unchanged from
# gates-manifest-check.sh's original comment (moved here verbatim in
# spirit): the workflow is hand-written YAML (RFC-005 Part B: jobs are
# heterogeneous, and generating YAML means building a templater with no
# customer), so this is a light grep/awk scan, not a real YAML parser — a
# deliberate, named trade-off. To keep that trade-off honest rather than
# silently wrong on a workflow edit this scan doesn't understand, this
# function independently collects two things under the top-level `jobs:`
# key and cross-checks them against EACH OTHER before trusting either:
#   (a) every job KEY (a 2-space-indented line consisting of nothing but
#       an identifier and a trailing colon — YAML's own job-definition
#       shape).
#   (b) every job's own `name:` field VALUE (a 4-space-indented `name:`
#       line — RFC-005 Part B's "every job carries an explicit name:
#       equal to its manifest check-name" convention, load-bearing for
#       ruleset required-check matching since GitHub's ruleset engine
#       matches check-RUN names, not job keys).
# If the COUNT or SET of (a) differs from (b), that is a parse surprise —
# the light scan's structural assumption (one job key, one same-named
# `name:` field somewhere in its body) no longer holds — and this
# function fails LOUD with both sets printed, exactly like
# gates-manifest-check.sh's original inline version did.
#
# Usage: extract_workflow_job_names <workflow-file>
#   Prints the sorted job-name set to stdout, one per line, on success.
#   On a parse surprise, prints the diagnostic to stderr and returns 1.
extract_workflow_job_names() {
  local workflow="$1"

  if [[ ! -f "$workflow" ]]; then
    echo "workflow-job-names: $workflow not found." >&2
    return 1
  fi

  local job_keys name_values job_key_count name_value_count

  job_keys="$(awk '
    /^jobs:[[:space:]]*$/ { in_jobs = 1; next }
    in_jobs && /^[^[:space:]]/ { in_jobs = 0 }
    in_jobs && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
      line = $0
      sub(/^  /, "", line)
      sub(/:[[:space:]]*$/, "", line)
      print line
    }
  ' "$workflow" | sort)"

  name_values="$(awk '
    /^jobs:[[:space:]]*$/ { in_jobs = 1; next }
    in_jobs && /^[^[:space:]]/ { in_jobs = 0 }
    in_jobs && /^    name:[[:space:]]/ {
      line = $0
      sub(/^    name:[[:space:]]*/, "", line)
      print line
    }
  ' "$workflow" | sort)"

  job_key_count=$(printf '%s\n' "$job_keys" | grep -c . || true)
  name_value_count=$(printf '%s\n' "$name_values" | grep -c . || true)

  if [[ "$job_key_count" -eq 0 ]]; then
    echo "workflow-job-names: PARSE SURPRISE -- found zero job keys under 'jobs:' in $workflow. The light awk scan's structural assumptions (a top-level 'jobs:' key, 2-space-indented job keys directly under it) no longer hold for this file -- fix the scan or the file before trusting this check." >&2
    return 1
  fi

  if [[ "$job_key_count" -ne "$name_value_count" ]]; then
    {
      echo "workflow-job-names: PARSE SURPRISE -- found $job_key_count job key(s) but $name_value_count 'name:' line(s) under 'jobs:' in $workflow."
      echo "Every job must carry an explicit name: field equal to its job key (RFC-005 Part B) -- this count mismatch means either a job is missing its name:, or the light scan mis-read the file. Refusing to guess which."
      echo "Job keys found:"
      printf '  %s\n' "$job_keys"
      echo "name: values found:"
      printf '  %s\n' "$name_values"
    } >&2
    return 1
  fi

  if [[ "$job_keys" != "$name_values" ]]; then
    {
      echo "workflow-job-names: PARSE SURPRISE -- the job-key set and the name:-value set are not IDENTICAL (every job's own name: must equal its job key)."
      echo "Job keys:"
      printf '  %s\n' "$job_keys"
      echo "name: values:"
      printf '  %s\n' "$name_values"
    } >&2
    return 1
  fi

  printf '%s\n' "$job_keys"
  return 0
}
