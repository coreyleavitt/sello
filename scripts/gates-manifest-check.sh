#!/usr/bin/env bash
# scripts/gates-manifest-check.sh — RFC-005 slice 3: the
# "gates-manifest-sync" drift check. Asserts
# .github/workflows/merge-gate.yml's job name set equals
# scripts/lib/gates.txt's check-name set, in BOTH directions -- a job
# added to the workflow with no manifest entry (unreachable from
# scripts/merge-gate.sh, and invisible to the future ruleset generator,
# RFC-005 slice 4) and a manifest entry with no matching job (a name that
# scripts/merge-gate.sh or a ruleset could require, that CI never
# actually runs) are both drift, caught here rather than discovered later
# by hand.
#
# Container vs. plain runner (RFC-005 slice 3 decision, recorded per the
# slice's own instructions): this check needs no Nim toolchain, no
# podman, no milpa -- it is a pure text scan over two committed files.
# The RFC's digest-pinned-container rule (Part B) targets BUILD jobs,
# where the exact compiler/toolchain the code runs under is part of what
# is being certified; a grep/awk scan over YAML and a manifest has no
# such dependency, so it runs on a plain `ubuntu-latest` runner in CI (see
# merge-gate.yml's own job comment) -- faster, and correctly signals that
# this check's trust boundary is "the text in this repo," not "a pinned
# toolchain." The one-scripts/-invocation build-path invariant still
# holds: the job's run step is exactly `scripts/gates-manifest-check.sh`.
#
# Parse method, and its own honesty requirement: the workflow is
# hand-written YAML (RFC-005 Part B: jobs are heterogeneous, and
# generating YAML means building a templater with no customer), so this
# is a light grep/awk scan, not a real YAML parser -- a deliberate,
# named trade-off, not an oversight. To keep that trade-off honest rather
# than silently wrong on a workflow edit this scan doesn't understand,
# this script independently collects two things under the top-level
# `jobs:` key and cross-checks them against EACH OTHER before trusting
# either:
#   (a) every job KEY (a 2-space-indented line consisting of nothing but
#       an identifier and a trailing colon -- YAML's own job-definition
#       shape).
#   (b) every job's own `name:` field VALUE (a 4-space-indented `name:`
#       line -- RFC-005 Part B's "every job carries an explicit name:
#       equal to its manifest check-name" convention, load-bearing for
#       ruleset required-check matching since GitHub's ruleset engine
#       matches check-RUN names, not job keys).
# If the COUNT of (a) differs from the COUNT of (b), or the SET of (a)
# differs from the SET of (b), that is a parse surprise -- the light
# scan's structural assumption (one job key, one same-named `name:` field
# somewhere in its body) no longer holds, e.g. a job missing its `name:`,
# a differently-indented job, or a `name:` line appearing inside a step
# rather than a job -- and this script fails LOUD with both sets printed,
# rather than silently comparing a partial/wrong set against the
# manifest and reporting a false pass or a confusing false drift.
#
# Self-reference (by design, not a bug): this script's own CI job,
# "gates-manifest-sync", must appear in BOTH merge-gate.yml (as a job
# whose name: is "gates-manifest-sync") AND scripts/lib/gates.txt (as a
# check-name), or this check fails on itself -- exactly the drift-
# detection property it exists to provide, extended to its own
# enforcement machinery with no special-casing.
#
# Usage:  scripts/gates-manifest-check.sh
set -euo pipefail
cd "$(dirname "$0")/.."

source "$(dirname "$0")/lib/gates.sh"
load_gates

workflow=".github/workflows/merge-gate.yml"

if [[ ! -f "$workflow" ]]; then
  echo "gates-manifest-check: $workflow not found." >&2
  exit 1
fi

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
  echo "gates-manifest-check: PARSE SURPRISE -- found zero job keys under 'jobs:' in $workflow. The light awk scan's structural assumptions (a top-level 'jobs:' key, 2-space-indented job keys directly under it) no longer hold for this file -- fix the scan or the file before trusting this check." >&2
  exit 1
fi

if [[ "$job_key_count" -ne "$name_value_count" ]]; then
  {
    echo "gates-manifest-check: PARSE SURPRISE -- found $job_key_count job key(s) but $name_value_count 'name:' line(s) under 'jobs:' in $workflow."
    echo "Every job must carry an explicit name: field equal to its job key (RFC-005 Part B) -- this count mismatch means either a job is missing its name:, or the light scan mis-read the file. Refusing to guess which."
    echo "Job keys found:"
    printf '  %s\n' "$job_keys"
    echo "name: values found:"
    printf '  %s\n' "$name_values"
  } >&2
  exit 1
fi

if [[ "$job_keys" != "$name_values" ]]; then
  {
    echo "gates-manifest-check: PARSE SURPRISE -- the job-key set and the name:-value set are not IDENTICAL (every job's own name: must equal its job key)."
    echo "Job keys:"
    printf '  %s\n' "$job_keys"
    echo "name: values:"
    printf '  %s\n' "$name_values"
  } >&2
  exit 1
fi

workflow_names="$job_keys"
manifest_names="$(printf '%s\n' "${gate_check_names[@]}" | sort)"

missing_from_manifest="$(comm -23 <(printf '%s\n' "$workflow_names") <(printf '%s\n' "$manifest_names"))"
missing_from_workflow="$(comm -13 <(printf '%s\n' "$workflow_names") <(printf '%s\n' "$manifest_names"))"

status=0

if [[ -n "$missing_from_manifest" ]]; then
  {
    echo "gates-manifest-check: DRIFT -- job(s) present in $workflow with no scripts/lib/gates.txt entry:"
    printf '  %s\n' "$missing_from_manifest"
  } >&2
  status=1
fi

if [[ -n "$missing_from_workflow" ]]; then
  {
    echo "gates-manifest-check: DRIFT -- scripts/lib/gates.txt entry/entries with no matching job in $workflow:"
    printf '  %s\n' "$missing_from_workflow"
  } >&2
  status=1
fi

if [[ "$status" -eq 0 ]]; then
  echo "gates-manifest-check: OK -- $workflow job names and scripts/lib/gates.txt check names match exactly ($job_key_count check(s))."
fi

exit "$status"
