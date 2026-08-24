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
# named trade-off, not an oversight. As of RFC-005 slice 4 the scan itself
# lives in scripts/lib/workflow-job-names.sh's `extract_workflow_job_names`
# (factored out so scripts/ruleset-sync-check.sh can reuse the identical
# extraction instead of a second hand-typed copy -- round-2 finding 25's
# "one source, multiple consumers" precedent, applied to this scan too).
# That function's own header comment has the full parse-method writeup
# (the two independent extractions -- job keys vs. name: values -- cross-
# checked against each other before either is trusted, failing LOUD on
# any parse surprise rather than silently comparing a partial/wrong set).
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
source "$(dirname "$0")/lib/workflow-job-names.sh"

workflow=".github/workflows/merge-gate.yml"

if [[ ! -f "$workflow" ]]; then
  echo "gates-manifest-check: $workflow not found." >&2
  exit 1
fi

workflow_names="$(extract_workflow_job_names "$workflow")" || exit 1
job_key_count=$(printf '%s\n' "$workflow_names" | grep -c . || true)
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
