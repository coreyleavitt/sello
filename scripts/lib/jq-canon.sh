#!/usr/bin/env bash
# scripts/lib/jq-canon.sh — RFC-005 slice 4: the shared `jq_canon` helper
# both scripts/ruleset-apply.sh and scripts/ruleset-sync-check.sh use to
# invoke scripts/lib/ruleset-canon.jq's function definitions (round-2
# finding 25's "one source, multiple consumers" precedent, applied to
# this small piece of glue too, not just the jq module itself). Not a
# standalone script — sourced only; declares `jq_canon()` into the
# sourcing shell. The sourcing script must set `canon_filter` (path to
# ruleset-canon.jq) before calling `jq_canon`.
#
# Usage: JQ_CANON_EXPR='<jq expression, e.g. normalize or
# set_required_checks($checks)>' [JQ_CANON_FILE=<path>] jq_canon
# [jq-option...]
#
# Reads $JQ_CANON_FILE (if set, else stdin) through the concatenation of
# ruleset-canon.jq's text followed by $JQ_CANON_EXPR, passed to jq as a
# single filter-program string. The filter-program-text-then-input-file
# split via two env vars (rather than passing both as positional "$@"
# elements) is deliberate: jq's own positional-argument rule (the first
# bare positional is the filter, the rest are input files) means the
# filter text and any input file path can never both be plain elements
# of "$@" without jq mistaking which is which. Also avoids relying on
# jq's `include` module-search-path semantics (cwd-sensitive, easy to get
# subtly wrong from a script invoked from outside the repo root) — plain
# text concatenation has no such ambiguity.
jq_canon() {
  local program
  program="$(cat "$canon_filter"; echo "$JQ_CANON_EXPR")"
  if [[ -n "${JQ_CANON_FILE:-}" ]]; then
    jq "$@" "$program" "$JQ_CANON_FILE"
  else
    jq "$@" "$program"
  fi
}
