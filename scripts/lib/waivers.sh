#!/usr/bin/env bash
# scripts/lib/waivers.sh — parses scripts/lib/waivers.txt (RFC-005 slice
# 4's waiver register) into parallel arrays, mirroring
# scripts/lib/gates.sh's own load_gates() shape. Not a standalone script —
# sourced only; declares `load_waivers()`, `waiver_is_sha()`, and
# `waiver_expired()` into the sourcing shell. The one consumer is
# scripts/ruleset-sync-check.sh.
#
# Format parsed here (documented authoritatively in
# scripts/lib/waivers.txt itself): one waiver per non-blank, non-comment
# (#-prefixed) line, three whitespace-separated columns -- check-name,
# expiry, then the rest of the line verbatim as the reason (only the
# first two runs of whitespace are treated as column separators).
load_waivers() {
  waiver_check_names=()
  waiver_expiries=()
  waiver_reasons=()

  local manifest
  manifest="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/waivers.txt"

  local line name expiry reason
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"

    [[ -z "$line" ]] && continue
    [[ "$line" == \#* ]] && continue

    read -r name expiry reason <<< "$line"

    waiver_check_names+=("$name")
    waiver_expiries+=("$expiry")
    waiver_reasons+=("$reason")
  done < "$manifest"
}

# waiver_is_sha <expiry> -- true (exit 0) iff $1 looks like a full
# 40-character lowercase-hex git commit SHA, false (exit 1) otherwise
# (treated as an ISO date, YYYY-MM-DD).
waiver_is_sha() {
  [[ "$1" =~ ^[0-9a-f]{40}$ ]]
}

# waiver_expired <expiry> [<check-sha>] -- exit 0 if EXPIRED, exit 1 if
# still ACTIVE, exit 2 if the expiry is a SHA this checkout cannot verify
# (not reachable in the local git history -- treated as fail-safe ACTIVE
# by the caller, since a shallow-clone artifact must not silently expire
# a legitimate outage waiver, but the caller should surface the
# distinction rather than reporting a plain "active"). <check-sha>
# defaults to HEAD -- the commit ruleset-sync is currently evaluating.
waiver_expired() {
  local expiry="$1"
  local check_sha="${2:-HEAD}"

  if waiver_is_sha "$expiry"; then
    if ! git cat-file -e "${expiry}^{commit}" 2>/dev/null; then
      return 2
    fi
    if git merge-base --is-ancestor "$expiry" "$check_sha" 2>/dev/null; then
      return 0   # expired: the fix SHA has already landed
    else
      return 1   # not yet landed: still active
    fi
  else
    local today
    today="$(date -u +%Y-%m-%d)"
    if [[ "$today" > "$expiry" || "$today" == "$expiry" ]]; then
      return 0   # expired: at or past the UTC calendar date (inclusive)
    else
      return 1
    fi
  fi
}
