#!/usr/bin/env bash
# scripts/lib/coverage-down-path.sh -- RFC-005 slice 17: the coverage
# ratchet's (A3) DOWN-PATH governance, enforced at `scripts/coverage.sh
# --update` time (never by the CI check itself -- see that script's own
# header comment for the full "this slice's own reading" writeup of why).
#
# Declares one function, `coverage_down_path_guard`, sourced (not
# standalone -- no shebang effect beyond documentation) into
# scripts/coverage.sh's own shell, mirroring scripts/lib/baseline.sh's
# own sourced-library convention.
#
#   coverage_down_path_guard <pin-file> <justifications-file> <fresh-body>
#
# <pin-file>: tests/coverage/expected/baseline.txt (may not exist yet --
#   a first-ever `--update` has nothing to compare against, so nothing
#   can be a "drop" relative to a baseline that doesn't exist; this
#   function is then a no-op pass).
# <justifications-file>: tests/coverage/expected/justifications.md (see
#   that file's own header comment for the exact ledger format this
#   function parses -- newest entry at the TOP, a `Cites:` line
#   comma-separating `key=value` pairs).
# <fresh-body>: the freshly computed dump (scripts/coverage.sh's own
#   `$fresh_body`, i.e. tests/coverage/coverage_report_gen.py's stdout --
#   "aggregate <pct>" then one "<key> <pct>" line per file, ALREADY
#   confirmed deterministic by the caller's own double-run check).
#
# Returns 0 (and prints nothing) if every key whose fresh value is lower
# than the currently committed baseline is cited, verbatim, in
# justifications.md's newest entry -- or if there are no such keys at
# all (the common case: a raise, an unchanged suite, or a first-ever
# baseline with nothing to compare against). Returns 1 (after printing a
# loud, specific diagnosis: which key(s), old value, new value, and the
# exact `Cites:` fragment still missing) otherwise -- the caller
# (scripts/coverage.sh) treats a nonzero return as "do not write
# baseline.txt," so an unjustified drop never reaches the committed pin.
set -uo pipefail

coverage_down_path_guard() {
  local pin_file="$1" just_file="$2" fresh_body="$3"

  if [[ ! -f "$pin_file" ]]; then
    echo "coverage-down-path: no committed baseline at $pin_file yet -- nothing to compare against, first --update is unconditionally allowed." >&2
    return 0
  fi

  # The committed pin's BODY (strip baseline.sh's own `#`-header block +
  # the blank line after it) -- same shape _baseline_body_of_file
  # produces, reimplemented here rather than depending on baseline.sh
  # having already been sourced by the caller (this function is meant to
  # be usable standalone too).
  local committed
  committed="$(awk '
    BEGIN { in_header = 1 }
    in_header && /^#/ { next }
    in_header && NF == 0 { in_header = 0; next }
    in_header { in_header = 0 }
    { print }
  ' "$pin_file")"

  # Build old[key]=value from the committed body, fresh[key]=value from
  # the fresh dump -- both "aggregate <pct>" and "<file> <pct>" lines
  # share the same "<key> <value>" shape, so one parse handles both.
  local -A old_val=()
  local -A fresh_val=()
  local line key val
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    key="${line%% *}"
    val="${line#* }"
    old_val["$key"]="$val"
  done <<<"$committed"
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    key="${line%% *}"
    val="${line#* }"
    fresh_val["$key"]="$val"
  done <<<"$fresh_body"

  # A key present in old but absent from fresh (a file deleted/renamed
  # entirely, or the aggregate key itself somehow missing) is NOT this
  # function's concern -- that shows up as an ordinary baseline_check/
  # baseline_update diff (the committed line simply has no fresh
  # counterpart to compare against), not a "number dropped" case this
  # ledger governs. Only keys present in BOTH, where fresh is
  # numerically lower, count as a drop.
  local -a drop_keys=()
  local -a drop_msgs=()
  local ok=""
  local ov fv
  for key in "${!fresh_val[@]}"; do
    ov="${old_val[$key]:-}"
    [[ -z "$ov" ]] && continue
    fv="${fresh_val[$key]}"
    # Compare as tenths-of-a-percent integers (both are already
    # one-decimal-formatted strings like "71.2") -- avoids any shell
    # floating-point arithmetic entirely.
    ov_x10="${ov/./}"; fv_x10="${fv/./}"
    if [[ "$fv_x10" -lt "$ov_x10" ]]; then
      drop_keys+=("$key")
      drop_msgs+=("$key: $ov -> $fv")
    fi
  done

  if [[ ${#drop_keys[@]} -eq 0 ]]; then
    return 0
  fi

  echo "coverage-down-path: ${#drop_keys[@]} pinned number(s) would DROP relative to the committed baseline:" >&2
  local m
  for m in "${drop_msgs[@]}"; do
    echo "  - $m" >&2
  done

  if [[ ! -f "$just_file" ]]; then
    echo "coverage-down-path: FAIL -- $just_file does not exist. A coverage drop needs a justification entry -- see that file's own header comment for the format." >&2
    return 1
  fi

  # The NEWEST entry is the one at the TOP of the file -- its `Cites:`
  # line is the first one found scanning from the top (justifications.md's
  # own header explains why: newest-first is the human-readable
  # convention this ledger uses, and "the newest entry" is unambiguous
  # only if there is exactly one place to look first).
  local cites_line
  cites_line="$(grep -m1 '^Cites: ' "$just_file" || true)"
  if [[ -z "$cites_line" ]]; then
    echo "coverage-down-path: FAIL -- $just_file has no 'Cites: ...' line at all (or it isn't the newest entry's -- see that file's format)." >&2
    return 1
  fi
  cites_line="${cites_line#Cites: }"

  local missing=0
  local expect
  for m in "${drop_msgs[@]}"; do
    key="${m%%:*}"
    fv="${fresh_val[$key]}"
    expect="$key=$fv"
    if [[ "$cites_line" != *"$expect"* ]]; then
      echo "coverage-down-path: FAIL -- missing citation for '$expect' in $just_file's newest Cites: line." >&2
      missing=1
    fi
  done

  if [[ "$missing" -eq 1 ]]; then
    echo "coverage-down-path: newest Cites: line found: Cites: $cites_line" >&2
    echo "coverage-down-path: add a new entry at the TOP of $just_file citing every dropped key=value pair above (exact one-decimal value), then re-run --update." >&2
    return 1
  fi

  echo "coverage-down-path: OK -- every dropped key is cited in $just_file's newest entry." >&2
  return 0
}
