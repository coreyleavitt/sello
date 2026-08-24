#!/usr/bin/env bash
# scripts/lib/gates.sh — parses scripts/lib/gates.txt (RFC-005 slice 3's
# gates manifest) into two parallel arrays, `gate_check_names` and
# `gate_invocations`, so scripts/merge-gate.sh and
# scripts/gates-manifest-check.sh read one parser instead of two
# hand-typed copies (round-2 finding 25's convention -- same reasoning as
# scripts/lib/unit-test-files.sh/tier-summary.sh: one source, multiple
# consumers, no chance of silent drift between independently-typed-out
# copies). Not a standalone script -- `source`d only; declares
# `load_gates()` into the sourcing shell.
#
# Format parsed here (documented authoritatively in scripts/lib/gates.txt
# itself): one gate per non-blank, non-comment (#-prefixed) line, two
# whitespace-separated columns -- check-name, then the rest of the line
# verbatim as the script-invocation (so a future entry may carry
# arguments; only the FIRST run of whitespace is treated as the column
# separator).
load_gates() {
  gate_check_names=()
  gate_invocations=()

  local manifest
  manifest="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/gates.txt"

  local line name invocation
  while IFS= read -r line || [[ -n "$line" ]]; do
    # Trim leading/trailing whitespace.
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"

    [[ -z "$line" ]] && continue
    [[ "$line" == \#* ]] && continue

    # First field is the check name; `read`'s last variable absorbs the
    # remainder of the line (minus the single separating run of
    # whitespace) verbatim, including any internal whitespace.
    read -r name invocation <<< "$line"

    gate_check_names+=("$name")
    gate_invocations+=("$invocation")
  done < "$manifest"
}
