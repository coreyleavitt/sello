#!/usr/bin/env bash
# scripts/lib/baseline.sh -- RFC-005's "regenerable-baseline idiom" (Part
# B), implemented once and shared by every gate that pins a machine
# -generated dump against a committed expectation.
#
# PLACEMENT NOTE (slice 18's own reordering, recorded here and in
# CLAUDE.md/the handoff): Part B originally assigned this file to slice
# 17 (the coverage ratchet, A3) -- "its interface proof-spiked against the
# disasm gate's needs... before freezing on coverage alone." Slice 17
# remains blocked on the same Corey-owned ghcr `write:packages`
# credential (the `sello-dev` image) as slices 10/14/15, so it could not
# land first as the RFC's own slice numbering implies. Slice 18 (the
# API-surface gate, A8) needs only the always-available BASE image and is
# this file's actual first consumer, so it lands the full contract here,
# unchanged from what the RFC specifies -- nothing speculative beyond it.
# Slice 17 is expected to `source` this file exactly as slice 18 does,
# not fork or duplicate it.
#
# THE CONTRACT (RFC-005 Part B, verbatim in spirit):
#   - location: a committed text file under tests/<gate>/expected/ (the
#     CALLER decides the exact path -- this file has no opinion on gate
#     names).
#   - shape: a `#`-prefixed HEADER block (kind: regenerable, generator,
#     regeneration command, image digest + compiler version -- "load
#     -bearing for A2's bump journey"), then one blank line, then the
#     BODY -- the actual pinned dump, byte-for-byte what the generator
#     command prints to stdout. Only the BODY is compared by
#     baseline_check; the header is metadata a human reads, not diffed
#     content (a header re-generated with a newer compiler/image pin, body
#     otherwise unchanged, is not itself a failure -- that's the whole
#     point of separating the two).
#   - failure shape: print the diff, print the EXACT regeneration command
#     (the caller's own regen_cmd_str, not re-derived from the header),
#     exit nonzero.
#   - `--update` semantics live in the CALLING gate script (baseline_check
#     vs baseline_update below are the two primitives it dispatches
#     between) and HARD-FAIL when `$CI` is set: regeneration is by
#     definition a local, deliberate act -- without this guard, a
#     compromised Actions run could pass --update and turn the pin into a
#     self-approving no-op (RFC-005 Part B, verbatim).
#
# Usage (sourced, not standalone -- declares baseline_check/baseline_update
# into the sourcing shell; not `set -e`-safe to source blindly into a
# script that isn't already careful about that, same convention as this
# project's other scripts/lib/*.sh files):
#
#   source scripts/lib/baseline.sh
#   baseline_check  <pin-file> <generator-desc> <regen-cmd-str> -- <generate-cmd...>
#   baseline_update <pin-file> <generator-desc> <regen-cmd-str> -- <generate-cmd...>
#
# <generate-cmd...> (everything after the literal `--`) is executed via
# "$@" and must print the fresh dump to stdout; a nonzero exit from it is
# treated as a hard failure of the calling function. <generator-desc> and
# <regen-cmd-str> are free text the CALLER already knows (this file never
# tries to reconstruct them from a possibly-stale committed header) --
# written into the header on update, and printed verbatim in a check
# failure's "how to fix this" line, so what a maintainer is told to run
# is always exactly what this invocation itself would have run.
#
# Diff mechanism: prefers `diff -u` when present, falling back to
# Python's difflib otherwise -- this project's OWN pinned base image
# (ghcr.io/coreyleavitt/nim:2.2.10) ships no diffutils at all (verified
# during this slice's own spike, an unplanned but genuine finding), but
# does ship python3 (already relied on by scripts/lib/milpa-install.sh),
# so the fallback is exercised on every real CI run of a baseline
# -consuming gate today, not a theoretical branch.
set -uo pipefail

# Strips a leading `#`-prefixed header block plus the first blank line
# that follows it -- everything after that is "the body." A file with NO
# header at all (defensive: shouldn't happen for a tool-written pin, but
# keeps this robust rather than assuming) is treated as all-body.
_baseline_body_of_file() {
  local f="$1"
  awk '
    BEGIN { in_header = 1 }
    in_header && /^#/ { next }
    in_header && NF == 0 { in_header = 0; next }
    in_header { in_header = 0 }
    { print }
  ' "$f"
}

# Captures the two header fields load-bearing for A2's bump journey: the
# compiler actually on PATH right now, and (when this checkout carries
# one) the pinned base-image line from scripts/lib/image-pins.txt. Every
# baseline-consuming gate runs inside that same pinned image today, so
# capturing it here once means no per-caller boilerplate; a future
# non-image-based gate simply gets a header with no `image:` line.
_baseline_header_meta() {
  local nim_version image_pin
  nim_version="$(nim --version 2>/dev/null | head -n1 || echo 'nim --version unavailable')"
  image_pin="$(grep -E '^ghcr\.io/coreyleavitt/nim@sha256:' "$(dirname "${BASH_SOURCE[0]}")/image-pins.txt" 2>/dev/null | head -n1 || true)"
  echo "compiler: $nim_version"
  if [[ -n "$image_pin" ]]; then
    echo "image: $image_pin"
  fi
}

_baseline_parse_args() {
  # Shared arg handling for both entry points below. Sets the globals
  # _bl_pin, _bl_desc, _bl_regen, then shifts the caller's positional
  # params down to just <generate-cmd...> (the caller does `shift $?` --
  # no, bash can't return a shift count this way, so instead this sets
  # _bl_argv, an array of the remaining generate-cmd words, and the
  # caller uses that directly rather than "$@").
  if [[ $# -lt 4 ]]; then
    echo "baseline: usage: <pin-file> <generator-desc> <regen-cmd-str> -- <generate-cmd...>" >&2
    return 2
  fi
  _bl_pin="$1"; _bl_desc="$2"; _bl_regen="$3"
  shift 3
  if [[ "$1" != "--" ]]; then
    echo "baseline: expected '--' before the generate-cmd, got '$1'" >&2
    return 2
  fi
  shift
  if [[ $# -eq 0 ]]; then
    echo "baseline: no generate-cmd given after '--'" >&2
    return 2
  fi
  _bl_argv=("$@")
  return 0
}

baseline_check() {
  local _bl_pin _bl_desc _bl_regen
  local -a _bl_argv
  _baseline_parse_args "$@" || return $?

  if [[ ! -f "$_bl_pin" ]]; then
    echo "baseline_check: FAIL -- no committed baseline at $_bl_pin." >&2
    echo "baseline_check: create it locally (never in CI): $_bl_regen" >&2
    return 1
  fi

  local fresh rc
  fresh="$("${_bl_argv[@]}")"
  rc=$?
  if [[ "$rc" -ne 0 ]]; then
    echo "baseline_check: FAIL -- generator command failed (exit $rc): ${_bl_argv[*]}" >&2
    return 1
  fi

  local committed
  committed="$(_baseline_body_of_file "$_bl_pin")"

  if [[ "$fresh" == "$committed" ]]; then
    echo "baseline_check: OK -- $_bl_pin matches the freshly generated dump ($_bl_desc)."
    return 0
  fi

  echo "baseline_check: FAIL -- $_bl_pin does not match the freshly generated dump ($_bl_desc)." >&2
  echo "baseline_check: diff (committed -> fresh):" >&2
  if command -v diff >/dev/null 2>&1; then
    diff <(printf '%s\n' "$committed") <(printf '%s\n' "$fresh") >&2 || true
  else
    python3 -c '
import sys, difflib
a = sys.argv[1].splitlines(keepends=True)
b = sys.argv[2].splitlines(keepends=True)
sys.stderr.writelines(difflib.unified_diff(a, b, fromfile="committed", tofile="fresh"))
' "$committed" "$fresh" >&2
  fi
  echo "baseline_check: to accept a REVIEWED, INTENTIONAL change, regenerate locally (never in CI): $_bl_regen" >&2
  return 1
}

baseline_update() {
  local _bl_pin _bl_desc _bl_regen
  local -a _bl_argv
  _baseline_parse_args "$@" || return $?

  if [[ -n "${CI:-}" ]]; then
    echo "baseline_update: REFUSING to run under CI (\$CI is set). Regenerating a" >&2
    echo "baseline_update: baseline is a local, deliberate, reviewed act by design" >&2
    echo "baseline_update: (RFC-005 Part B) -- see this file's own header comment." >&2
    return 1
  fi

  local fresh rc
  fresh="$("${_bl_argv[@]}")"
  rc=$?
  if [[ "$rc" -ne 0 ]]; then
    echo "baseline_update: FAIL -- generator command failed (exit $rc): ${_bl_argv[*]}" >&2
    return 1
  fi

  mkdir -p "$(dirname "$_bl_pin")"
  {
    echo "# kind: regenerable"
    echo "# generator: $_bl_desc"
    echo "# regeneration command: $_bl_regen"
    _baseline_header_meta | sed 's/^/# /'
    echo "#"
    echo "# DO NOT HAND-EDIT the body below this line -- run the regeneration"
    echo "# command above (never under CI -- see this file's own header comment)."
    echo ""
    printf '%s\n' "$fresh"
  } > "$_bl_pin"
  echo "baseline_update: wrote $_bl_pin ($_bl_desc)."
}
