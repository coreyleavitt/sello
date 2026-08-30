#!/usr/bin/env bash
# scripts/disasm-gate.sh -- RFC-005 slice 23 (A2): the disassembly gate.
#
# Builds tests/ct_disasm/main.nim (every {.noinline.} disasm-gate root
# referenced, same -d:release register scripts/ct.sh's dudect harness
# uses) with --lineDir:on into a dedicated nimcache directory, then hands
# (nimcache dir, binary) to scripts/lib/disasm_gate_resolve.py -- the
# resolver + branch extractor whose own module doc comment defines the
# pinned artifact shape (per-root ordered conditional-branch list,
# address-free symbolized context, plus count). The fresh dump is
# compared against (or, with --update, written to) the per-backend
# committed baseline under tests/ct_disasm/expected/{gcc,clang}.txt via
# scripts/lib/baseline.sh's regenerable-baseline idiom (the SAME
# contract api-surface/coverage already use -- see that file's own header
# comment).
#
# Needs the sello-dev image (objdump/nm are part of the standard
# binutils already in the base Nim image, but this runs inside sello-dev
# for consistency with the project's other CT-adjacent gates and because
# a future disasm-gate extension may need valgrind-adjacent tooling --
# pulled BY DIGEST via scripts/lib/sello-dev-image.sh, same convention as
# scripts/ct-taint.sh/scripts/test-libsodium.sh/scripts/bmc.sh).
#
# Usage:
#   scripts/disasm-gate.sh                    # gcc, compare against baseline
#   scripts/disasm-gate.sh --cc clang          # clang, compare against baseline
#   scripts/disasm-gate.sh --update            # regenerate the gcc baseline (never under $CI -- baseline.sh's own guard)
#   scripts/disasm-gate.sh --cc clang --update # regenerate the clang baseline
#   scripts/disasm-gate.sh --build-only        # compile the probe binary and stop (build-smoke's own use)
#   scripts/disasm-gate.sh --cc <cc> --canary  # RFC-005 slice 23 stage 4 (A6): rolling-baseline
#                                                 canary mode -- see that section below. No
#                                                 comparison against the pinned per-backend
#                                                 baseline in this mode.
#   SELLO_IN_CONTAINER=1 scripts/disasm-gate.sh [...]   # already inside sello-dev (CI)
#
# --canary mode (A6, this slice's own toolchain-canary extension): reads
# a previous rolling profile from $SELLO_DISASM_CANARY_PREV (a file path;
# absent or unset means "first run -- bootstrap"), compares ROOT-LEVEL
# conditional-branch COUNTS only (never the ordered branch list itself --
# a canary compiler's codegen differs from the pinned backend's on benign
# grounds essentially always, which is exactly why A2's own round-2 text
# scopes this to counts-only, alert-on-increase), and writes the fresh
# profile to $SELLO_DISASM_CANARY_OUT (required in this mode) for the
# caller (the toolchain-canary workflow's own actions/cache save step) to
# persist. A first-run bootstrap (no $SELLO_DISASM_CANARY_PREV, or an
# unreadable one) is logged as such and does NOT fail -- there is nothing
# to compare against yet, matching A5's fuzz-continuity canary's own
# bootstrap posture. An increase in ANY root's branch count is logged
# loud but --canary mode NEVER exits nonzero for it (A6: "failures
# notify, never gate") -- the caller workflow's own notify job is what
# turns this into a pinned-issue comment, not this script.
set -euo pipefail
cd "$(dirname "$0")/.."

cc_name="gcc"
cc_flag=""
build_only=0
do_update=0
canary=0
while [[ "${1:-}" == "--cc" || "${1:-}" == "--build-only" || "${1:-}" == "--update" || "${1:-}" == "--canary" ]]; do
  case "$1" in
    --cc)
      if [[ -z "${2:-}" ]]; then
        echo "scripts/disasm-gate.sh: --cc requires a compiler name, e.g. --cc clang" >&2
        exit 2
      fi
      cc_name="$2"
      cc_flag="--cc:$cc_name"
      shift 2
      ;;
    --build-only)
      build_only=1
      shift
      ;;
    --update)
      do_update=1
      shift
      ;;
    --canary)
      canary=1
      shift
      ;;
  esac
done

if [[ "$do_update" -eq 1 && "$canary" -eq 1 ]]; then
  echo "scripts/disasm-gate.sh: --update and --canary are mutually exclusive." >&2
  exit 2
fi

forward_args=""
if [[ -n "$cc_flag" ]]; then
  forward_args="$forward_args --cc $(printf '%q' "$cc_name")"
fi
if [[ "$build_only" -eq 1 ]]; then
  forward_args="$forward_args --build-only"
fi
if [[ "$do_update" -eq 1 ]]; then
  forward_args="$forward_args --update"
fi
if [[ "$canary" -eq 1 ]]; then
  forward_args="$forward_args --canary"
fi

disasm_gate_main() {
  mkdir -p build

  echo "disasm-gate: platform-identity canary (${cc_name})..." >&2
  scripts/lib/toolchain-canary.sh "${cc_name}" nim c ${cc_flag} -d:release --lineDir:on --outdir:build --listCmd -f -r tests/ct_disasm/main.nim

  if [ "${build_only}" -eq 1 ]; then
    echo "disasm-gate: --build-only -- tests/ct_disasm/main.nim compiled and ran once (see the canary output above); no resolution, no baseline comparison." >&2
    return 0
  fi

  local nimcache_dir="build/nimcache_disasm_${cc_name}"
  local bin="build/ct_disasm_probe_${cc_name}"
  echo "disasm-gate: building the probe binary (${cc_name}, --lineDir:on, fresh nimcache)..." >&2
  nim c ${cc_flag} -d:release --lineDir:on --nimcache:"${nimcache_dir}" -f --outdir:build -o:"${bin}" tests/ct_disasm/main.nim
  echo "disasm-gate: running the probe once (real end-to-end evidence, no verdict of its own)..." >&2
  "./${bin}"

  echo "disasm-gate: checking the root list is >= the A7 register's disasmRoots() union..." >&2
  cat > build/disasm_gate_register_probe.nim <<'EOF'
import registers/secret_targets
for r in disasmRoots():
  echo r
EOF
  local register_roots
  register_roots="$(nim r --hints:off --warnings:off --path:tests build/disasm_gate_register_probe.nim 2>/dev/null)"
  local gate_roots
  gate_roots="$(python3 -c '
import sys
sys.path.insert(0, "scripts/lib")
from disasm_gate_resolve import ROOTS
for name, *_ in ROOTS:
    print(name)
')"
  local missing=0
  while IFS= read -r r; do
    [[ -z "$r" ]] && continue
    if ! grep -qxF "$r" <<<"$gate_roots"; then
      echo "disasm-gate: FAIL -- register root '$r' (tests/registers/secret_targets.disasmRoots()) is not covered by scripts/lib/disasm_gate_resolve.py's ROOTS table." >&2
      missing=1
    fi
  done <<<"$register_roots"
  if [[ "$missing" -ne 0 ]]; then
    exit 1
  fi
  echo "disasm-gate: OK -- every register disasmRoots() entry is covered (containment, not equality -- the gate's own root set legitimately includes internal symbols with no register entry: feCMove, feCSwap, cmovCached, feSqrtRatioM1)." >&2

  echo "disasm-gate: resolving + disassembling every root (${cc_name})..." >&2
  local fresh
  fresh="$(python3 scripts/lib/disasm_gate_resolve.py "${nimcache_dir}" "${bin}" "$(pwd)")"

  if [ "${canary}" -eq 1 ]; then
    disasm_gate_canary_mode "$fresh"
    return 0
  fi

  local fresh_file="build/disasm_gate_fresh_${cc_name}.txt"
  printf '%s\n' "$fresh" > "$fresh_file"

  source "$(dirname "$0")/lib/baseline.sh"
  local pin="tests/ct_disasm/expected/${cc_name}.txt"
  local regen_cmd="scripts/disasm-gate.sh --cc ${cc_name} --update"
  local desc="disasm-gate per-root conditional-branch profile (${cc_name})"
  if [ "${do_update}" -eq 1 ]; then
    baseline_update "$pin" "$desc" "$regen_cmd" -- cat "$fresh_file"
  else
    baseline_check "$pin" "$desc" "$regen_cmd" -- cat "$fresh_file"
  fi
}

# --canary mode (A6): root-level branch-COUNT rolling baseline, alert
# -only, never gates. $SELLO_DISASM_CANARY_PREV / $SELLO_DISASM_CANARY_OUT
# are plain file paths the caller (a workflow step) owns the persistence
# of (actions/cache in CI); this function only reads/writes them.
disasm_gate_canary_mode() {
  local fresh="$1"
  local out="${SELLO_DISASM_CANARY_OUT:-}"
  if [[ -z "$out" ]]; then
    echo "disasm-gate: FAIL -- --canary mode requires \$SELLO_DISASM_CANARY_OUT (a file path to write the fresh rolling profile to)." >&2
    exit 1
  fi
  mkdir -p "$(dirname "$out")"

  # Extract "root -> branch-count" from the fresh dump (the same "==
  # root: NAME ==" / "branch-count: N" pair scripts/lib/baseline.sh's
  # generic body-diff already treats as the pinned artifact -- this mode
  # parses the identical shape rather than a second one).
  local fresh_counts
  fresh_counts="$(echo "$fresh" | awk '
    /^== root: / { name = $0; sub(/^== root: /, "", name); sub(/ ==$/, "", name) }
    /^branch-count: / { c = $0; sub(/^branch-count: /, "", c); print name "\t" c }
  ')"

  # BUG FIX (RFC-005 slice 23 stage 4, caught by a real dispatch): $out
  # and $SELLO_DISASM_CANARY_PREV are THE SAME PATH in the real CI
  # wiring (the workflow restores the prior cache entry to that path,
  # then this script overwrites it in place so the NEXT run's cache
  # -save step picks up the fresh profile). Writing $out BEFORE reading
  # $prev would silently clobber the previous profile with the fresh
  # one first, making every comparison a no-op self-compare (and a true
  # bootstrap -- no previous file at all -- indistinguishable from a
  # normal run, since the file "exists" the instant it's written). Snap
  # -shot $prev's content into memory FIRST, THEN write $out, so the
  # comparison below is always against what was ACTUALLY there before
  # this invocation touched anything.
  local prev="${SELLO_DISASM_CANARY_PREV:-}"
  local prev_snapshot=""
  local have_prev=0
  if [[ -n "$prev" && -f "$prev" ]]; then
    prev_snapshot="$(cat "$prev")"
    have_prev=1
  fi

  echo "$fresh_counts" > "$out"

  if [[ "$have_prev" -eq 0 ]]; then
    echo "disasm-gate: --canary BOOTSTRAP -- no previous rolling profile found (\$SELLO_DISASM_CANARY_PREV unset or missing). Recording this run's profile as the new baseline for next time; nothing to compare against yet." >&2
    echo "disasm-gate: canary profile (bootstrap):" >&2
    cat "$out" >&2
    return 0
  fi

  echo "disasm-gate: --canary comparing against previous rolling profile at $prev..." >&2
  local increased=0
  while IFS=$'\t' read -r name prev_count; do
    [[ -z "$name" ]] && continue
    local new_count
    new_count="$(awk -F'\t' -v n="$name" '$1==n {print $2}' "$out")"
    if [[ -z "$new_count" ]]; then
      echo "disasm-gate: --canary NOTE -- root '$name' present in the previous profile but not the fresh one (renamed/removed root, or a genuine regression in the ROOTS table -- notify only, per A6)." >&2
      continue
    fi
    if [[ "$new_count" -gt "$prev_count" ]]; then
      echo "disasm-gate: --canary ALERT -- root '$name' conditional-branch count INCREASED: ${prev_count} -> ${new_count} (${cc_name}). Failures notify, never gate (A6) -- this is a finding for the toolchain-canary workflow's notify job, not a script exit failure." >&2
      increased=1
    fi
  done <<< "$prev_snapshot"

  if [[ "$increased" -eq 0 ]]; then
    echo "disasm-gate: --canary OK -- no root-level conditional-branch-count increase vs. the previous ${cc_name} profile." >&2
  fi
}

if [ "${SELLO_IN_CONTAINER:-}" = "1" ]; then
  disasm_gate_main
else
  source "$(dirname "$0")/lib/milpa-preflight.sh"
  milpa_preflight

  source "$(dirname "$0")/lib/sello-dev-image.sh"
  resolve_sello_dev_image

  self="$(cd "$(dirname "$0")/.." && pwd)"
  podman run --rm \
    -v "$self:/workspace" \
    -v "$HOME/.cache/milpa:/.cache/milpa" \
    -v "$HOME/.cache/milpa:$HOME/.cache/milpa" \
    -w /workspace \
    "$img" \
    bash -c "SELLO_IN_CONTAINER=1 scripts/disasm-gate.sh${forward_args}"
fi
