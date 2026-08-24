#!/usr/bin/env bash
# scripts/merge-gate.sh — RFC-005 slice 3: run the required merge-gate
# checks locally, reading scripts/lib/gates.txt (the two-column manifest
# that also generates the future ruleset's required-check array and is
# checked for drift against .github/workflows/merge-gate.yml by
# scripts/gates-manifest-check.sh's "gates-manifest-sync" job) so this
# script can never diverge from what CI actually runs by name -- only the
# manifest's own script-invocation column decides that, and it is
# reviewed alongside the workflow file it must match.
#
# Usage:
#   scripts/merge-gate.sh                          # run every gate
#   scripts/merge-gate.sh <gate-name> [<gate-name> ...]
#                                                    # run a named subset
#   scripts/merge-gate.sh -h | --help
#
# Each gate is one scripts/ invocation (RFC-005 Part B's build-path
# invariant). Every gate script in the manifest is dual-mode: it wraps
# itself in the pinned podman image automatically when run here (no
# SELLO_IN_CONTAINER set), the same way a maintainer's existing
# `scripts/test.sh` invocation always has -- so this script needs podman
# on PATH and the same documented prerequisite those scripts already
# state (`milpa fetch` run at least once). It does no podman-wrapping of
# its own; that stays each gate script's own concern (RFC-005 slice 3
# decision -- see scripts/lib/gates.txt's header comment for why the
# manifest's script-invocation column can stay a literal, host-runnable
# command).
#
# THIS RUNS THE LINUX SET ONLY. macOS-arm64 and Windows/MinGW legs
# (RFC-005 slices 12-13) do not exist yet, and when they land they run
# NATIVELY on their own hosts (Windows via Git Bash) -- there is no
# "run the macOS leg locally" mode on a Linux workstation, and this
# script does not pretend otherwise. Update this comment and the help
# text below in the same slice that adds those legs, not before.
#
# Within "the Linux set," the two `*-arm64-*` gates (RFC-005 slice 11)
# are themselves host-arch-dependent: their script-invocation column
# hardcodes SELLO_IN_CONTAINER=1 (no podman wrap exists for them at all --
# scripts/lib/gates.txt's own header comment on this slice's entries has
# the full reasoning) and installs a native aarch64 Nim toolchain via
# scripts/ci-nim-setup.sh, whose own platform-identity canary REJECTS the
# run outright on a non-aarch64 host. Running `scripts/merge-gate.sh` (no
# arguments, or naming an arm64 gate explicitly) on a typical amd64
# workstation therefore reports those two gates FAIL by design, not a
# bug in this script -- exactly the same "hosted-only residual" category
# macOS/Windows will join, just arriving one slice earlier since arm64's
# gates.txt entries exist starting now. Run them for real only on an
# actual arm64 Linux host, or rely on the CI job.
#
# Fail-fast per gate, full summary at the end: every gate script already
# runs under its own `set -euo pipefail` (fails fast internally, at its
# first error), but this script does NOT stop at the first FAILING gate
# -- it runs every selected gate to completion and reports a per-gate
# PASS/FAIL table, so one push-equivalent local run surfaces every
# failure at once rather than one gate at a time across repeated
# invocations.
set -uo pipefail
cd "$(dirname "$0")/.."

usage() {
  cat <<'EOF'
Usage: scripts/merge-gate.sh [gate-name ...]

Runs sello's required merge-gate checks locally, reading
scripts/lib/gates.txt -- the same manifest .github/workflows/merge-gate.yml
is checked against (scripts/gates-manifest-check.sh) and the future
ruleset's required-check array will be generated from (RFC-005 slice 4).

  scripts/merge-gate.sh                      run every gate in the manifest
  scripts/merge-gate.sh <gate-name> ...      run only the named gate(s)
  scripts/merge-gate.sh -h | --help          this text

Known gate names (from scripts/lib/gates.txt):
EOF
  source "$(dirname "$0")/lib/gates.sh"
  load_gates
  local n
  for n in "${gate_check_names[@]}"; do
    printf '  %s\n' "$n"
  done
  cat <<'EOF'

THIS RUNS THE LINUX SET ONLY. macOS-arm64 and Windows/MinGW legs are
hosted-only residuals: none exist in the manifest yet (RFC-005 slices
12-13), and when they land they run natively on their own hosts, not
through this script on a Linux workstation.

The unit-linux-arm64-gcc / property-linux-arm64-gcc gates (RFC-005 slice
11) are themselves a hosted-only residual WITHIN the Linux set: they have
no container/podman story at all and install a native aarch64 Nim
toolchain directly, so running them on a non-aarch64 host fails loud via
scripts/ci-nim-setup.sh's own platform-identity canary -- expected, not a
bug in this script.

Prerequisites: podman on PATH, and `milpa fetch` run at least once in
this checkout (same prerequisite scripts/test.sh's own header documents)
-- each gate script wraps itself in the pinned podman image automatically
(except the arm64 gates above, which never use podman).

Exit status: nonzero if any run gate fails.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

source "$(dirname "$0")/lib/gates.sh"
load_gates

if [[ "${#gate_check_names[@]}" -eq 0 ]]; then
  echo "merge-gate.sh: scripts/lib/gates.txt parsed to zero gates -- refusing to run an empty battery (check the manifest for a parse problem)." >&2
  exit 1
fi

selected_names=()
if [[ $# -eq 0 ]]; then
  selected_names=("${gate_check_names[@]}")
else
  for arg in "$@"; do
    found=0
    for n in "${gate_check_names[@]}"; do
      if [[ "$n" == "$arg" ]]; then
        found=1
        break
      fi
    done
    if [[ "$found" -eq 0 ]]; then
      echo "merge-gate.sh: unknown gate '$arg'. Known gates:" >&2
      printf '  %s\n' "${gate_check_names[@]}" >&2
      exit 2
    fi
    selected_names+=("$arg")
  done
fi

declare -A gate_status
declare -A gate_seconds
overall_rc=0

for name in "${selected_names[@]}"; do
  invocation=""
  for i in "${!gate_check_names[@]}"; do
    if [[ "${gate_check_names[$i]}" == "$name" ]]; then
      invocation="${gate_invocations[$i]}"
      break
    fi
  done

  echo ""
  echo "======================================================================="
  echo "merge-gate: running '$name' -- $invocation"
  echo "======================================================================="

  start=$(date +%s)
  if bash -c "$invocation"; then
    rc=0
  else
    rc=$?
  fi
  end=$(date +%s)

  gate_seconds["$name"]=$((end - start))
  if [[ "$rc" -eq 0 ]]; then
    gate_status["$name"]="PASS"
  else
    gate_status["$name"]="FAIL"
    overall_rc=1
  fi
done

echo ""
echo "======================================================================="
echo "merge-gate summary"
echo "======================================================================="
for name in "${selected_names[@]}"; do
  printf "  %-28s %-4s (%ds)\n" "$name" "${gate_status[$name]}" "${gate_seconds[$name]}"
done
echo "======================================================================="
if [[ "$overall_rc" -eq 0 ]]; then
  echo "merge-gate: ALL GATES PASSED"
else
  echo "merge-gate: ONE OR MORE GATES FAILED"
fi

exit "$overall_rc"
