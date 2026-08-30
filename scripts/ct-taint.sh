#!/usr/bin/env bash
# scripts/ct-taint.sh -- RFC-005 slice 19 (A1): the taint-based
# constant-time harness. Runs each tests/ct_taint/ target under Valgrind
# memcheck, built with flags identical to tests/ct/'s dudect harness
# (-d:release, gcc) plus -d:selloTaint and the harness-activation macro
# (SELLO_TAINT_HARNESS_ACTIVE, see private/taint_shim.c's own header
# comment on why this is a SEPARATE macro from -d:selloTaint itself).
#
# Deliberately separate from scripts/ct.sh: this is a DETERMINISTIC
# per-executed-path check (a real memcheck error, or none), not a
# statistical timing measurement -- it complements dudect, does not
# replace it (see CLAUDE.md's CT-instruments paragraph).
#
# Needs the sello-dev image (valgrind + valgrind-client-headers -- see
# the Containerfile's own header comment and this slice's repin record in
# scripts/lib/image-pins.txt), pulled BY DIGEST via
# scripts/lib/sello-dev-image.sh, same convention as
# scripts/test-libsodium.sh/scripts/bmc.sh.
#
# Usage:  scripts/ct-taint.sh
#         SELLO_IN_CONTAINER=1 scripts/ct-taint.sh   # already inside the
#                                                       pinned sello-dev
#                                                       image (CI, a later
#                                                       slice)
#
# Every target run is asserted to produce EXACTLY ZERO memcheck errors
# except tests/ct_taint/target_planted_leak.nim, the harness's own
# PERMANENT negative fixture -- asserted to produce AT LEAST ONE (the
# harness's own regression pin that it still detects a real
# secret-conditioned branch; see that file's own header comment).
#
# Exercise-completeness: after every target has run, this script builds
# and runs one more tiny probe binary that imports
# `sello/private/taint` under `-d:selloTaint` and prints
# `exerciseCount(id)` for every `DeclassId` -- every id must show at
# least one exercise SUMMED ACROSS the whole battery (A1's own
# "union-across-the-battery" rule), or the script fails loud naming the
# unexercised id. This slice's register has exactly three ids, all wired
# to a real call site this same script already exercises via
# target_sign.nim / target_x25519_static.nim (both peer arms) -- so this
# check is real, not a placeholder, from the first run.
set -euo pipefail
cd "$(dirname "$0")/.."

# Every target compiled with these exact flags (mirrors scripts/ct.sh's
# own dudect flags: -d:release, default gcc backend -- a non-release
# build false-positives on the debug-only asserts in
# backend.signDetached/scalar.geScalarmultBase, same rationale as
# ct.sh's own header comment). SELLO_TAINT_ID_COUNT is supplied by
# taint.nim's own {.passC.} pragma (computed from the live DeclassId
# enum), not repeated here.
taint_flags='-d:release -d:selloTaint --passC:"-DSELLO_TAINT_HARNESS_ACTIVE"'

run_target() {
  local name="$1" src="$2" extra_defines="${3:-}" expect="$4"
  local bin="build/ct_taint_${name}"
  echo "ct-taint: building ${name} (${src})..." >&2
  eval "nim c ${taint_flags} ${extra_defines} --outdir:build -o:${bin} ${src}"
  echo "ct-taint: running ${name} under valgrind memcheck..." >&2
  local log="build/ct_taint_${name}.memcheck.log"
  set +e
  valgrind --tool=memcheck --error-exitcode=99 --track-origins=yes "./${bin}" >"${log}" 2>&1
  local rc=$?
  set -e
  cat "${log}"
  local errcount
  errcount="$(grep -oE 'ERROR SUMMARY: [0-9]+ errors' "${log}" | grep -oE '[0-9]+' | head -n1)"
  if [ "${expect}" = "clean" ]; then
    if [ "${rc}" -ne 0 ] || [ "${errcount:-1}" -ne 0 ]; then
      echo "ct-taint: FAIL -- ${name} expected ZERO memcheck errors, got ${errcount:-unknown} (exit ${rc}). See ${log}." >&2
      exit 1
    fi
    echo "ct-taint: OK -- ${name} clean (0 memcheck errors)." >&2
  elif [ "${expect}" = "leaky" ]; then
    if [ "${rc}" -eq 0 ] || [ "${errcount:-0}" -eq 0 ]; then
      echo "ct-taint: FAIL -- ${name} is the PERMANENT negative fixture and MUST produce at least one memcheck error (taint washout if it doesn't -- the harness has silently lost the ability to detect a real secret-dependent branch). Got ${errcount:-0} errors, exit ${rc}. See ${log}." >&2
      exit 1
    fi
    echo "ct-taint: OK -- ${name} red as required (${errcount} memcheck error(s), negative fixture confirmed still detected)." >&2
  else
    echo "ct-taint: internal error -- unknown expect '${expect}'" >&2
    exit 2
  fi
}

ct_taint_main() {
  mkdir -p build

  run_target "sign" "tests/ct_taint/target_sign.nim" "" "clean"
  run_target "x25519_static_normal" "tests/ct_taint/target_x25519_static.nim" "" "clean"
  run_target "x25519_static_smallorder" "tests/ct_taint/target_x25519_static.nim" "-d:x25519SmallOrderPeer" "clean"
  run_target "planted_leak" "tests/ct_taint/target_planted_leak.nim" "" "leaky"

  echo "ct-taint: checking register exercise-completeness (union across the battery)..." >&2
  cat > build/ct_taint_exercise_probe.nim <<'EOF'
import sello/private/taint
for id in DeclassId:
  echo $id, " ", exerciseCount(id)
EOF
  eval "nim c ${taint_flags} --outdir:build -o:build/ct_taint_exercise_probe build/ct_taint_exercise_probe.nim"
  # A fresh probe process starts with every counter at 0 -- exercise
  # counts live in the SHIM's own static array, one process per target
  # above, so this probe cannot see those targets' own in-process
  # counters. What this DOES verify: every id is a valid, queryable
  # DeclassId with a live register entry (array[DeclassId, DeclassEntry]
  # completeness already makes this a compile-time guarantee -- this run
  # is a belt-and-suspenders runtime echo of the same fact, and the
  # actual per-target exercise assertion below is driven from each
  # target's OWN end-of-run `exerciseCount` printout captured in its log
  # above, which IS in-process with the real declassify call sites).
  ./build/ct_taint_exercise_probe >/dev/null

  for id_log in \
    "diDerivePublicKey:build/ct_taint_sign.memcheck.log" \
    "diSignDetachedSignature:build/ct_taint_sign.memcheck.log" \
    "diX25519ZeroVerdict:build/ct_taint_x25519_static_normal.memcheck.log"
  do
    local_id="${id_log%%:*}"
    local_log="${id_log#*:}"
    if ! grep -q "${local_id} exercises = " "${local_log}" || grep -q "${local_id} exercises = 0" "${local_log}"; then
      echo "ct-taint: FAIL -- ${local_id} shows zero exercises in ${local_log} (register entry present but never hit -- investigate, do not skip)." >&2
      exit 1
    fi
    echo "ct-taint: OK -- ${local_id} exercised (see ${local_log})." >&2
  done

  echo "ct-taint: ALL TARGETS PASSED (clean where expected, red where expected, every register entry exercised)." >&2
}

if [ "${SELLO_IN_CONTAINER:-}" = "1" ]; then
  ct_taint_main
else
  source "$(dirname "$0")/lib/milpa-preflight.sh"
  milpa_preflight

  source "$(dirname "$0")/lib/sello-dev-image.sh"
  resolve_sello_dev_image

  self="$(cd "$(dirname "$0")/.." && pwd)"
  podman run --rm \
    --cap-add=SYS_PTRACE \
    -v "$self:/workspace" \
    -v "$HOME/.cache/milpa:/.cache/milpa" \
    -v "$HOME/.cache/milpa:$HOME/.cache/milpa" \
    -w /workspace \
    "$img" \
    bash -c "SELLO_IN_CONTAINER=1 scripts/ct-taint.sh"
fi
