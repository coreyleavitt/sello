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
# unexercised id. Slice 19 wired the first three ids (target_sign.nim /
# target_x25519_static.nim, both peer arms); RFC-005 slice 21 wired the
# remaining six (x25519's base-public-key id shared by both x25519Base
# overloads, ristretto's encode/equal/import-reject/ephemeral-zero-
# verdict ids, and sha512's digest-KAT id) via the additional targets
# below -- so this check is real, not a placeholder, across every id.
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

  # RFC-005 slice 21: the remaining targets -- one module at a time,
  # matching CLAUDE.md's own "the mechanical ~5-module sweep" note.
  run_target "x25519_base" "tests/ct_taint/target_x25519_base.nim" "" "clean"
  run_target "x25519_ephemeral_normal" "tests/ct_taint/target_x25519_ephemeral.nim" "" "clean"
  run_target "x25519_ephemeral_smallorder" "tests/ct_taint/target_x25519_ephemeral.nim" "-d:x25519SmallOrderPeer" "clean"
  run_target "wipe_x25519" "tests/ct_taint/target_wipe_x25519.nim" "" "clean"

  run_target "keypair_expected_public_match" "tests/ct_taint/target_keypair_expected_public.nim" "" "clean"
  run_target "keypair_expected_public_mismatch" "tests/ct_taint/target_keypair_expected_public.nim" "-d:keypairMismatch" "clean"
  run_target "wipe_signing" "tests/ct_taint/target_wipe_signing.nim" "" "clean"

  run_target "ristretto_scalarmult" "tests/ct_taint/target_ristretto_scalarmult.nim" "" "clean"
  run_target "ristretto_ephemeral_normal" "tests/ct_taint/target_ristretto_ephemeral.nim" "" "clean"
  run_target "ristretto_ephemeral_identity" "tests/ct_taint/target_ristretto_ephemeral.nim" "-d:ristrettoIdentityPeer" "clean"
  run_target "ristretto_from_uniform" "tests/ct_taint/target_ristretto_from_uniform.nim" "" "clean"
  run_target "ristretto_import_canonical" "tests/ct_taint/target_ristretto_import.nim" "" "clean"
  run_target "ristretto_import_noncanonical" "tests/ct_taint/target_ristretto_import.nim" "-d:ristrettoImportNonCanonical" "clean"
  run_target "wipe_ristretto" "tests/ct_taint/target_wipe_ristretto.nim" "" "clean"

  run_target "sha512" "tests/ct_taint/target_sha512.nim" "" "clean"

  run_target "wipe_generic" "tests/ct_taint/target_wipe_generic.nim" "" "clean"

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
    "diX25519ZeroVerdict:build/ct_taint_x25519_static_normal.memcheck.log" \
    "diX25519BasePublicKey:build/ct_taint_x25519_base.memcheck.log" \
    "diRistrettoEncodeOutput:build/ct_taint_ristretto_scalarmult.memcheck.log" \
    "diRistrettoEqualVerdict:build/ct_taint_ristretto_scalarmult.memcheck.log" \
    "diRistrettoStaticSecretImportReject:build/ct_taint_ristretto_import_canonical.memcheck.log" \
    "diRistrettoEphemeralZeroVerdict:build/ct_taint_ristretto_ephemeral_normal.memcheck.log" \
    "diSha512DigestKat:build/ct_taint_sha512.memcheck.log"
  do
    local_id="${id_log%%:*}"
    local_log="${id_log#*:}"
    if ! grep -q "${local_id} exercises = " "${local_log}" || grep -q "${local_id} exercises = 0" "${local_log}"; then
      echo "ct-taint: FAIL -- ${local_id} shows zero exercises in ${local_log} (register entry present but never hit -- investigate, do not skip)." >&2
      exit 1
    fi
    echo "ct-taint: OK -- ${local_id} exercised (see ${local_log})." >&2
  done

  echo "ct-taint: checking register taint-column coverage (assert-against, RFC-005 slice 20/A7)..." >&2
  # tests/registers/secret_targets.nim's `taint` coverage cell is asserted
  # here rather than in Nim (ct_main.nim's own compile-time assert-against
  # is possible because dudect's target set is enumerable at compile time
  # via one const array; this harness's targets are separate PROCESSES run
  # by this script, so their "name" identity only exists here, in bash) --
  # every `ckDirect` taint cell's `name` must be one of the target
  # identities this script actually ran above; a `ckExempt` cell whose
  # rationale begins with the literal "PENDING (slice 21)" is printed as
  # an honest skip, never silently treated as covered (this slice's own
  # scope (c) instruction: "never silently green").
  python3 - <<'PYEOF'
import re
import sys

names_run = {
    "sign", "x25519_static_normal", "x25519_static_smallorder",
    # RFC-005 slice 21 additions:
    "x25519_base", "x25519_ephemeral_normal", "x25519_ephemeral_smallorder",
    "wipe_x25519",
    "keypair_expected_public_match", "keypair_expected_public_mismatch",
    "wipe_signing",
    "ristretto_scalarmult", "ristretto_ephemeral_normal",
    "ristretto_ephemeral_identity", "ristretto_from_uniform",
    "ristretto_import_canonical", "ristretto_import_noncanonical",
    "wipe_ristretto",
    "sha512",
    "wipe_generic",
}
# ^ the identity anchors this script's own run_target calls above use --
# "planted_leak" is deliberately excluded: it is the harness's own
# PERMANENT negative fixture, not a secret_targets.nim register entry.

text = open("tests/registers/secret_targets.nim").read()
# One block per `SecretTargetEntry(...)` -- split on the entry-opening
# marker so each block's own `taint:` field cannot bleed into another
# entry's (the register's own author-facing formatting keeps one entry
# per `id: st...,` / `taint: Coverage(...)` pair; this is the same
# light, single-pass text-scan register gates-manifest-check.sh's own
# awk scan already precedents for a hand-written, reviewed source file).
blocks = re.split(r'\n  st\w+: SecretTargetEntry\(', text)[1:]

# Each entry's field order is fixed (qualifiedProc, facadeExported,
# ruleBasis, secretShape, dudect, taint, disasm, declassIds, note), so the
# taint cell is isolated as the span from its own `taint: Coverage(` up to
# the NEXT field's `disasm:` label -- robust to the cell's rationale text
# spanning one line or several. A `ckExempt` cell whose rationale is the
# BARE identifier `Pending` (referencing this module's own `const Pending
# = "PENDING (slice 21) -- ..."`, never re-typed as a literal string at
# each of its 28 call sites) is the temporary/slice-21 register; every
# other `ckExempt` cell's rationale is a literal string -- a PERMANENT,
# stated design boundary.
direct_names = []
pending_count = 0
permanent_exempt_count = 0
covered_by_count = 0
for block in blocks:
    m = re.search(r'\n    id: (\w+),', block)
    entry_id = m.group(1) if m else "<unknown>"
    tm = re.search(r'taint: Coverage\(.*?\n    disasm:', block, re.S)
    if not tm:
        sys.stderr.write(f"ct-taint: FAIL -- could not isolate a taint "
                          f"cell for register entry {entry_id}.\n")
        sys.exit(1)
    span = tm.group(0)
    if 'kind: ckDirect' in span:
        nm = re.search(r'name: "([^"]*)"', span)
        direct_names.append((entry_id, nm.group(1) if nm else "<unnamed>"))
    elif 'kind: ckCoveredBy' in span:
        covered_by_count += 1
    elif re.search(r'rationale:\s*Pending\b', span):
        pending_count += 1
    else:
        permanent_exempt_count += 1

missing = [(eid, name) for eid, name in direct_names if name not in names_run]
if missing:
    sys.stderr.write(
        "ct-taint: FAIL -- the following register entries are taint-"
        "ckDirect but name a target this script did not run: "
        + ", ".join(f"{eid} -> {name!r}" for eid, name in missing) + "\n")
    sys.exit(1)

print(f"ct-taint: OK -- {len(direct_names)} taint-direct register "
      f"entr{'y' if len(direct_names) == 1 else 'ies'} all correspond to "
      f"a target actually run this invocation: "
      + ", ".join(f"{eid}->{name}" for eid, name in direct_names))
print(f"ct-taint: {covered_by_count} register entr"
      f"{'y is' if covered_by_count == 1 else 'ies are'} taint-coveredBy "
      f"another entry (not independently asserted here).")
print(f"ct-taint: {pending_count} register entr"
      f"{'y is' if pending_count == 1 else 'ies are'} taint-PENDING "
      f"slice 21 (named in A1's own target list, no live target yet -- "
      f"printed for visibility, never silently treated as covered).")
print(f"ct-taint: {permanent_exempt_count} register entr"
      f"{'y is' if permanent_exempt_count == 1 else 'ies are'} taint-"
      f"exempt permanently (a stated design boundary, e.g. the secret-"
      f"OUTPUT-disclosure rule).")
PYEOF

  echo "ct-taint: ALL TARGETS PASSED (clean where expected, red where expected, every register entry exercised, register taint column checked)." >&2
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
