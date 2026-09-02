#!/usr/bin/env bash
# scripts/memcheck.sh -- RFC-005 slice 26's own A9 sub-item (untainted
# nightly memcheck): plain, UNTAINTED Valgrind memcheck over the ordinary
# unit suite -- the class of bug ASan cannot see (uninitialized reads,
# invalid heap/stack accesses caught only by Valgrind's own shadow-memory
# tracking, not compiler-inserted redzones) and the class MSan was
# declined over (CLAUDE.md's own A9 paragraph: "TSan is a recorded
# non-goal ... the codebase's sole concurrency is backend_sodium's
# std/atomics once-guard" -- the same reasoning extends to MSan/memcheck:
# Valgrind's setup cost is already paid by the taint CT harness (A1,
# scripts/ct-taint.sh), so this is the SAME instrument, pointed at the
# ORDINARY unit suite instead of the taint targets -- not a new tool.
#
# DELIBERATELY DIFFERENT from scripts/ct-taint.sh in what it checks: that
# script asserts a DETERMINISTIC secret-dependent-branch verdict (a
# hand-picked target list, each expected exactly clean or exactly leaky)
# via Valgrind's CLIENT-REQUEST taint API. This script asserts a much
# more ordinary thing -- that Valgrind's memcheck finds ZERO
# uninitialized-read/invalid-access errors anywhere the real unit suite's
# own KATs/adversarial-vector runs touch -- over the SAME test binaries
# scripts/test.sh already compiles and runs natively, just executed under
# `valgrind --tool=memcheck` instead of directly.
#
# Scope: UNIT SUITE ONLY, same as unit-linux-amd64-gcc-asan-ubsan/
# unit-linux-i386-gcc/the two hosted-residual legs -- this script never
# fetches nelli, so tests/unit/unit-test-files.sh's own dynamic
# _deps/nelli detection (scripts/lib/unit-test-files.sh's header
# comment) naturally excludes the six test_properties_*.nim files from
# the array this script iterates, with no special-casing needed here.
# Property-based generative search under a 20-50x Valgrind slowdown on
# TOP of nelli's own per-example overhead would blow well past this
# job's nightly budget for a class of bug the property suites are not
# designed to surface in the first place (they assert FUNCTIONAL
# properties, not memory safety) -- the RFC's own A9 text scopes this to
# "the unit suite," not the full validation-tier battery.
#
# --- Build-flag decision (recorded, not left implicit) ------------------
#
# `-d:useMalloc`: REQUIRED, the identical reasoning scripts/test.sh's own
# --sanitize asan-ubsan header comment already recorded for ASan, restated
# here because it is equally load-bearing for Valgrind: Nim's ORC memory
# manager (this project's standing --mm:orc) services allocations from its
# own arena allocator by default, which Valgrind's memcheck cannot
# instrument -- allocations never call the real libc malloc/free memcheck
# intercepts, so heap-tracking (uninitialized reads INTO heap-allocated
# memory, use-after-free, etc.) would silently go uninstrumented without
# this flag. Verified empirically this slice with TWO isolated scratch
# probes (not merely assumed by analogy to the ASan case): a probe with a
# deliberate uninitialized STACK read (`{.noinit.}` local) was caught by
# memcheck identically with and without -d:useMalloc (`--error-exitcode=99`
# fired both ways) -- memcheck's stack tracking needs no help from this
# flag, it instruments every stack frame regardless of the allocator. A
# second probe with a deliberate uninitialized HEAP read (raw
# `alloc`/`UncheckedArray` access, no zero-init) was MISSED entirely
# WITHOUT -d:useMalloc (exit 0, "ERROR SUMMARY: 0 errors") and correctly
# CAUGHT with it (exit 99, "ERROR SUMMARY: 8 errors") -- the reproduced,
# not merely assumed, confirmation that ORC's own arena is genuinely
# invisible to Valgrind without this flag. -d:useMalloc is kept ON
# unconditionally: this script's job is exercising memcheck's FULL
# detection surface (heap included), not only the stack-local class this
# slice's own red demo happens to use.
#
# NOT `-d:release`: the ordinary unit suite (scripts/test.sh's own
# default, no -d:release) is what this leg exercises -- unlike
# scripts/ct-taint.sh's secret-holding CT targets (which need
# -d:release specifically to skip debug-only re-derivation asserts in
# backend.signDetached/scalar.geScalarmultBase that would otherwise run
# under this leg's own -d:useMalloc-only build), this script's targets are
# the SAME test binaries unit-linux-amd64-gcc already compiles and runs
# natively -- running them under a DIFFERENT optimization/assert profile
# than what merge-gate itself exercises would make a memcheck finding
# harder to reproduce/correlate against the required check, for no
# benefit (memcheck's own instrumentation is unaffected by -d:release).
#
# --- Leak-check policy (recorded, not left implicit) --------------------
#
# `--leak-check=no`: deliberately DISABLED. Leak detection is not this
# job's target (the RFC's own A9 text: "uninitialized reads and invalid
# accesses ... the ~20-50x slowdown is nightly-shaped" -- no mention of
# leaks), and Nim's ORC arena allocator holds long-lived pool memory by
# design that a naive leak scan would flag as "definitely lost" even
# though it is release()'d (or simply process-exit-reclaimed) correctly --
# the identical false-positive risk scripts/test.sh's own --sanitize
# asan-ubsan header already recorded for LeakSanitizer, restated here for
# Valgrind's own leak checker. Uninitialized-read/invalid-access
# detection (this job's actual target) is unaffected by this flag --
# memcheck's core instrumentation runs regardless of the leak-checker
# setting.
#
# --track-origins=yes: kept ON (unlike scripts/ct-taint.sh, which omits
# it) -- that script's targets are small, hand-picked CT harnesses where a
# bare "uninitialized value" report is already actionable; this script
# runs the FULL unit suite (thousands of lines of adversarial-vector
# parsing, KAT fixtures, etc.), where an origin trace is the difference
# between an actionable finding and an unusable one.
#
# Usage:  scripts/memcheck.sh
#         SELLO_IN_CONTAINER=1 scripts/memcheck.sh   # already inside the
#                                                     # pinned sello-dev
#                                                     # image (CI)
set -euo pipefail
cd "$(dirname "$0")/.."

memcheck_main() {
  mkdir -p build
  source "$(dirname "$0")/lib/unit-test-files.sh"

  if [[ "${#skipped_property_files[@]}" -eq 0 && "${#unit_test_files[@]}" -gt 14 ]]; then
    echo "memcheck: NOTE -- _deps/nelli is present in this environment, so unit-test-files.sh's own array already includes the property suites; this script does not filter them back out (see its own header on why nightly practice is to leave nelli unfetched for this job, not to special-case it here)." >&2
  fi

  echo "memcheck: platform-identity canary (gcc, -d:useMalloc)..." >&2
  scripts/lib/toolchain-canary.sh gcc nim c -d:useMalloc --listCmd -f -o:build/memcheck_canary_probe --outdir:build tests/unit/test_field.nim >/dev/null

  any_fail=0
  for f in "${unit_test_files[@]}"; do
    bn="$(basename "$f" .nim)"
    bin="build/memcheck_${bn}"
    log="build/memcheck_${bn}.log"
    echo "memcheck: building ${f}..." >&2
    nim c -d:useMalloc --outdir:build -o:"$bin" "$f"
    echo "memcheck: running ${bn} under valgrind memcheck..." >&2
    set +e
    valgrind --tool=memcheck --error-exitcode=99 --track-origins=yes --leak-check=no "./${bin}" >"${log}" 2>&1
    rc=$?
    set -e
    if [[ "$rc" -ne 0 ]]; then
      any_fail=1
      echo "memcheck: FAIL -- ${f} produced a real memcheck error (exit ${rc}). Full log below -- see this script's own header comment: do NOT fix inline, escalate with the stack trace." >&2
      cat "${log}" >&2
    else
      errcount="$(grep -oE 'ERROR SUMMARY: [0-9]+ errors' "${log}" | grep -oE '[0-9]+' | head -n1 || true)"
      echo "memcheck: OK -- ${f} clean (${errcount:-0} memcheck errors)." >&2
    fi
  done

  if [[ "$any_fail" -ne 0 ]]; then
    echo "memcheck: FAIL -- at least one unit test binary produced a real memcheck error. See the logs above (also preserved at build/memcheck_*.log)." >&2
    exit 1
  fi

  echo "memcheck: ALL CLEAN -- every unit test binary ran with zero memcheck errors (uninitialized reads / invalid accesses)." >&2
}

if [ "${SELLO_IN_CONTAINER:-}" = "1" ]; then
  memcheck_main
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
    bash -c "SELLO_IN_CONTAINER=1 scripts/memcheck.sh"
fi
