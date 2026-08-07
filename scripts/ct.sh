#!/usr/bin/env bash
# Run tests/ct's dudect-style constant-time timing harness. Replaces the
# old `nimble ct` task. Deliberately separate from scripts/test.sh -- this
# is statistical and environment-sensitive (t-statistics, not a fixed
# pass/fail vector), takes much longer (>= 1e6 samples/class per target),
# and its honest interpretation belongs in docs/ct-results.md, not the
# green/red signal of the main suite.
#
# Usage:  scripts/ct.sh
#
# Mounts: the project + the milpa CAS (at both the canonical path and its
# host-absolute path, so milpa's absolute dep symlinks under _deps/
# resolve in-container). Prerequisite: `milpa fetch` has been run on the
# host at least once (see scripts/test.sh).
set -euo pipefail
cd "$(dirname "$0")/.."

# Lockfile-conformance preflight (RFC-001 ledger finding 30) -- see
# scripts/lib/milpa-preflight.sh for exactly what this does and does not
# treat as fatal.
source "$(dirname "$0")/lib/milpa-preflight.sh"
milpa_preflight

# Environment preflight banner (RFC-003 slice 5 item 2). Slice 4's run
# disclosed a shared-host caveat (an idle unrelated container, a load
# average spike) that only made it into docs/ct-results.md because the
# agent running it happened to check and hand-transcribe `podman ps`/
# `uptime` output -- a mechanism that already failed once and is not
# something to keep relying on. This prints the same class of
# observations, unconditionally, every run, so they land in the captured
# log instead. WARN, never hard-fail (RFC-003 non-goals: "environments
# legitimately vary" -- the compromise being fixed is silence about the
# environment, not intolerance of a noisy one).
echo "=============================================================="
echo "ct.sh environment preflight"
echo "=============================================================="

governor="unknown"
governor_file=$(ls /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null | head -n1 || true)
if [ -n "${governor_file:-}" ] && [ -r "$governor_file" ]; then
  governor="$(cat "$governor_file")"
  echo "CPU scaling governor (cpu0): $governor"
else
  echo "CPU scaling governor: UNAVAILABLE (no /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor -- cannot read, continuing)"
fi
if [ "$governor" = "powersave" ]; then
  echo "WARN: governor is 'powersave', not 'performance' -- frequency scaling is a source of timing-measurement noise (interleaving cancels it on average but not sample-by-sample). See docs/ct-results.md."
fi

container_count="unknown"
if command -v podman >/dev/null 2>&1; then
  container_count="$(podman ps --format '{{.ID}}' 2>/dev/null | wc -l | tr -d ' ')"
  echo "Running containers (host 'podman ps', excluding the one this run is about to start): $container_count"
  if [ -n "$container_count" ] && [ "$container_count" != "0" ]; then
    echo "WARN: $container_count container(s) already running on this host -- shared-host scheduling noise may inflate variance. Detail:"
    podman ps 2>/dev/null | sed 's/^/    /'
  fi
else
  echo "Running containers: UNAVAILABLE (podman not on PATH -- cannot check, continuing)"
fi

load_line="unavailable"
if [ -r /proc/loadavg ]; then
  load_line="$(cat /proc/loadavg)"
  load1="$(awk '{print $1}' /proc/loadavg)"
  echo "Load average (1m 5m 15m, running/total procs, last pid): $load_line"
  # High-load warning: compare 1-minute load (integer part) against a
  # generous fixed threshold rather than trying to detect core count in
  # bash -- this is a WARN heuristic, not a precise per-core computation.
  load1_int="${load1%%.*}"
  if [ -n "$load1_int" ] && [ "$load1_int" -ge 4 ] 2>/dev/null; then
    echo "WARN: 1-minute load average ($load1) is high -- consider re-running when the host is quieter. See docs/ct-results.md."
  fi
else
  echo "Load average: UNAVAILABLE (/proc/loadavg not readable -- cannot check, continuing)"
fi

echo "=============================================================="
echo "(warnings above are recorded, not enforced -- RFC-003 slice 5: environments legitimately vary. Proceeding.)"
echo "=============================================================="
echo ""

img=ghcr.io/coreyleavitt/nim:2.2.10

podman run --rm \
  -v "$PWD:/workspace" \
  -v "$HOME/.cache/milpa:/.cache/milpa" \
  -v "$HOME/.cache/milpa:$HOME/.cache/milpa" \
  -w /workspace \
  "$img" \
  bash -c '
    set -e
    nim c -d:release --outdir:build tests/ct/ct_main.nim
    bin=build/ct_main
    if command -v taskset >/dev/null 2>&1; then
      echo "pinning to core 0 via taskset"
      taskset -c 0 "$bin"
    else
      echo "taskset not found -- running WITHOUT CPU pinning (see docs/ct-results.md)"
      "$bin"
    fi
  '
