#!/usr/bin/env bash
# scripts/lib/milpa-preflight.sh — lockfile-conformance preflight (RFC-001
# ledger finding 30). `source`d by scripts/test.sh, scripts/test-libsodium.sh,
# scripts/ct.sh, scripts/fuzz.sh, and scripts/bmc.sh, each of which calls
# `milpa_preflight` once near the top, after `cd`-ing to the repo root and
# before the podman invocation -- so a stale/corrupt dependency tree fails
# fast on the HOST, not two layers down inside a container.
#
# Cheap mechanism: run `milpa verify` on the host (never in-container --
# `_deps/`/`milpa.lock` are host-side state; the podman mount just exposes
# them to the container) and react to what it actually prints and exits,
# verified empirically against this milpa build (0.0.1) rather than assumed
# from its --help text alone:
#
#   - no `milpa` binary on PATH: warn and continue (exit 0). Not every
#     dev/CI environment that can run these scripts necessarily has milpa
#     installed (e.g. one with `_deps/`/`nim.cfg` already populated by some
#     other mechanism) -- this preflight is a courtesy staleness check
#     layered on top of the existing prerequisite ("milpa fetch has been
#     run at least once", documented in each script's own header comment),
#     not a new hard dependency every invocation gains. An environment that
#     currently works without milpa on PATH must keep working.
#
#   - `milpa verify` exits 0: lockfile and `_deps/` agree; proceed silently.
#
#   - `milpa verify` exits non-zero with `FROZEN-ACTIVE-FLAGS-MISMATCH` in
#     its output: warn, but do not fail. Confirmed by direct
#     experimentation, not assumed: `milpa verify -h` takes no `--features`
#     flag of its own, so it always recomputes expected activation from the
#     manifest's ZERO-feature default -- it has no way to know a prior
#     `milpa fetch --features nelli` (sello's own documented, ordinary
#     local-dev step; see scripts/test.sh's header comment) is what produced
#     the current, fully self-consistent `_deps/`/`milpa.lock` state. Every
#     workflow that has ever run the nelli-enabling fetch trips this
#     specific code on every subsequent plain `milpa verify`, forever,
#     even though nothing is actually stale -- reproduced on this exact
#     repo while writing this preflight. Treating it as fatal would make
#     the preflight fail on the very state most of these scripts require
#     (test.sh/test-libsodium.sh/fuzz.sh/bmc.sh all need the optional
#     nelli dep fetched). This is a milpa 0.0.1 limitation (verify
#     cannot express "check against a non-default feature selection"), not
#     drift, so it gets a warning, not a hard stop.
#
#   - any OTHER non-zero exit: a real conformance failure (a dep missing
#     from `_deps/`, a content-hash mismatch, a corrupted entry, etc.) --
#     fail loudly with the fix command, before the podman invocation ever
#     starts.
milpa_preflight() {
  if ! command -v milpa >/dev/null 2>&1; then
    echo "milpa_preflight: 'milpa' not found on PATH -- skipping the lockfile-conformance check (see scripts/lib/milpa-preflight.sh)" >&2
    return 0
  fi

  # Callers run under `set -e`: a bare `out="$(cmd)"` assignment propagates
  # `cmd`'s exit status to the assignment itself, which `set -e` treats as
  # a failing simple command and aborts the whole script right there --
  # before this function ever gets to inspect $out. Running the capture as
  # an `if` condition sidesteps that (a command's exit status inside an
  # `if`/`while` test is explicitly exempted from triggering errexit).
  local out rc
  if out="$(milpa verify 2>&1)"; then
    rc=0
  else
    rc=$?
  fi

  if [ "$rc" -eq 0 ]; then
    return 0
  fi

  if printf '%s' "$out" | grep -q 'FROZEN-ACTIVE-FLAGS-MISMATCH'; then
    echo "milpa_preflight: warning -- 'milpa verify' reports a feature-activation mismatch, not real drift (known milpa 0.0.1 limitation: verify has no --features flag of its own and always checks against the zero-feature default, so any host that has ever run 'milpa fetch --features nelli' trips this every time). Continuing." >&2
    return 0
  fi

  echo "milpa_preflight: 'milpa verify' failed -- milpa.lock and _deps/ are out of sync. Run 'milpa fetch' (or 'milpa fetch --features nelli' if you need the optional property-testing/fuzzing/Z3 deps -- see scripts/test.sh's header comment) and retry." >&2
  echo "$out" >&2
  return 1
}
