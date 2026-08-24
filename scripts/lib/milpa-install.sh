#!/usr/bin/env bash
# scripts/lib/milpa-install.sh — RFC-005 slice 2: builds milpa from the
# commit pinned in scripts/lib/milpa-pin.txt, inside whatever environment
# this is sourced from (the digest-pinned Nim toolchain image, in CI).
#
# `source`d by scripts/ci-property.sh; not a standalone script (declares
# `install_milpa` into the sourcing shell, same convention as
# scripts/lib/milpa-preflight.sh and scripts/lib/unit-test-files.sh).
#
# milpa publishes no release artifact -- it is a source-only, two-
# implementation project (Python reference + Rust, see its own README).
# The mechanics settled on here: the Python reference implementation,
# installed with `pip` into an isolated venv rather than the README's own
# `uv tool install` route, because the pinned Nim image
# (ghcr.io/coreyleavitt/nim:2.2.10, openSUSE Tumbleweed base) ships
# python3 + the stdlib `venv` module but no `uv` binary -- verified
# empirically rather than assumed, and adding a whole second package
# manager to the pinned image for this one job was rejected as
# disproportionate. `venv` bundles its own pip bootstrap (no `ensurepip`
# step needed), so this has no dependency beyond python3 itself.
#
# The venv is isolated under a directory the caller controls (normally
# build/milpa-venv -- gitignored, matching every other build/ artifact in
# this project) so this never touches the container's system Python.
#
# Idempotent within one venv directory: if a previous install already
# matches the requested SHA (recorded in a marker file inside the venv),
# re-installing is skipped -- harmless in CI (a fresh container every run
# has no venv to find) and saves a rebuild for local/manual re-invocation.
install_milpa() {
  local pin_file venv_dir pinned_sha marker
  pin_file="$(dirname "${BASH_SOURCE[0]}")/milpa-pin.txt"
  venv_dir="${1:?install_milpa: venv directory argument required}"

  pinned_sha="$(grep -v '^[[:space:]]*#' "$pin_file" | grep -v '^[[:space:]]*$' | head -n1)"
  if [ -z "$pinned_sha" ]; then
    echo "install_milpa: could not read a pinned commit SHA from $pin_file" >&2
    return 1
  fi

  marker="$venv_dir/.milpa-pin-sha"
  if [ -x "$venv_dir/bin/milpa" ] && [ -f "$marker" ] && [ "$(cat "$marker")" = "$pinned_sha" ]; then
    echo "install_milpa: $venv_dir already has milpa built from $pinned_sha -- skipping rebuild" >&2
  else
    echo "install_milpa: building milpa from pinned commit $pinned_sha into $venv_dir" >&2
    rm -rf "$venv_dir"
    python3 -m venv "$venv_dir"
    "$venv_dir/bin/pip" install --quiet \
      "git+https://github.com/coreyleavitt/milpa.git@${pinned_sha}#subdirectory=impls/python"
    echo "$pinned_sha" > "$marker"
  fi

  MILPA_BIN="$venv_dir/bin/milpa"
  "$MILPA_BIN" --version >&2
}
