#!/usr/bin/env bash
# scripts/ci-nim-setup.sh -- RFC-005 slice 11: installs a pinned Nim
# toolchain directly onto a hosted runner that has no digest-pinnable
# container image to run inside. Every other required job runs its
# `scripts/` invocation inside the pinned `ghcr.io/coreyleavitt/nim:2.2.10`
# container (RFC-005 Part B's build-path invariant); slice 7's manifest
# query found that image has NO arm64 variant (linux/amd64 and
# windows/amd64 only), and growing one is out of scope for this repo (the
# image's own build source lives in a separate, undocumented-here repo --
# slice 7's own title parenthetical). The recorded decision (slice 7's
# handoff entry) is direct install instead, mirroring the ALREADY-PLANNED
# macOS-arm64 leg's own pin story (no container exists on macOS runners at
# all) -- so this script is written arch/OS-parametric from the start
# (scripts/lib/nim-pin.txt's platform-key lookup) rather than hardcoding
# linux/arm64, even though this slice only wires and exercises one row.
#
# Source + pin story: scripts/lib/nim-pin.txt's own header has the full
# provenance writeup (nim-lang/nightlies, the official Nim project's own
# release repo; the row this slice uses is built from the EXACT same
# source commit as the `2.2.10` container image tag, verified against the
# v2.2.10 git tag directly, not merely "a nearby nightly"). Every download
# is SHA-256 verified against that pin before extraction -- a mismatch is
# treated as a supply-chain event (loud failure, no retry), not a
# transient flake.
#
# Why a prebuilt binary, not choosenim or a from-source build: the task's
# own investigation named three realistic options -- (a) nim-lang/
# nightlies prebuilt tarballs (arm64 IS published, verified above), (b)
# choosenim (builds from source on unsupported arches -- slow, and still
# needs its own pin story on top), (c) a direct `build_all.sh` source
# build from the v2.2.10 tag (~5-15 minutes, would need actions/cache to
# stay inside budget). (a) needs no build step, no C toolchain
# bootstrapping beyond what the runner already ships, and downloads in
# low single-digit seconds (a statically-linked ~16 MiB .tar.xz) --
# strictly cheaper and simpler than either alternative, with an equally
# concrete pin (release tag + asset name + checksum, not merely a version
# string). NO actions/cache is used for this install: a source build's
# ~5-15 minute cost is exactly what RFC-005 Part B's wall-clock-budget
# paragraph had in mind when it authorized caching the toolchain "if
# building from source" -- a single-digit-second prebuilt-binary fetch
# doesn't meet that bar, and skipping the cache also sidesteps RFC-005
# Part B's "no cross-branch cache trust" scoping (today: "the Actions
# cache is used only for the fuzz working corpus, keyed so non-main
# branches cannot seed main-consumed entries") entirely rather than
# opening a second authorized cache scope for a saving this small.
#
# Platform-identity canary (RFC-005 Part B's red-then-green rule, "every
# matrix leg carries a platform-identity canary... the classic matrix
# failure is a leg silently running the wrong thing: host arch instead of
# target"): --expect-arch <name> is REQUIRED and is asserted against
# `uname -m` BEFORE any download happens -- proof the runner genuinely is
# the architecture the job's check name claims, not merely that the job
# was scheduled with an arm64-sounding runs-on: label (GitHub Actions'
# hosted arm64 runner rollout is recent enough that a mislabeled/reverted
# runner image is a real, not hypothetical, failure mode to guard). This
# composes with, and does not replace, scripts/lib/toolchain-canary.sh's
# existing compiler-identity canary -- scripts/test.sh already routes its
# first file's compile through that check unconditionally (gcc included),
# so a job that runs this script followed by scripts/test.sh gets BOTH
# the runner-arch canary (this script) and the C-compiler-identity canary
# (scripts/test.sh's own, unchanged) for the combined proof RFC-005 Part B
# calls for -- no new gcc-specific logic needed here.
#
# Install convention (deliberately NOT $GITHUB_PATH): installs to
# $HOME/.sello-nim/nim-<version>-<platform-key>/, then updates a stable
# symlink $HOME/.sello-nim/current -> that directory. scripts/test.sh
# checks for $HOME/.sello-nim/current/bin/nim at its own top and prepends
# it to PATH when present (a few-line, unconditional, harmless-elsewhere
# addition -- see that script's own header) -- this on-disk convention
# works identically whether scripts/test.sh runs as a separate later
# workflow step (where a $GITHUB_PATH write would only take effect on the
# NEXT step, GitHub Actions' own documented behavior) or chained via `&&`
# on the SAME command line the way scripts/lib/gates.txt's entries and
# unit-linux-amd64-gcc's own `ci-setup.sh && ... test.sh` job already do
# (where a subprocess's own `export PATH` would not propagate back to the
# parent shell at all) -- one mechanism, no GitHub-Actions-specific
# plumbing, works locally on a real arm64 host too.
#
# Idempotent: a marker file records the exact (platform-key, release-tag,
# asset-name, sha256) tuple the current `current` symlink target was
# installed from; a matching marker skips the download+extract entirely
# (harmless on CI's always-fresh runners, useful for local/manual
# re-invocation on a real arm64 dev host -- same idiom as
# scripts/lib/milpa-install.sh's own venv marker).
#
# Usage: scripts/ci-nim-setup.sh --expect-arch <uname-m-value>
#   e.g. scripts/ci-nim-setup.sh --expect-arch aarch64   # linux/arm64
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ "${1:-}" != "--expect-arch" || -z "${2:-}" ]]; then
  echo "scripts/ci-nim-setup.sh: usage: scripts/ci-nim-setup.sh --expect-arch <name>" >&2
  echo "  e.g. scripts/ci-nim-setup.sh --expect-arch aarch64" >&2
  exit 2
fi
expect_arch="$2"

# --- platform-identity canary: prove the runner is genuinely the claimed
# architecture BEFORE trusting anything else it reports (RFC-005 Part B's
# matrix-leg canary rule). ---
actual_arch="$(uname -m)"
echo "arch canary: expected uname -m = '$expect_arch', observed '$actual_arch'"
if [[ "$actual_arch" != "$expect_arch" ]]; then
  echo "arch canary: FAIL -- this runner is NOT '$expect_arch'. Refusing to install a toolchain for the wrong architecture (the classic silent-wrong-leg matrix failure)." >&2
  exit 1
fi
echo "arch canary: PASS -- runner architecture confirmed '$expect_arch'."

os_lower="$(uname -s | tr '[:upper:]' '[:lower:]')"
platform_key="${os_lower}-${actual_arch}"

pin_file="$(dirname "$0")/lib/nim-pin.txt"
pin_line="$(grep -v '^[[:space:]]*#' "$pin_file" | grep -v '^[[:space:]]*$' | awk -v k="$platform_key" '$1 == k { print; found=1 } END { if (!found) exit 1 }')" || {
  echo "ci-nim-setup: no pin row for platform-key '$platform_key' in $pin_file -- this platform is not wired yet." >&2
  exit 1
}
read -r _ release_tag asset_name expected_sha <<<"$pin_line"
echo "ci-nim-setup: platform-key '$platform_key' -> release '$release_tag', asset '$asset_name'"

version="$(sed -E 's/^nim-([0-9.]+)-.*/\1/' <<<"$asset_name")"
install_root="$HOME/.sello-nim"
install_dir="$install_root/nim-${version}-${platform_key}"
marker="$install_dir/.nim-pin-marker"
expected_marker="$platform_key $release_tag $asset_name $expected_sha"

if [[ -x "$install_dir/bin/nim" && -f "$marker" && "$(cat "$marker")" == "$expected_marker" ]]; then
  echo "ci-nim-setup: $install_dir already matches the pinned (platform, release, asset, checksum) tuple -- skipping download."
else
  echo "ci-nim-setup: installing Nim $version for '$platform_key' into $install_dir"
  rm -rf "$install_dir"
  mkdir -p "$install_root"

  tmp_tarball="$(mktemp)"
  trap 'rm -f "$tmp_tarball"' EXIT
  url="https://github.com/nim-lang/nightlies/releases/download/${release_tag}/${asset_name}"
  echo "ci-nim-setup: downloading $url"
  curl -sSfL -o "$tmp_tarball" "$url"

  actual_sha="$(sha256sum "$tmp_tarball" | awk '{print $1}')"
  if [[ "$actual_sha" != "$expected_sha" ]]; then
    echo "ci-nim-setup: CHECKSUM MISMATCH for $asset_name -- expected $expected_sha, got $actual_sha. Refusing to install an unverified toolchain (treat as a supply-chain event, not a flake)." >&2
    exit 1
  fi
  echo "ci-nim-setup: checksum verified ($actual_sha)."

  extract_tmp="$(mktemp -d)"
  tar -xJf "$tmp_tarball" -C "$extract_tmp"
  # The tarball's own top-level directory is "nim-<version>" (no
  # platform suffix) -- move its contents into our platform-keyed
  # install_dir so a future second platform on the same host (unlikely in
  # CI, plausible on a local multi-arch dev box) cannot collide.
  mkdir -p "$install_dir"
  mv "$extract_tmp"/nim-*/* "$install_dir"/
  rm -rf "$extract_tmp"
  rm -f "$tmp_tarball"
  trap - EXIT

  echo "$expected_marker" > "$marker"
fi

ln -sfn "$install_dir" "$install_root/current"

echo "ci-nim-setup: resolved toolchain version (proof the extracted binary actually runs, not just that a checksum matched):"
"$install_root/current/bin/nim" --version

echo "ci-nim-setup: OK -- $install_root/current -> $install_dir"
