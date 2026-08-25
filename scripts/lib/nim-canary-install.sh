#!/usr/bin/env bash
# scripts/lib/nim-canary-install.sh -- RFC-005 slice 26 (A6, toolchain
# canary). Installs a Nim toolchain from a nim-lang/nightlies MOVING
# release tag (`latest-devel` / `latest-version-2-4` today) onto a bare
# `ubuntu-latest` runner, for .github/workflows/toolchain-canary.yml's
# `nim-devel`/`nim-latest-stable` legs.
#
# Deliberately UNPINNED -- no checksum verification, unlike
# scripts/ci-nim-setup.sh / scripts/lib/nim-pin.txt (this project's
# standing pin-everything posture, everywhere else). This is not an
# oversight: A6's whole reason to exist is watching these two targets
# DRIFT out from under the project's own pinned Nim -- pinning a checksum
# here would mean re-pinning it every single day this canary usefully
# fires, which defeats the leg's own purpose (compare to
# scripts/ci-nim-setup.sh, whose whole point IS a checksum pin, for every
# OTHER leg that wants stability rather than drift-watching). This
# divergence from the pin-everything posture is deliberate and recorded
# here, not silently inconsistent -- see docs/rfc-005-validation-infra.md's
# A6 text ("no checksum pin on these legs") for the RFC's own framing.
#
# `latest-devel` / `latest-version-2-4`: nim-lang/nightlies' own ROLLING
# tags (re-published in place as new builds land, unlike the DATED tags
# scripts/lib/nim-pin.txt pins by exact commit) -- `latest-devel` tracks
# the `devel` branch's newest build; `latest-version-2-4` tracks the
# newest build of the newest STABLE release series nightlies currently
# publishes (2.4 as of this slice, ahead of this project's own pinned
# 2.2.10 -- verified via `gh api repos/nim-lang/nightlies/releases` before
# choosing this tag: nightlies also republishes `latest-version-2-2`,
# tracking the SAME series this project pins, which would not be a useful
# "latest STABLE" canary target since it's the series already pinned
# elsewhere). Every asset under a rolling tag has a FIXED, non-versioned
# filename (`linux_x64.tar.xz`, confirmed via `gh api
# .../releases/tags/latest-devel` before writing this script) -- unlike
# the dated tags' own `nim-<version>-<platform>.tar.xz` naming.
#
# Install path: $HOME/.sello-nim-canary/<label>/ (a namespace distinct
# from both scripts/ci-nim-setup.sh's $HOME/.sello-nim/ -- the pinned
# install -- and $HOME/.sello-nim-mingw/, so none of the three
# conventions can collide), with a stable $HOME/.sello-nim-canary/current
# symlink the caller is expected to prepend to PATH itself (this script
# does not touch PATH or $GITHUB_PATH -- the calling workflow step does
# that explicitly, matching every prior RFC-005 toolchain-install script's
# "on-disk convention, not $GITHUB_PATH" posture, documented at length in
# scripts/ci-nim-setup.sh's own header).
#
# Usage: scripts/lib/nim-canary-install.sh <release-tag> <label>
#   e.g. scripts/lib/nim-canary-install.sh latest-devel        nim-devel
#        scripts/lib/nim-canary-install.sh latest-version-2-4  nim-latest-stable
set -euo pipefail

tag="${1:?usage: nim-canary-install.sh <release-tag> <label>}"
label="${2:?usage: nim-canary-install.sh <release-tag> <label>}"

install_root="$HOME/.sello-nim-canary"
install_dir="$install_root/$label"

echo "nim-canary-install: installing Nim from UNPINNED nim-lang/nightlies tag '$tag' (label=$label) -- see this script's own header for why no checksum is pinned here."
rm -rf "$install_dir"
mkdir -p "$install_dir"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
url="https://github.com/nim-lang/nightlies/releases/download/${tag}/linux_x64.tar.xz"
echo "nim-canary-install: downloading $url"
curl -sSfL -o "$tmp" "$url"
tar -xJf "$tmp" -C "$install_dir" --strip-components=1
rm -f "$tmp"
trap - EXIT

rm -f "$install_root/current"
ln -s "$install_dir" "$install_root/current"

echo "nim-canary-install: resolved toolchain version (proof the extracted binary actually runs, not just that the download succeeded):"
"$install_root/current/bin/nim" --version

echo "nim-canary-install: OK -- $install_root/current -> $install_dir (label=$label, tag=$tag)"
