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
# RFC-005 slice 12 (macOS-arm64) extends this table with a `darwin-arm64`
# row and, per its own DoD's real-macOS portability audit, fixes two
# GNU-coreutils-isms this script's slice-11 body carried that macOS's BSD
# userland does not ship: `sha256sum` (macOS has `shasum -a 256` instead,
# resolved via a small `sha256()` shell function below) and `ln -sfn`
# (GNU-only `-n` flag spelling; replaced with a portable `rm -f` + plain
# `ln -s`). Neither changes behavior on Linux -- `sha256sum` is still
# preferred first, and the symlink's end state is identical either way.
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
# RFC-005 slice 13 (Windows/MinGW-gcc) addition: --expect-os <case-glob>
# is an OPTIONAL second identity canary, asserted against the RAW `uname
# -s` value (before this script's own windows-normalization step below
# folds it down to a stable platform-key). It exists because arch alone
# stops being sufficient once a THIRD `uname -m` value enters the matrix:
# Git Bash on a 64-bit Windows runner reports `x86_64` for `uname -m` --
# the identical string a plain Linux amd64 host reports for the SAME
# physical architecture -- so `--expect-arch x86_64` alone cannot tell a
# genuine Windows/Git-Bash runner apart from an ordinary Linux dev
# workstation (unlike the aarch64-vs-arm64 Linux/Darwin split, which is
# already a distinct string per OS). `--expect-os` closes that gap
# directly: pass a bash `case`-pattern (alternation via `|` is supported
# in one clause, e.g. `'MINGW64_NT*|MSYS*'`) and this script rejects the
# run before installing anything unless the raw `uname -s` matches it.
# Every existing leg (linux/arm64, macOS-arm64) omits this flag and is
# completely unaffected -- it is opt-in per invocation, not a new
# universal check threaded into legs that never needed it.
#
# --with-mingw (RFC-005 slice 13): an OPTIONAL boolean flag. When set,
# after the Nim install below completes, this script ALSO installs the
# pinned MinGW-w64 toolchain from scripts/lib/mingw-pin.txt (that file's
# own header has the full source/build/pin-format writeup) onto a second,
# dedicated on-disk path (see the PATH-mechanism paragraph below), and
# asserts the installed `gcc --version` output contains the EXACT version
# string the pin file records -- not merely that some gcc-named binary
# landed on PATH (RFC-005 Part B's canary rule, and this slice's own DoD:
# "toolchain canary confirming the PINNED gcc"). This is the RFC's own
# explicit demand that "the runner-bundled MinGW drifts -- pin story
# explicit": GitHub's windows-* runner images do ship a MinGW toolchain
# out of the box, but its exact version is whatever the image's own
# maintainers most recently bundled, an unpinned dependency this
# project's whole pin-everything posture exists to close (RFC-005 slice
# 7 caught this exact risk class live, when the pinned Nim container
# image's own mutable TAG moved out from under an in-progress session).
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
# MinGW install convention (RFC-005 slice 13, `--with-mingw` only):
# mirrors the Nim convention above but under its OWN root,
# $HOME/.sello-nim-mingw/ (not a subdirectory of $HOME/.sello-nim/) --
# deliberately separate namespaces for two independently-pinned toolchains
# rather than one root serving both, so neither install's marker/symlink
# convention has to know the other exists. Installs to
# $HOME/.sello-nim-mingw/<gcc-version>-<platform-key>/mingw64/ (the
# archive's own top-level directory name, kept as-is rather than
# flattened, since nothing else about this convention depends on the
# exact subdirectory name), then updates a stable symlink
# $HOME/.sello-nim-mingw/current -> that directory's `mingw64` subtree.
# scripts/test.sh checks for $HOME/.sello-nim-mingw/current/bin/gcc.exe
# (or extensionless `gcc`, for local non-Windows testing symmetry) at its
# own top and prepends that `bin/` to PATH when present, the same
# on-disk-convention pattern (not $GITHUB_PATH) the Nim install already
# established, for the identical reasons (works whether ci-nim-setup.sh
# ran as an earlier step or chained via `&&`, no GitHub-Actions-specific
# plumbing). Idempotent the same way: a marker file records the exact
# (platform-key, url, sha256) tuple; a matching marker skips the
# download+extract.
#
# Usage: scripts/ci-nim-setup.sh --expect-arch <uname-m-value> [--expect-os <case-glob>] [--with-mingw]
#   e.g. scripts/ci-nim-setup.sh --expect-arch aarch64   # linux/arm64
#        scripts/ci-nim-setup.sh --expect-arch x86_64 --expect-os 'MINGW64_NT*|MSYS*' --with-mingw   # windows/MinGW-gcc
set -euo pipefail
cd "$(dirname "$0")/.."

# Portable SHA-256 (RFC-005 slice 12 portability finding): `sha256sum` is a
# GNU-coreutils-ism -- absent by default on macOS (BSD userland ships
# `shasum -a 256` instead, a bundled Perl script, and has no `sha256sum`
# binary on PATH). Resolved once, here, rather than at each call site, so
# the checksum-verification logic below stays a single `sha256 <file>`
# call regardless of which tool the host actually has.
if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  echo "ci-nim-setup: no SHA-256 tool found on PATH (need 'sha256sum' or 'shasum') -- cannot verify download integrity, refusing to proceed." >&2
  exit 1
fi

# --- argument parsing: --expect-arch is mandatory; --expect-os and
# --with-mingw are optional (RFC-005 slice 13). Order-independent, small
# hand-rolled loop -- same style as scripts/test.sh's own leading-flag
# parser, not a general getopts parser, since this script has exactly
# three named flags. ---
expect_arch=""
expect_os=""
with_mingw=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --expect-arch)
      if [[ -z "${2:-}" ]]; then
        echo "scripts/ci-nim-setup.sh: --expect-arch requires a value, e.g. --expect-arch aarch64" >&2
        exit 2
      fi
      expect_arch="$2"
      shift 2
      ;;
    --expect-os)
      if [[ -z "${2:-}" ]]; then
        echo "scripts/ci-nim-setup.sh: --expect-os requires a case-pattern value, e.g. --expect-os 'MINGW64_NT*|MSYS*'" >&2
        exit 2
      fi
      expect_os="$2"
      shift 2
      ;;
    --with-mingw)
      with_mingw=1
      shift
      ;;
    *)
      echo "scripts/ci-nim-setup.sh: unrecognized argument '$1'" >&2
      exit 2
      ;;
  esac
done
if [[ -z "$expect_arch" ]]; then
  echo "scripts/ci-nim-setup.sh: usage: scripts/ci-nim-setup.sh --expect-arch <name> [--expect-os <case-glob>] [--with-mingw]" >&2
  echo "  e.g. scripts/ci-nim-setup.sh --expect-arch aarch64" >&2
  echo "  e.g. scripts/ci-nim-setup.sh --expect-arch x86_64 --expect-os 'MINGW64_NT*|MSYS*' --with-mingw" >&2
  exit 2
fi

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

# --- OS-identity canary (RFC-005 slice 13, --expect-os only): a SECOND,
# independent identity check against the RAW `uname -s` string, needed
# because Git Bash on 64-bit Windows reports `x86_64` for `uname -m` --
# the same string a plain Linux amd64 host reports for the identical
# `uname -m` value -- so the arch canary alone cannot distinguish a
# genuine Windows/Git-Bash runner from an ordinary Linux dev workstation
# the way it already distinguishes aarch64 (Linux) from arm64 (Darwin).
# Skipped entirely when --expect-os is not passed (every pre-slice-13 leg
# keeps its exact prior behavior, byte-for-byte). ---
actual_os_raw="$(uname -s)"
if [[ -n "$expect_os" ]]; then
  echo "OS canary: expected uname -s to match '$expect_os', observed '$actual_os_raw'"
  case "$actual_os_raw" in
    $expect_os)
      echo "OS canary: PASS -- runner OS identity confirmed against pattern '$expect_os'."
      ;;
    *)
      echo "OS canary: FAIL -- this runner's uname -s ('$actual_os_raw') does not match '$expect_os'. Refusing to install a toolchain for the wrong OS (the classic silent-wrong-leg matrix failure, one level up from architecture)." >&2
      exit 1
      ;;
  esac
fi

# Windows OS-name normalization (RFC-005 slice 13): Git Bash's `uname -s`
# embeds the Windows kernel build number (e.g. `MINGW64_NT-10.0-20348`),
# which would otherwise force a new scripts/lib/nim-pin.txt row every time
# GitHub bumps the runner OS build, even though nothing about the pinned
# NIM BINARY changed -- that per-build variability is exactly what the
# OS-identity canary above already proves directly against the raw
# string, so the pin-table lookup key below only needs a STABLE token.
# MSYS*/CYGWIN* are folded the same way for the same reason, even though
# this project only wires and exercises MINGW64_NT* today (Git-for-
# Windows' own default `shell: bash` environment). Linux/Darwin are
# unchanged from every prior slice.
case "$actual_os_raw" in
  MINGW*|MSYS*|CYGWIN*) os_lower="windows" ;;
  *) os_lower="$(printf '%s' "$actual_os_raw" | tr '[:upper:]' '[:lower:]')" ;;
esac
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

  actual_sha="$(sha256 "$tmp_tarball")"
  if [[ "$actual_sha" != "$expected_sha" ]]; then
    echo "ci-nim-setup: CHECKSUM MISMATCH for $asset_name -- expected $expected_sha, got $actual_sha. Refusing to install an unverified toolchain (treat as a supply-chain event, not a flake)." >&2
    exit 1
  fi
  echo "ci-nim-setup: checksum verified ($actual_sha)."

  extract_tmp="$(mktemp -d)"
  # Extraction branches on the asset's own extension (RFC-005 slice 13):
  # every row before windows-x86_64 is a `.tar.xz`; that row alone is a
  # `.zip` (Nim's nightlies publish no `.tar.xz` for Windows at all --
  # verified against the real release listing, not assumed). Prefer
  # `unzip` when present; fall back to `tar -xf`, which extracts `.zip`
  # natively on Windows' own in-box bsdtar (confirmed: Windows 10 1803+
  # ships a real bsdtar as `tar.exe`, not a GNU-tar shim) without
  # requiring a separate `unzip` install on a fresh runner.
  case "$asset_name" in
    *.zip)
      if command -v unzip >/dev/null 2>&1; then
        unzip -q "$tmp_tarball" -d "$extract_tmp"
      else
        tar -xf "$tmp_tarball" -C "$extract_tmp"
      fi
      ;;
    *)
      tar -xJf "$tmp_tarball" -C "$extract_tmp"
      ;;
  esac
  # The archive's own top-level directory is "nim-<version>" (no
  # platform suffix, in both the tar.xz and zip registers -- verified
  # directly against the real windows zip's file listing) -- move its
  # contents into our platform-keyed install_dir so a future second
  # platform on the same host (unlikely in CI, plausible on a local
  # multi-arch dev box) cannot collide.
  mkdir -p "$install_dir"
  mv "$extract_tmp"/nim-*/* "$install_dir"/
  rm -rf "$extract_tmp"
  rm -f "$tmp_tarball"
  trap - EXIT

  echo "$expected_marker" > "$marker"
fi

# rm-then-ln (RFC-005 slice 12 portability finding), not `ln -sfn`: GNU
# ln's `-n`/`--no-dereference` flag has no confirmed-portable BSD ln
# equivalent (BSD ln's own "don't follow an existing symlink" flag is
# spelled `-h`, not `-n` -- a genuine, not merely cosmetic, flag-spelling
# divergence between the two `ln` implementations). Removing the old
# symlink first and creating a plain new one sidesteps the whole question
# and works identically under GNU coreutils, BSD/macOS, and Git Bash.
rm -f "$install_root/current"
ln -s "$install_dir" "$install_root/current"

echo "ci-nim-setup: resolved toolchain version (proof the extracted binary actually runs, not just that a checksum matched):"
"$install_root/current/bin/nim" --version

echo "ci-nim-setup: OK -- $install_root/current -> $install_dir"

# --- MinGW-w64 install (RFC-005 slice 13, --with-mingw only). Own root,
# own marker/symlink convention, own pin file -- see this script's own
# header and scripts/lib/mingw-pin.txt's header for the full rationale. ---
if [[ "$with_mingw" -eq 1 ]]; then
  mingw_pin_file="$(dirname "$0")/lib/mingw-pin.txt"
  mingw_pin_line="$(grep -v '^[[:space:]]*#' "$mingw_pin_file" | grep -v '^[[:space:]]*$' | awk -v k="$platform_key" '$1 == k { print; found=1 } END { if (!found) exit 1 }')" || {
    echo "ci-nim-setup: --with-mingw given but no pin row for platform-key '$platform_key' in $mingw_pin_file -- this platform's MinGW install is not wired yet." >&2
    exit 1
  }
  read -r _ mingw_url mingw_expected_sha mingw_expected_version <<<"$mingw_pin_line"
  echo "ci-nim-setup: (mingw) platform-key '$platform_key' -> $mingw_url (gcc $mingw_expected_version)"

  mingw_install_root="$HOME/.sello-nim-mingw"
  mingw_asset_name="${mingw_url##*/}"
  mingw_install_dir="$mingw_install_root/${mingw_expected_version}-${platform_key}"
  mingw_marker="$mingw_install_dir/.mingw-pin-marker"
  mingw_expected_marker="$platform_key $mingw_url $mingw_expected_sha"

  mingw_gcc_path=""
  for candidate in "$mingw_install_dir/mingw64/bin/gcc.exe" "$mingw_install_dir/mingw64/bin/gcc"; do
    if [[ -x "$candidate" ]]; then
      mingw_gcc_path="$candidate"
      break
    fi
  done

  if [[ -n "$mingw_gcc_path" && -f "$mingw_marker" && "$(cat "$mingw_marker")" == "$mingw_expected_marker" ]]; then
    echo "ci-nim-setup: (mingw) $mingw_install_dir already matches the pinned (platform, url, checksum) tuple -- skipping download."
  else
    echo "ci-nim-setup: (mingw) installing MinGW-w64 gcc $mingw_expected_version for '$platform_key' into $mingw_install_dir"
    rm -rf "$mingw_install_dir"
    mkdir -p "$mingw_install_root"

    mingw_tmp_zip="$(mktemp)"
    trap 'rm -f "$mingw_tmp_zip"' EXIT
    echo "ci-nim-setup: (mingw) downloading $mingw_url"
    curl -sSfL -o "$mingw_tmp_zip" "$mingw_url"

    mingw_actual_sha="$(sha256 "$mingw_tmp_zip")"
    if [[ "$mingw_actual_sha" != "$mingw_expected_sha" ]]; then
      echo "ci-nim-setup: (mingw) CHECKSUM MISMATCH for $mingw_asset_name -- expected $mingw_expected_sha, got $mingw_actual_sha. Refusing to install an unverified toolchain (treat as a supply-chain event, not a flake)." >&2
      exit 1
    fi
    echo "ci-nim-setup: (mingw) checksum verified ($mingw_actual_sha)."

    mkdir -p "$mingw_install_dir"
    if command -v unzip >/dev/null 2>&1; then
      unzip -q "$mingw_tmp_zip" -d "$mingw_install_dir"
    else
      tar -xf "$mingw_tmp_zip" -C "$mingw_install_dir"
    fi
    rm -f "$mingw_tmp_zip"
    trap - EXIT

    for candidate in "$mingw_install_dir/mingw64/bin/gcc.exe" "$mingw_install_dir/mingw64/bin/gcc"; do
      if [[ -x "$candidate" ]]; then
        mingw_gcc_path="$candidate"
        break
      fi
    done
    if [[ -z "$mingw_gcc_path" ]]; then
      echo "ci-nim-setup: (mingw) FAIL -- extracted $mingw_install_dir but found no mingw64/bin/gcc(.exe) inside it. Archive layout drifted from this pin's own recorded layout -- investigate before trusting this install." >&2
      exit 1
    fi

    echo "$mingw_expected_marker" > "$mingw_marker"
  fi

  rm -f "$mingw_install_root/current"
  ln -s "$(dirname "$(dirname "$mingw_gcc_path")")" "$mingw_install_root/current"

  # Toolchain-version canary (this slice's own DoD: "assert the gcc
  # version string matches the pin's recorded version, which also
  # satisfies 'pin story explicit'"): proves the PINNED gcc is what
  # actually landed, not merely a gcc-named binary from wherever `unzip`
  # happened to extract one -- the direct, mingw-specific analog of
  # scripts/lib/toolchain-canary.sh's own "assert from the tool's own
  # output, not just that a flag was accepted" posture. Invoked via the
  # exact resolved $mingw_gcc_path, not a `gcc*` glob -- mingw64/bin/ also
  # ships gcc-ar.exe/gcc-nm.exe/gcc-ranlib.exe, which a bare glob would
  # ambiguously multi-match.
  mingw_version_output="$("$mingw_gcc_path" --version 2>&1 | head -n1 || true)"
  echo "ci-nim-setup: (mingw) resolved toolchain version (observed 'gcc --version', first line): ${mingw_version_output:-<no output>}"
  case "$mingw_version_output" in
    *"$mingw_expected_version"*)
      echo "ci-nim-setup: (mingw) version canary: PASS -- installed gcc reports the pinned version '$mingw_expected_version'."
      ;;
    *)
      echo "ci-nim-setup: (mingw) version canary: FAIL -- expected 'gcc --version' to contain the pinned version '$mingw_expected_version', but observed: ${mingw_version_output:-<no output>}" >&2
      exit 1
      ;;
  esac

  echo "ci-nim-setup: OK -- $mingw_install_root/current -> $(readlink "$mingw_install_root/current")"
fi
