#!/usr/bin/env bash
# scripts/policy-lint.sh — RFC-005 slice 4: the "policy-lint" CI check.
# actionlint over every .github/workflows/*.yml, PLUS four assertions of
# our own over the same files (RFC-005 Part B: "actionlint plus
# assertions that every uses: is SHA-pinned, no continue-on-error on
# required jobs, a permissions block is present, and container: digests
# match the committed pin file -- workflow content drift as a red check,
# not a review hope"):
#   1. every `uses:` action reference is pinned by a full 40-character
#      commit SHA, not a mutable tag/branch (RFC-005 Part B's "CI supply
#      chain": "all third-party actions pinned by commit SHA").
#   2. no `continue-on-error: true` anywhere (every job in
#      merge-gate.yml is a required check; a `continue-on-error: true` on
#      any of them would make its own required-status-check report
#      success regardless of the step's real outcome).
#   3. every workflow file carries a top-level `permissions:` block
#      (RFC-005 Part B: "workflow-level least-privilege permissions").
#   4. every `container: image: ...@sha256:...` value appears verbatim in
#      the committed scripts/lib/image-pins.txt (RFC-005 Part B: "the
#      pin file records the pair... CI fails if the Containerfile hash
#      changed without a digest bump" -- this check is the workflow-side
#      half: the workflow's own image references must match the pin
#      file, whichever direction drifted).
#
# actionlint pinning strategy, decided (RFC-005 slice 4): actionlint is
# NOT preinstalled on GitHub-hosted ubuntu-latest runners (unlike
# shellcheck), and this check must be host-runnable too (the gates.txt
# manifest's plain-invocation convention, same as gates-manifest-sync) --
# so this script downloads the actionlint release binary itself, pinned
# by version + a SHA-256 checksum recorded below (verified against the
# upstream release's own published checksums.txt before being pinned
# here, and independently re-verified via a fresh download before this
# script was committed), rather than depending on a GitHub Marketplace
# action (which would need its own SHA pin and adds a supply-chain hop
# for a tool this script can just fetch-and-verify directly, mirroring
# scripts/lib/milpa-install.sh's own "build/fetch a pinned tool inside
# the script" precedent). Caches the verified binary under
# build/policy-lint/ (gitignored) so a repeat run/host doesn't
# re-download every time; CI's container is ephemeral per job, so it
# always does the one-time fetch+verify, same as a fresh clone would.
#
# Supported host arch: linux/amd64 only (uname -s/-m checked below,
# matching this repo's existing "the linux set only" scope for
# merge-gate.sh/gates.txt-driven checks -- widen when a non-amd64 gate
# lands).
#
# Container vs. plain runner: like gates-manifest-sync and ruleset-sync,
# this needs no pinned Nim toolchain -- it lints/greps committed YAML
# text, so it runs on a plain `ubuntu-latest` runner (network access to
# download actionlint is its only real dependency, same category as
# scripts/ci-property.sh's milpa fetch). Still exactly one scripts/
# invocation.
#
# Usage:  scripts/policy-lint.sh
set -euo pipefail
cd "$(dirname "$0")/.."

ACTIONLINT_VERSION="1.7.12"
ACTIONLINT_SHA256_LINUX_AMD64="8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"

os="$(uname -s)"
arch="$(uname -m)"
if [[ "$os" != "Linux" || "$arch" != "x86_64" ]]; then
  echo "policy-lint: unsupported host ($os/$arch) -- this script's actionlint download is pinned to linux/amd64 only. Widen when a non-amd64 gate lands." >&2
  exit 1
fi

cache_dir="build/policy-lint"
bin_path="$cache_dir/actionlint-$ACTIONLINT_VERSION"

if [[ ! -x "$bin_path" ]]; then
  mkdir -p "$cache_dir"
  tmp_tarball="$(mktemp)"
  trap 'rm -f "$tmp_tarball"' EXIT
  url="https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz"
  echo "policy-lint: downloading actionlint v$ACTIONLINT_VERSION..."
  curl -sfL -o "$tmp_tarball" "$url"
  actual_sha="$(sha256sum "$tmp_tarball" | awk '{print $1}')"
  if [[ "$actual_sha" != "$ACTIONLINT_SHA256_LINUX_AMD64" ]]; then
    echo "policy-lint: CHECKSUM MISMATCH for actionlint v$ACTIONLINT_VERSION linux_amd64 -- expected $ACTIONLINT_SHA256_LINUX_AMD64, got $actual_sha. Refusing to run an unverified binary." >&2
    exit 1
  fi
  tar -xzf "$tmp_tarball" -C "$cache_dir" actionlint
  mv "$cache_dir/actionlint" "$bin_path"
  chmod +x "$bin_path"
  rm -f "$tmp_tarball"
  trap - EXIT
fi

status=0

echo "policy-lint: running actionlint v$ACTIONLINT_VERSION over .github/workflows/*.yml..."
if ! "$bin_path" .github/workflows/*.yml; then
  status=1
fi

echo ""
echo "policy-lint: running content assertions over .github/workflows/*.yml..."

for wf in .github/workflows/*.yml; do
  echo "-- $wf --"
  wf_status=0

  # 1. every `uses:` pinned by a full 40-character commit SHA.
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    ref="${line#*@}"
    ref="${ref%%[[:space:]]*}"
    if [[ ! "$ref" =~ ^[0-9a-f]{40}$ ]]; then
      echo "policy-lint: FAIL -- $wf: 'uses:' reference not pinned by a full 40-character commit SHA: $line" >&2
      status=1
      wf_status=1
    fi
  done < <(grep -oE 'uses:[[:space:]]*[^[:space:]]+@[^[:space:]]+' "$wf" | sed 's/^uses:[[:space:]]*//')

  # 2. no continue-on-error: true anywhere.
  if grep -qE '^\s*continue-on-error:\s*true\s*$' "$wf"; then
    echo "policy-lint: FAIL -- $wf: contains 'continue-on-error: true' -- every job in this workflow is a required check; a step allowed to fail silently defeats that." >&2
    status=1
    wf_status=1
  fi

  # 3. a top-level permissions: block is present.
  if ! grep -qE '^permissions:\s*$' "$wf"; then
    echo "policy-lint: FAIL -- $wf: no top-level 'permissions:' block found (RFC-005 Part B: workflow-level least-privilege permissions)." >&2
    status=1
    wf_status=1
  fi

  # 4. every container: image digest matches scripts/lib/image-pins.txt.
  while IFS= read -r image; do
    [[ -z "$image" ]] && continue
    if ! grep -qxF "$image" scripts/lib/image-pins.txt; then
      echo "policy-lint: FAIL -- $wf: container image '$image' has no matching line in scripts/lib/image-pins.txt." >&2
      status=1
      wf_status=1
    fi
  done < <(grep -oE 'image:[[:space:]]*[^[:space:]]+@sha256:[0-9a-f]+' "$wf" | sed 's/^image:[[:space:]]*//')

  if [[ "$wf_status" -eq 0 ]]; then
    echo "   OK"
  fi
done

if [[ "$status" -eq 0 ]]; then
  echo ""
  echo "policy-lint: OK -- actionlint clean, all content assertions passed."
fi

exit "$status"
