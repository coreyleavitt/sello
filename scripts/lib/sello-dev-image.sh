#!/usr/bin/env bash
# scripts/lib/sello-dev-image.sh — RFC-005 slice 7 ("Image consolidation"):
# resolves the `sello-dev` image reference for scripts/test-libsodium.sh
# and scripts/bmc.sh, replacing each script's old
# `podman image exists "$img" || podman build ...` build-if-missing logic
# with pull-by-digest of the published `ghcr.io/coreyleavitt/sello-dev`
# image, per the pin recorded in scripts/lib/image-pins.txt.
#
# `resolve_sello_dev_image()` sets the caller's `img` variable and, on the
# pull path, actually performs the pull (so a stale/missing local copy is
# refreshed every invocation rather than silently reused forever — pinned
# by DIGEST, so a repeat pull of an already-present digest is a cheap
# local no-op, not a real network fetch).
#
# Two escape hatches, both opt-in via environment variable (unset by
# default — the default path is always the real pull-by-digest):
#
#   SELLO_DEV_LOCAL_BUILD=1
#     Build the image locally from the committed Containerfile instead of
#     pulling — for a developer actively iterating on the Containerfile
#     itself, before a new (Containerfile-hash, digest) pin has been
#     published (see scripts/policy-lint.sh's sello-dev drift assertion).
#     Sets img=localhost/sello-dev:latest.
#
#   SELLO_DEV_IMAGE_REF=<image-ref>
#     Override the image reference to pull, bypassing the pin file
#     entirely — for pointing at a scratch/mirror registry (e.g. while
#     validating the pull-by-digest mechanism itself against a throwaway
#     registry before a real ghcr credential exists) or at a newer,
#     not-yet-repinned digest during development. Ordinary use needs
#     neither variable: the pin file is the normal source of truth.
#
# Reads the `sello-dev` line from scripts/lib/image-pins.txt (format:
# `sello-dev <containerfile-sha256> <image>@sha256:<digest>`, three
# whitespace-separated fields — see that file's own header comment).
resolve_sello_dev_image() {
  if [[ -n "${SELLO_DEV_LOCAL_BUILD:-}" ]]; then
    img=localhost/sello-dev:latest
    echo "sello-dev-image: SELLO_DEV_LOCAL_BUILD=1 -- building locally from Containerfile (escape hatch, not the published pin)." >&2
    podman build -t "$img" -f Containerfile .
    return 0
  fi

  if [[ -n "${SELLO_DEV_IMAGE_REF:-}" ]]; then
    img="$SELLO_DEV_IMAGE_REF"
    echo "sello-dev-image: SELLO_DEV_IMAGE_REF override -- pulling $img (bypassing scripts/lib/image-pins.txt)." >&2
    podman pull "$img"
    return 0
  fi

  local pin_line ref
  pin_line="$(grep -E '^sello-dev[[:space:]]' scripts/lib/image-pins.txt || true)"
  if [[ -z "$pin_line" ]]; then
    echo "sello-dev-image: no 'sello-dev' line found in scripts/lib/image-pins.txt -- cannot resolve the pull-by-digest reference. Run with SELLO_DEV_LOCAL_BUILD=1 to build locally instead, or repin per that file's own header comment." >&2
    return 1
  fi
  ref="$(awk '{print $3}' <<<"$pin_line")"
  if [[ -z "$ref" ]]; then
    echo "sello-dev-image: malformed 'sello-dev' line in scripts/lib/image-pins.txt: $pin_line" >&2
    return 1
  fi

  img="$ref"
  echo "sello-dev-image: pulling $img (pinned by digest -- scripts/lib/image-pins.txt)." >&2
  if ! podman pull "$img"; then
    echo "sello-dev-image: pull of $img failed. If ghcr.io/coreyleavitt/sello-dev has not been published yet (or you have no pull access), use SELLO_DEV_LOCAL_BUILD=1 to build the image locally from the committed Containerfile instead." >&2
    return 1
  fi
}
