#!/usr/bin/env bash
# Run sello's unit test suite (pure-Nim backend) inside the base Nim
# toolchain image. Replaces the old `nimble test` task now that milpa is
# the resolver: nimcrypto is pinned in milpa.lock and resolved into
# _deps/nimcrypto rather than vendored or nimble-fetched.
#
# Usage:  scripts/test.sh              # plain pure-Nim backend
#         scripts/test.sh -d:release   # extra defines forwarded to each nim c
#
# Mounts: the project + the milpa CAS (at both the canonical path and its
# host-absolute path, so milpa's absolute dep symlinks under _deps/
# resolve in-container -- same pattern as proptest's scripts/runtest.sh).
#
# Prerequisite: `milpa fetch` has been run on the host at least once (populates
# _deps/ and nim.cfg from milpa.lock). Not invoked automatically here, matching
# proptest's scripts/ convention -- keeps this script network-free and lets
# `--frozen` verification stay an explicit, separate step (`milpa verify`).
#
# Additional prerequisite for the property-based tests (test_properties_*,
# RFC-001 finding 10): proptest is an OPTIONAL milpa dep (milpa.kdl:
# `optional=#true`, auto-gated behind a same-named "proptest" feature flag,
# RFC #23 §3.2) so consumers of sello never transitively fetch
# proptest+nim-z3+softlink just by depending on sello. A plain `milpa fetch`
# prunes it (verified empirically: nim.cfg gains no proptest/z3/softlink
# --path lines and _deps/ contains only nimcrypto). To enable it for local
# dev, run once: `milpa fetch --features proptest` -- this resolves and
# fetches proptest AND its own transitive deps (z3, softlink; proptest's own
# manifest declares z3 unconditionally), and nim.cfg gains their --path
# lines. Note this also rewrites the *committed* milpa.lock's proptest/z3/
# softlink entries in your working tree; that's expected milpa behavior
# (activation is recomputed from the manifest + requested features on every
# fetch, not preserved from a prior lock state) -- see the B4a summary in
# docs/rfc-001-signing.handoff.md. `import proptest` compiles fine in this
# script's base image with no z3 shared library installed: the only module
# that imports `z3` is `proptest/symex`, which the top-level `proptest`
# module never imports (confirmed empirically).
set -euo pipefail
cd "$(dirname "$0")/.."

extra_defines=("$@")

# unit_test_files ("which unit test files make up the suite") is defined in
# scripts/lib/unit-test-files.sh and sourced here, not retyped -- the same
# file is sourced by scripts/test-libsodium.sh, so the two matrices read one
# array instead of two hand-maintained copies that could silently drift
# apart (round-2 finding 25; the old comment here claimed "cannot drift"
# while actually being two independently-typed-out arrays -- this sourcing
# is what makes that claim true).
source "$(dirname "$0")/lib/unit-test-files.sh"

img=ghcr.io/coreyleavitt/nim:2.2.10

cmd="set -e"
for f in "${unit_test_files[@]}"; do
  cmd+=$'\n'"echo '=== $f ==='"
  cmd+=$'\n'"nim c ${extra_defines[*]:-} -r $f"
done

podman run --rm \
  -v "$PWD:/workspace" \
  -v "$HOME/.cache/milpa:/.cache/milpa" \
  -v "$HOME/.cache/milpa:$HOME/.cache/milpa" \
  -w /workspace \
  "$img" \
  bash -c "$cmd"
