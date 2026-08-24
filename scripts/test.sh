#!/usr/bin/env bash
# Run sello's unit test suite (pure-Nim backend) inside the base Nim
# toolchain image. Replaces the old `nimble test` task now that milpa is
# the resolver. As of RFC-006 (in-house SHA-512 retired the nimcrypto
# dependency), a plain `milpa fetch` resolves ZERO dependencies for the
# core library -- _deps/ is empty unless proptest has been fetched (see
# below).
#
# Usage:  scripts/test.sh              # plain pure-Nim backend, default C compiler (gcc)
#         scripts/test.sh -d:release   # extra defines forwarded to each nim c
#         scripts/test.sh --cc clang   # compile with clang instead of gcc (RFC-005 slice 8)
#         scripts/test.sh --sanitize asan-ubsan   # ASan/UBSan build of the unit suite (RFC-005 slice 9)
#         scripts/test.sh --cc clang -d:release   # leading flags compose with defines
#         scripts/test.sh --sanitize asan-ubsan --cc clang   # leading flags compose with each other too
#
# --cc <name> (RFC-005 slice 8, the clang-backend matrix leg): threads
# `--cc:<name>` into every `nim c` invocation below, so this ONE script
# serves both the unit-linux-amd64-gcc and unit-linux-amd64-clang required
# checks (scripts/lib/gates.txt: `scripts/test.sh` vs `scripts/test.sh
# --cc clang`) -- no forked clang-flavored script, per RFC-005 Part B's
# build-path invariant. Left unset, `nim c` resolves its own default
# backend (gcc on this project's pinned Linux image, unchanged from every
# prior slice).
#
# --sanitize <name> (RFC-005 slice 9, the ASan/UBSan matrix leg): threads
# `--passC`/`--passL` sanitizer flags plus `-d:useMalloc` into every `nim c`
# invocation below. Today's only supported name is `asan-ubsan`
# (`-fsanitize=address,undefined -fno-sanitize-recover=all`, `-g` for
# usable stack traces in the report, and `-fsanitize=address,undefined` on
# the link line too since sanitizer runtimes must be linked in, not just
# compiled in). `-d:useMalloc` is REQUIRED, not cosmetic: Nim's ORC memory
# manager (this project's standing `--mm:orc`, config.nims) otherwise
# services allocations from its own arena allocator, which ASan cannot see
# into -- without `-d:useMalloc` routing Nim's allocations through the
# system `malloc`/`free` ASan instruments, real reports would either be
# missed (ASan has no redzones around ORC's own arena blocks) or spurious
# (ASan misreading ORC-internal bookkeeping as corruption); this is a
# documented Nim+ASan interaction, not a sello-specific guess. `--debugger:
# native` was considered and declined: it changes codegen (embeds full
# native-debugger stack-trace support) for a marginal report-readability
# gain over plain `-g`, and this leg's job is proving the sanitizer fires,
# not producing the prettiest possible crash report. `--sanitize` composes
# with `--cc`: this leg is run on gcc (`scripts/lib/gates.txt`'s
# `unit-linux-amd64-gcc-asan-ubsan` entry passes no `--cc`), a deliberate
# choice over clang -- gcc is this project's default/most-exercised
# backend, and layering ASan onto it keeps this leg's one variable
# (does the sanitizer trip) isolated from slice 8's own variable (does
# clang's codegen differ) rather than compounding both in one leg; nothing
# here prevents `--sanitize asan-ubsan --cc clang` for local investigation.
# ASan's LeakSanitizer component is disabled (`ASAN_OPTIONS=detect_leaks=0`,
# exported only when `--sanitize` is set) since ptrace-based leak detection
# routinely cannot run in an unprivileged CI container (GitHub Actions'
# own container jobs included) -- a documented, scoped call, not a general
# weakening: AddressSanitizer's and UndefinedBehaviorSanitizer's own
# (non-leak) checks are unaffected and stay fully active.
#
# Both flags are parsed by a small leading-argument loop (still not a
# general getopts parser -- this script has exactly two optional flags,
# each taking one value, and every other argument stays an opaque
# pass-through define as before), so either flag, in either order, may
# lead the argument list; the loop stops at the first argument that isn't
# `--cc`/`--sanitize`, and everything from there on is forwarded verbatim
# as a define. The FIRST unit test file's compile is additionally run
# through a canary: scripts/lib/toolchain-canary.sh (compiler identity
# only) when `--sanitize` is unset, or scripts/lib/sanitizer-canary.sh
# (compiler identity AND sanitizer-flag presence, from the same one
# compile -- see that script's own header) when it is set. Both prove
# their claim via Nim's own `--listCmd` output -- not merely that a flag
# was accepted -- see either script's header for why a bare `clang
# --version`-style sanity check alone would not be enough. One code path:
# `cc_flag`/`cc_name`/`sanitize_name`/`sanitize_nim_args` are plain bash
# variables consumed while building the `cmd` string below, so both
# entrypoints (SELLO_IN_CONTAINER=1 and the podman-wrapped host branch)
# get identical flag/canary behavior with no branch-specific handling of
# either.
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
# SELLO_IN_CONTAINER=1 (RFC-005 slice 1): CI already runs this script
# inside the pinned toolchain image (the workflow's own `container:`), so
# there is no podman wrapper left to invoke and no HOST-side milpa state
# to preflight-check -- lib/milpa-preflight.sh's own header is explicit
# that `_deps/`/`milpa.lock` are host-side state the podman mount merely
# exposes; a container job either runs against a bare zero-dep nim.cfg
# (scripts/ci-setup.sh) or its own subsequently-fetched _deps/, and
# either way there is no host to check. One code path, two entrypoints:
# the `cmd` string built below is the single source of "what the suite
# run actually does," normally handed to `podman run ... bash -c "$cmd"`;
# under SELLO_IN_CONTAINER=1 it is instead handed to a plain local
# `bash -c "$cmd"`, skipping the podman/milpa-preflight branch entirely.
#
# OS-portability audit (part of this mode's own DoD, since the
# in-container branch is what the future macOS/Windows-Git-Bash CI jobs
# will run natively): the `cmd` string below is built entirely from
# forward-slash relative paths (`tests/unit/test_*.nim`, accepted as-is by
# Nim on Windows), plain `nim c`/`echo`/`set -e` lines with no shell
# builtin or flag specific to a Linux userland, and is executed via a bare
# `bash -c` relying on PATH resolution -- no `/bin/bash` hardcoding, no
# `/proc`, no GNU-coreutils-only flags. `cd "$(dirname "$0")/.."` and the
# `source`s above it use only `dirname`/`cd`, both present in Git Bash.
# Nothing in this branch shells out to a Linux-only tool (no `apt`, no
# `/dev/...` path, no `ldconfig`). Conclusion: clean, no Linux-isms found.
#
# Additional prerequisite for the property-based tests (test_properties_*,
# RFC-001 finding 10): proptest is an OPTIONAL milpa dep (milpa.kdl:
# `optional=#true`, auto-gated behind a same-named "proptest" feature flag,
# RFC #23 §3.2) so consumers of sello never transitively fetch
# proptest+nim-z3+softlink just by depending on sello. A plain `milpa fetch`
# prunes it (verified empirically: nim.cfg gains no proptest/z3/softlink
# --path lines and _deps/ is left empty -- there is no other dependency
# left to populate it). To enable it for local
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

# --cc <name> / --sanitize <name> (RFC-005 slices 8/9) -- see the header
# comment above. Either flag, in either order, may lead the argument list;
# the loop stops at the first argument that is neither, and everything
# from there on (including anything after the last consumed pair) is
# forwarded verbatim as before.
cc_name="gcc"
cc_flag=""
sanitize_name=""
sanitize_nim_args=""
while [[ "${1:-}" == "--cc" || "${1:-}" == "--sanitize" ]]; do
  case "$1" in
    --cc)
      if [[ -z "${2:-}" ]]; then
        echo "scripts/test.sh: --cc requires a compiler name, e.g. --cc clang" >&2
        exit 2
      fi
      cc_name="$2"
      cc_flag="--cc:$cc_name"
      shift 2
      ;;
    --sanitize)
      if [[ -z "${2:-}" ]]; then
        echo "scripts/test.sh: --sanitize requires a sanitizer set name, e.g. --sanitize asan-ubsan" >&2
        exit 2
      fi
      sanitize_name="$2"
      case "$sanitize_name" in
        asan-ubsan)
          # -g: usable source locations in ASan/UBSan reports (report
          # readability only -- no behavior change on a non-sanitize
          # build, since this whole block is gated behind --sanitize).
          # -fno-sanitize-recover=all: an UBSan finding aborts the run
          # instead of printing and continuing, so a real hit is a failed
          # test run, not a buried log line. -d:useMalloc: see header
          # comment above (required for ASan to see Nim/ORC's
          # allocations at all).
          sanitize_nim_args='--passC:"-fsanitize=address,undefined -fno-sanitize-recover=all -g" --passL:"-fsanitize=address,undefined" -d:useMalloc'
          ;;
        *)
          echo "scripts/test.sh: unknown --sanitize value '$sanitize_name' (supported: asan-ubsan)" >&2
          exit 2
          ;;
      esac
      shift 2
      ;;
  esac
done

extra_defines=("$@")

# unit_test_files ("which unit test files make up the suite") is defined in
# scripts/lib/unit-test-files.sh and sourced here, not retyped -- the same
# file is sourced by scripts/test-libsodium.sh, so the two matrices read one
# array instead of two hand-maintained copies that could silently drift
# apart (round-2 finding 25; the old comment here claimed "cannot drift"
# while actually being two independently-typed-out arrays -- this sourcing
# is what makes that claim true).
source "$(dirname "$0")/lib/unit-test-files.sh"

# End-of-run validation-tier visibility (round-3 fix batch B, finding B6) --
# see scripts/lib/tier-summary.sh's own header comment.
source "$(dirname "$0")/lib/tier-summary.sh"

img=ghcr.io/coreyleavitt/nim:2.2.10

cmd="set -e"
if [[ -n "$sanitize_name" ]]; then
  # LeakSanitizer disabled for sanitizer runs only -- see the --sanitize
  # header comment above for why (ptrace-based leak detection routinely
  # cannot run in an unprivileged CI container). Scoped to this branch so
  # a plain (non-sanitized) run's environment is untouched.
  cmd+=$'\n'"export ASAN_OPTIONS=detect_leaks=0"
fi
canary_done=0
for f in "${unit_test_files[@]}"; do
  cmd+=$'\n'"echo '=== $f ==='"
  if [[ "$canary_done" -eq 0 ]]; then
    # Platform-identity canary (RFC-005 slices 8/9): the first file's
    # compile is routed through a canary instead of a bare `nim c`,
    # proving from Nim's own --listCmd output what actually happened,
    # not merely what flag was requested. This IS this file's real
    # compile+run (`-r`), not an extra throwaway build -- the sanitizer
    # variant (when --sanitize is set) checks BOTH compiler identity and
    # sanitizer-flag presence from this one compile, rather than
    # composing two separate canary compiles of the same file.
    if [[ -n "$sanitize_name" ]]; then
      cmd+=$'\n'"scripts/lib/sanitizer-canary.sh $cc_name nim c $cc_flag $sanitize_nim_args ${extra_defines[*]:-} --listCmd -f -r $f"
    else
      cmd+=$'\n'"scripts/lib/toolchain-canary.sh $cc_name nim c $cc_flag ${extra_defines[*]:-} --listCmd -f -r $f"
    fi
    canary_done=1
  else
    cmd+=$'\n'"nim c $cc_flag $sanitize_nim_args ${extra_defines[*]:-} -r $f"
  fi
done
# Property suites skipped because _deps/proptest is absent (RFC-003 slice 2
# item 4) -- same loud self-skip register as test_libsodium_interop's
# runtime skip(), but decided here in bash since the failure mode being
# avoided (a missing `import proptest`) is a compile error, not something
# a runtime skip() inside the test binary could ever reach.
for f in "${skipped_property_files[@]}"; do
  cmd+=$'\n'"echo '=== $f ==='"
  cmd+=$'\n'"echo 'SKIPPED (proptest not fetched -- run: milpa fetch --features proptest)'"
done

if [ "${SELLO_IN_CONTAINER:-}" = "1" ]; then
  # Already inside the pinned toolchain image (CI) -- run the same
  # commands directly, no podman wrapper, no host milpa-lock preflight.
  bash -c "$cmd"
else
  # Lockfile-conformance preflight (RFC-001 ledger finding 30): fails fast
  # on the host if milpa.lock and _deps/ are genuinely out of sync, before
  # the podman invocation below ever starts. See
  # scripts/lib/milpa-preflight.sh for exactly what this does and does not
  # treat as fatal. Host-only: `_deps/`/`milpa.lock` are host-side state,
  # meaningless to check from inside the container this preflight is
  # gating entry to.
  source "$(dirname "$0")/lib/milpa-preflight.sh"
  milpa_preflight

  podman run --rm \
    -v "$PWD:/workspace" \
    -v "$HOME/.cache/milpa:/.cache/milpa" \
    -v "$HOME/.cache/milpa:$HOME/.cache/milpa" \
    -w /workspace \
    "$img" \
    bash -c "$cmd"
fi

print_tier_summary "scripts/test.sh"
