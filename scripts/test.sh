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
#         scripts/test.sh --expect-proptest-skip   # assert the proptest SKIPPED banner appears (RFC-005 slice 12)
#         scripts/test.sh --cpu i386   # 32-bit multilib build, unit+property suite (RFC-005 slice 10)
#         scripts/test.sh --cc clang -d:release   # leading flags compose with defines
#         scripts/test.sh --sanitize asan-ubsan --cc clang   # leading flags compose with each other too
#
# Pinned-toolchain convention (RFC-005 slice 11): if
# $HOME/.sello-nim/current/bin/nim exists, its directory is prepended to
# PATH before anything below runs. This is how hosted matrix legs with no
# digest-pinnable container image (linux/arm64, macOS-arm64, and
# Windows-MinGW, RFC-005 slices 11-13) get a pinned Nim onto PATH:
# scripts/ci-nim-setup.sh installs there (its own header has the full pin
# story) and this script picks it up automatically -- no $GITHUB_PATH
# plumbing, no sourcing gymnastics, and no branch-specific handling, since
# a plain on-disk check works identically whether ci-nim-setup.sh ran as a
# separate earlier workflow step or was chained via `&&` on the same
# command line (scripts/lib/gates.txt's convention for this leg). A no-op
# everywhere else -- container jobs never populate this directory, so
# `nim`/`gcc` keep resolving from the image's own PATH exactly as before.
#
# Pinned MinGW-w64 convention (RFC-005 slice 13, windows/MinGW-gcc leg
# only): the exact same idea, one directory over -- if
# $HOME/.sello-nim-mingw/current/bin/gcc(.exe) exists,
# $HOME/.sello-nim-mingw/current/bin is ALSO prepended to PATH. Windows
# ships no C compiler of any kind in-box, and Nim's own Windows toolchain
# zip is compiler-less (verified against the real asset, see
# scripts/lib/nim-pin.txt's own comment) -- scripts/ci-nim-setup.sh
# --with-mingw installs the pinned MinGW-w64 toolchain there (its own
# header has the full pin story). A no-op everywhere else -- no other leg
# ever populates this directory, so the check is unconditional and
# harmless the same way the Nim one above already is.
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
# --expect-proptest-skip (RFC-005 slice 12, the macOS-arm64 leg): a
# boolean (no value) leading flag asserting the proptest SKIPPED banner
# (see the "Additional prerequisite" paragraph below) DOES appear in this
# run's own output. This is the exact inverse of scripts/ci-property.sh's
# own assertion (that job asserts the banner is ABSENT, since it exists to
# run the property suites for real): a hosted leg with no milpa/proptest
# story of its own (macOS-arm64 today; Windows/MinGW, RFC-005 slice 13)
# has NO way to populate _deps/proptest, so the skip is the CORRECT,
# expected outcome there -- and a run where it went silently missing (or
# where the property suites somehow ran for real, e.g. a future change
# vendoring proptest into the zero-dep path) should be a red check, not a
# quietly-different suite. Implemented by tee-ing the run's combined
# output to a log file and grepping it afterward -- the same mechanism
# ci-property.sh already uses for its own (inverted) assertion, just
# inlined here rather than forwarded, since this flag belongs to
# scripts/test.sh itself (RFC-005 Part B's build-path invariant: one
# scripts/ invocation per job, no separate wrapper script needed for one
# grep).
#
# --cpu <name> (RFC-005 slice 10, the --cpu:i386 32-bit matrix leg):
# today's only supported name is `i386`. Threads `--cpu:i386` PLUS the C
# flags a real 32-bit build needs (`--passC:-m32 --passL:-m32`) into every
# `nim c` invocation below. `--cpu:i386` alone is NOT enough -- verified
# empirically inside sello-dev via `nim --cpu:i386 --listCmd`, not
# assumed: without an explicit `-m32` on the C compile/link lines, gcc
# happily compiles a 64-bit object under a Nim frontend that believes it
# targeted i386, and the mismatch is caught only downstream by nimbase.h's
# own `NIM_STATIC_ASSERT` on `sizeof(NI) == sizeof(void*)` -- a real,
# reproduced failure mode, not a hypothetical one, that composing
# `--passC:-m32 --passL:-m32` alongside `--cpu:i386` closes. This leg
# needs the `sello-dev` image (Containerfile's `gcc-32bit`/
# `glibc-devel-32bit`/`libstdc++6-32bit` packages, RFC-005 slice 7), not
# the base `ghcr.io/coreyleavitt/nim` image -- neither this script nor
# `scripts/lib/cpu-canary.sh` enforces that (both are plain image-agnostic
# `nim c`/gcc invocations); the image choice lives in the CALLER
# (`unit-linux-i386-gcc`'s own `container:` pin in merge-gate.yml).
# Composes with `--cc`/`--sanitize` the same way those two already compose
# with each other, though today's one caller (`scripts/lib/gates.txt`'s
# `unit-linux-i386-gcc` entry) passes `--cpu i386` alone, on the default
# gcc backend. `scripts/lib/cpu-canary.sh` is a genuinely different
# canary shape from `toolchain-canary.sh`/`sanitizer-canary.sh` -- see its
# own header comment for why (a runtime `doAssert sizeof(pointer) == 4`
# probe, not merely a `--listCmd` text inference) -- and runs once, BEFORE
# the per-file loop below, rather than riding the first unit test file's
# own compile the way the other two canaries do.
#
# All four flags are parsed by a small leading-argument loop (still not a
# general getopts parser -- this script has exactly four optional
# leading flags, three taking a value and one boolean, and every other
# argument stays an opaque pass-through define as before), so any of them,
# in any order, may lead the argument list; the loop stops at the first
# argument that isn't `--cc`/`--sanitize`/`--cpu`/`--expect-proptest-skip`,
# and everything from there on is forwarded verbatim as a define. The FIRST
# unit test file's compile is additionally run
# through a canary: scripts/lib/toolchain-canary.sh (compiler identity
# only) when `--sanitize` is unset, or scripts/lib/sanitizer-canary.sh
# (compiler identity AND sanitizer-flag presence, from the same one
# compile -- see that script's own header) when it is set. Both prove
# their claim via Nim's own `--listCmd` output -- not merely that a flag
# was accepted -- see either script's header for why a bare `clang
# --version`-style sanity check alone would not be enough. When `--cpu` is
# set, `scripts/lib/cpu-canary.sh` runs first (see above), and the
# per-file canary (toolchain- or sanitizer-) still runs too, now composed
# with the `--cpu`/`-m32` flags like every other compile in the run -- a
# second, incidental confirmation that the real suite's own first file
# also built 32-bit, on top of the dedicated probe's runtime proof. One
# code path: `cc_flag`/`cc_name`/`sanitize_name`/`sanitize_nim_args`/
# `cpu_name`/`cpu_flag`/`cpu_nim_args` are plain bash variables consumed
# while building the `cmd` string below, so both entrypoints
# (SELLO_IN_CONTAINER=1 and the podman-wrapped host branch) get identical
# flag/canary behavior with no branch-specific handling of either.
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

# Pinned-toolchain convention (RFC-005 slice 11) -- see the header comment
# above. Prepend, not overwrite: on hosted-runner legs this is the only
# nim/gcc on PATH; harmless no-op everywhere else.
if [ -x "$HOME/.sello-nim/current/bin/nim" ]; then
  export PATH="$HOME/.sello-nim/current/bin:$PATH"
fi

# Pinned MinGW-w64 convention (RFC-005 slice 13) -- see the header comment
# above. Prepend, not overwrite; harmless no-op everywhere else (no other
# leg ever populates $HOME/.sello-nim-mingw).
if [ -x "$HOME/.sello-nim-mingw/current/bin/gcc.exe" ] || [ -x "$HOME/.sello-nim-mingw/current/bin/gcc" ]; then
  export PATH="$HOME/.sello-nim-mingw/current/bin:$PATH"
fi

# --cc <name> / --sanitize <name> (RFC-005 slices 8/9) -- see the header
# comment above. Either flag, in either order, may lead the argument list;
# the loop stops at the first argument that is neither, and everything
# from there on (including anything after the last consumed pair) is
# forwarded verbatim as before.
cc_name="gcc"
cc_flag=""
sanitize_name=""
sanitize_nim_args=""
cpu_name=""
cpu_flag=""
cpu_nim_args=""
expect_proptest_skip=0
while [[ "${1:-}" == "--cc" || "${1:-}" == "--sanitize" || "${1:-}" == "--cpu" || "${1:-}" == "--expect-proptest-skip" ]]; do
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
    --cpu)
      if [[ -z "${2:-}" ]]; then
        echo "scripts/test.sh: --cpu requires a target name, e.g. --cpu i386" >&2
        exit 2
      fi
      cpu_name="$2"
      case "$cpu_name" in
        i386)
          # --cpu:i386 alone is not enough -- see the header comment
          # above for the reproduced NIM_STATIC_ASSERT failure this
          # composition closes.
          cpu_flag="--cpu:i386"
          cpu_nim_args='' # RFC-005 slice 10 RED DEMO -- -m32 deliberately dropped to show the platform-identity canary fail for real; reverted immediately after.
          ;;
        *)
          echo "scripts/test.sh: unknown --cpu value '$cpu_name' (supported: i386)" >&2
          exit 2
          ;;
      esac
      shift 2
      ;;
    --expect-proptest-skip)
      expect_proptest_skip=1
      shift
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
# scripts/lib/cpu-canary.sh (RFC-005 slice 10) runs BEFORE the per-file
# loop below, once, rather than riding the first file's own compile --
# see that script's own header comment for why (it proves a RUNTIME
# fact -- sizeof(pointer) == 4 -- that a --listCmd text inference alone
# cannot establish).
if [[ -n "$cpu_name" ]]; then
  cmd+=$'\n'"echo '=== cpu-canary ($cpu_name) ==='"
  cmd+=$'\n'"scripts/lib/cpu-canary.sh $cc_name nim c $cc_flag $cpu_flag $cpu_nim_args"
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
    # composing two separate canary compiles of the same file. When
    # --cpu is set (RFC-005 slice 10), this canary's own compile is ALSO
    # composed with the --cpu/-m32 flags -- a second, incidental
    # confirmation the real suite's own first file built 32-bit too, on
    # top of scripts/lib/cpu-canary.sh's dedicated runtime probe above.
    if [[ -n "$sanitize_name" ]]; then
      cmd+=$'\n'"scripts/lib/sanitizer-canary.sh $cc_name nim c $cc_flag $sanitize_nim_args $cpu_flag $cpu_nim_args ${extra_defines[*]:-} --listCmd -f -r $f"
    else
      cmd+=$'\n'"scripts/lib/toolchain-canary.sh $cc_name nim c $cc_flag $cpu_flag $cpu_nim_args ${extra_defines[*]:-} --listCmd -f -r $f"
    fi
    canary_done=1
  else
    cmd+=$'\n'"nim c $cc_flag $sanitize_nim_args $cpu_flag $cpu_nim_args ${extra_defines[*]:-} -r $f"
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

# --expect-proptest-skip's own log capture (RFC-005 slice 12) -- see the
# header comment above. Only allocated when the flag is set, so a plain
# `scripts/test.sh` run's output still streams straight to the terminal
# with no `tee` indirection at all (byte-identical to every prior slice's
# behavior). `set -o pipefail` (part of this script's own `set -euo
# pipefail`) is what makes `... | tee "$run_log"` still propagate the
# real command's exit status past the pipe, not `tee`'s own (always-zero)
# one.
run_log=""
if [[ "$expect_proptest_skip" -eq 1 ]]; then
  run_log="build/test-proptest-skip-check.log"
  mkdir -p "$(dirname "$run_log")"
fi

if [ "${SELLO_IN_CONTAINER:-}" = "1" ]; then
  # Already inside the pinned toolchain image (CI) -- run the same
  # commands directly, no podman wrapper, no host milpa-lock preflight.
  if [[ -n "$run_log" ]]; then
    bash -c "$cmd" 2>&1 | tee "$run_log"
  else
    bash -c "$cmd"
  fi
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

  # --cpu:i386 (RFC-005 slice 10) needs the 32-bit multilib packages only
  # `sello-dev` carries (Containerfile: gcc-32bit/glibc-devel-32bit/
  # libstdc++6-32bit, RFC-005 slice 7) -- the base
  # ghcr.io/coreyleavitt/nim image has no cross/multilib support at all.
  # A maintainer's local `scripts/test.sh --cpu i386` run therefore
  # resolves sello-dev instead, via the SAME pull-by-digest mechanism
  # scripts/test-libsodium.sh/scripts/bmc.sh already use
  # (scripts/lib/sello-dev-image.sh's own header has the full mechanism,
  # escape hatches included). CI itself never reaches this branch --
  # unit-linux-i386-gcc runs with SELLO_IN_CONTAINER=1, already inside
  # sello-dev via its own `container:` pin.
  if [[ -n "$cpu_name" ]]; then
    source "$(dirname "$0")/lib/sello-dev-image.sh"
    resolve_sello_dev_image
  fi

  if [[ -n "$run_log" ]]; then
    podman run --rm \
      -v "$PWD:/workspace" \
      -v "$HOME/.cache/milpa:/.cache/milpa" \
      -v "$HOME/.cache/milpa:$HOME/.cache/milpa" \
      -w /workspace \
      "$img" \
      bash -c "$cmd" 2>&1 | tee "$run_log"
  else
    podman run --rm \
      -v "$PWD:/workspace" \
      -v "$HOME/.cache/milpa:/.cache/milpa" \
      -v "$HOME/.cache/milpa:$HOME/.cache/milpa" \
      -w /workspace \
      "$img" \
      bash -c "$cmd"
  fi
fi

# --expect-proptest-skip's own assertion, run only after the suite itself
# has already succeeded (set -e above would have stopped this script
# already if it hadn't) -- the exact inverse of scripts/ci-property.sh's
# "assert the SKIPPED banner is ABSENT" check: this leg has no
# milpa/proptest story, so the banner's PRESENCE is the expected, correct
# outcome, and its absence (or the property suites somehow having run for
# real) is what must go red here.
if [[ -n "$run_log" ]]; then
  if grep -q 'SKIPPED (proptest not fetched' "$run_log"; then
    echo "test.sh: proptest SKIPPED banner present, as required (--expect-proptest-skip)." >&2
  else
    echo "" >&2
    echo "test.sh: FAIL -- --expect-proptest-skip was set but no SKIPPED banner appears in this run's log." >&2
    echo "test.sh: this leg has no milpa/proptest fetch story of its own, so the property" >&2
    echo "test.sh: suites are expected to self-skip loudly; either the skip went silent or" >&2
    echo "test.sh: they ran for real -- investigate, do not silence." >&2
    exit 1
  fi
fi

print_tier_summary "scripts/test.sh"
