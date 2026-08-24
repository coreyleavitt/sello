#!/usr/bin/env bash
# scripts/lib/sanitizer-canary.sh -- RFC-005 slice 9: the platform-identity
# canary for scripts/test.sh's --sanitize leg. Generalizes
# scripts/lib/toolchain-canary.sh's proof pattern (assert an identity fact
# from Nim's own --listCmd output, not from the flag alone) to the
# ASan/UBSan matrix leg: a job claiming "I compiled under
# -fsanitize=address,undefined" must prove the flag genuinely reached the
# real C compile command line, not merely that scripts/test.sh accepted
# --sanitize and forwarded --passC unchecked -- a typo'd --passC value, or
# a Nim/compiler version that silently drops an unrecognized passC token,
# would otherwise leave a green build that never actually sanitized
# anything (exactly the "gate proven only green is indistinguishable from
# a gate that cannot fire" failure mode the platform-identity canary rule
# exists to close).
#
# Supersedes scripts/lib/toolchain-canary.sh for the ONE first-unit-test-
# file compile scripts/test.sh routes through a canary, rather than
# composing with it (which would mean compiling that file twice for no
# extra assurance) -- this script re-implements the same compiler-identity
# check plus a second assertion for the sanitizer flags, from the SAME
# --listCmd capture, so the sanitizer leg's canary still costs exactly one
# already-necessary compile, same as the plain toolchain canary.
#
# Mechanism: identical capture/grep shape to toolchain-canary.sh (--listCmd
# + -f/--forceBuild, grep the emitted C-compiler-invocation line -- see
# that script's header for the full rationale on why --listCmd beats a
# bare `--version` check). Two assertions against the same captured line:
#   1. the expected compiler name appears (the same check
#      toolchain-canary.sh performs).
#   2. the literal substring "-fsanitize=" appears in that same
#      invocation line -- proving Nim's C backend genuinely received and
#      forwarded the --passC-supplied sanitizer flags into the real
#      compiler invocation, not just onto its own command line.
#
# Usage: sanitizer-canary.sh <expected-cc-name> <full nim invocation...>
#   e.g. sanitizer-canary.sh gcc nim c --passC:"-fsanitize=address,undefined -fno-sanitize-recover=all -g" --passL:"-fsanitize=address,undefined" -d:useMalloc --listCmd -f -r tests/unit/test_field.nim
set -uo pipefail

expect_cc="$1"
shift

out="$("$@" 2>&1)"
rc=$?
echo "$out"

if [[ "$rc" -ne 0 ]]; then
  echo "sanitizer canary: the compile/run itself failed (see output above) -- identity check not reached." >&2
  exit "$rc"
fi

# Same C-compiler-invocation line match as toolchain-canary.sh (see that
# script's header for the exact pattern rationale).
line="$(printf '%s\n' "$out" | grep -m1 -E '(^|[ /\t])(gcc|clang)(-[0-9.]+)?([ \t]|$)')"
echo "sanitizer canary: resolved C compiler invocation: ${line:-<none found in --listCmd output>}"

case "$line" in
  *"$expect_cc"*)
    echo "sanitizer canary: PASS -- confirmed Nim actually invoked '$expect_cc'."
    ;;
  *)
    echo "sanitizer canary: FAIL -- expected the C compiler invocation to contain '$expect_cc', but observed: $line" >&2
    exit 1
    ;;
esac

case "$line" in
  *"-fsanitize="*)
    echo "sanitizer canary: PASS -- confirmed the C compile invocation carries -fsanitize=."
    ;;
  *)
    echo "sanitizer canary: FAIL -- expected the C compile invocation to carry -fsanitize=, but observed: $line" >&2
    exit 1
    ;;
esac
