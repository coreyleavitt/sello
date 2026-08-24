#!/usr/bin/env bash
# scripts/lib/toolchain-canary.sh -- RFC-005 slice 8: the platform-identity
# canary for scripts/test.sh's C-backend selection (--cc). A matrix leg
# claiming "I ran on clang" (or, by the same mechanism, "gcc") must prove
# it, per RFC-005 Part B's red-then-green rule ("every matrix leg's DoD
# includes... the platform-identity canary") -- not merely echo the flag
# it was handed. Invoked exactly once per scripts/test.sh run, against
# the FIRST file in the unit-test-file list only: any single real `nim c`
# compile is enough to prove which C compiler Nim actually invoked, and
# repeating the check for every one of the ~18 files would be redundant
# log noise for zero extra assurance. gcc gets this canary for free
# (scripts/test.sh always calls this helper, whether or not --cc was
# passed) since the cost is one already-necessary compile, not a second
# one -- there was no reason to special-case gcc out of it.
#
# RFC-005 slice 12 addition: after the PASS/FAIL verdict, also echoes
# `<compiler> --version`'s first line -- the macOS-arm64 leg's own DoD
# needs the observed Apple clang version on record (Apple clang's version
# string diverges from upstream LLVM clang's), and this is the one place
# every leg's canary output already funnels through, so recording it here
# covers every leg uniformly rather than adding a macOS-only step.
#
# Mechanism: runs the given `nim c ...` invocation with `--listCmd`
# (Nim's own "print every command I execute" flag) and `-f`/--forceBuild
# (so the C-compiler invocation line is guaranteed to be emitted even if
# nimcache already holds a cached build from a prior run -- an incremental
# no-op build would print nothing to check), captures the combined
# output, and greps it for the literal compiler-invocation line --listCmd
# prints (e.g. "gcc -c -w ... -o ...o ...c" or "clang -c -w ... -o
# ...o ...c"). Asserting the EXPECTED compiler name appears in that line
# reads Nim's own record of what it executed, not just the flag we handed
# it -- closing the gap a bare `clang --version` sanity check would leave
# open (that only proves clang EXISTS on PATH, not that Nim actually
# invoked it for THIS build). The invocation also carries `-r` (run after
# compiling), so this doubles as the first file's real test-suite
# compile+run rather than an extra throwaway build -- scripts/test.sh
# does not compile this file a second time.
#
# Usage: toolchain-canary.sh <expected-cc-name> <full nim invocation...>
#   e.g. toolchain-canary.sh gcc   nim c --listCmd -f -r tests/unit/test_field.nim
#        toolchain-canary.sh clang nim c --cc:clang --listCmd -f -r tests/unit/test_field.nim
#
# <expected-cc-name> is a plain substring match against the captured
# compiler-invocation line (not a regex) -- "gcc" and "clang" are the only
# names scripts/test.sh's --cc parsing is exercised against today, but any
# name Nim's own [<name>] compiler-config section recognizes works the
# same way here.
set -uo pipefail

expect="$1"
shift

out="$("$@" 2>&1)"
rc=$?
echo "$out"

if [[ "$rc" -ne 0 ]]; then
  echo "toolchain canary: the compile/run itself failed (see output above) -- identity check not reached." >&2
  exit "$rc"
fi

# Matches a C-compiler-invocation line --listCmd prints: the compiler
# binary name (bare or path-prefixed, optionally version-suffixed like
# "gcc-13" or "clang-17") followed by whitespace, at the start of the
# line or after a path separator/whitespace.
line="$(printf '%s\n' "$out" | grep -m1 -E '(^|[ /\t])(gcc|clang)(-[0-9.]+)?([ \t]|$)')"
echo "toolchain canary: resolved C compiler invocation: ${line:-<none found in --listCmd output>}"

case "$line" in
  *"$expect"*)
    echo "toolchain canary: PASS -- confirmed Nim actually invoked '$expect'."
    ;;
  *)
    echo "toolchain canary: FAIL -- expected the C compiler invocation to contain '$expect', but observed: $line" >&2
    exit 1
    ;;
esac

# Observed compiler VERSION (RFC-005 slice 12 addition, general to every
# leg -- not macOS-specific): the checks above prove Nim invoked a binary
# named '$expect', but the macOS-arm64 leg's own pin story needs the
# ACTUAL version string on record too, not just the name -- Apple's clang
# reports a distinct "Apple clang version ..." line (its own version
# numbering, separate from upstream LLVM's), so a bare "clang" name match
# alone would not distinguish Apple's clang from upstream LLVM clang the
# way this project's pin-everything-verify-empirically posture expects.
# `--version`'s first line is enough to record identity; failure to run it
# is non-fatal (some compiler wrappers don't support a bare --version) so
# it never turns an otherwise-passing canary red.
if command -v "$expect" >/dev/null 2>&1; then
  version_line="$("$expect" --version 2>&1 | head -n1 || true)"
  echo "toolchain canary: observed '$expect --version' (first line): ${version_line:-<no output>}"
fi
