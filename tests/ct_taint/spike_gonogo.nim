## tests/ct_taint/spike_gonogo.nim -- Stage 1 go/no-go spike (RFC-005 slice
## 19, A1). Answers the two-sided go/no-go question BEFORE any
## DeclassId/register machinery is built (see docs/rfc-005-validation-infra.md's
## A1 "Go/no-go criterion" paragraph): does Valgrind memcheck, driven via
## client-request macros reached from a tiny C shim
## (tests/ct_taint/spike_shim.c -- a throwaway spike shim, NOT the
## production src/sello/private/taint_shim.c built in Stage 2), produce
## (i) ZERO errors on a masked-select chain fed a tainted secret, and (ii)
## EXACTLY ONE resolvable error class on a planted secret-conditioned
## branch over the SAME tainted secret.
##
## Two build modes, one file (matching the RFC's "the same toy" framing):
##   plain build            -> the clean half: taints a 32-byte scalar,
##                             feeds it through the real Montgomery ladder
##                             (sello/x25519.x25519Base -- exercises
##                             feCMove/feCSwap on every one of the ladder's
##                             255 iterations, a superset of "one ladder
##                             step"), declassifies only the derived PUBLIC
##                             key bytes (the harness-side
##                             MAKE_MEM_DEFINED-on-output idiom the RFC's
##                             boundary rule specifies), and never branches
##                             on the secret anywhere. Expected: 0 memcheck
##                             errors.
##   -d:spikeLeaky build     -> the leaky half: identical setup, PLUS one
##                             planted secret-conditioned branch
##                             (`if (secretBytes[0] and 1'u8) == 0'u8`)
##                             ahead of the ladder call -- a direct
##                             conditional jump on still-undefined memory.
##                             Expected: exactly one memcheck error class
##                             ("Conditional jump or move depends on
##                             uninitialised value(s)"), stack trace
##                             resolving to this proc's `if`.
##
## Built with the identical flags as the dudect harness (`-d:release`,
## same gcc, same pinned sello-dev image) per the RFC's build-pinning
## requirement -- a non-release build would false-positive on debug-only
## asserts elsewhere in the library.
##
## This file is NOT part of scripts/test.sh's unit_test_files array and
## is not built by scripts/ct-taint.sh (Stage 3's harness) -- it is run
## by hand (or by a future maintainer re-verifying the go/no-go finding),
## a permanent, inert record of the decision, not a CI gate.

import sello/x25519

{.passC: "-I/usr/include".}
{.compile: "spike_shim.c".}

proc spikeTaintUndefined(p: pointer; len: csize_t) {.importc: "spike_taint_undefined", cdecl.}
proc spikeTaintDefined(p: pointer; len: csize_t) {.importc: "spike_taint_defined", cdecl.}

proc main() =
  var secretBytes: array[32, byte]
  for i in 0 ..< 32: secretBytes[i] = byte(i * 7 + 3)
  spikeTaintUndefined(addr secretBytes[0], csize_t(32))

  when defined(spikeLeaky):
    # Planted secret-conditioned branch: a direct conditional jump on
    # still-undefined (= tainted-secret) data. This is the ONE thing this
    # build adds relative to the plain build above.
    if (secretBytes[0] and 1'u8) == 0'u8:
      echo "spike: leaky branch took the even path"
    else:
      echo "spike: leaky branch took the odd path"

  let secret = toX25519StaticSecret(secretBytes)
  # Exercises the real Montgomery ladder (sello/x25519.ladder, via
  # x25519Base) on the tainted scalar -- feCSwap's masked swap runs once
  # per ladder iteration (255 total), never branching on the secret bit
  # it swaps on.
  let pub = x25519Base(secret)

  var outBytes = toBytes(pub)
  # Harness-side MAKE_MEM_DEFINED on the derived PUBLIC key bytes before
  # use -- the boundary-rule idiom: this is sanctioned public output (a
  # derived public key), not a secret DH output, so a direct declassify
  # here (rather than a register entry) matches this spike's own "before
  # any register exists" scope.
  spikeTaintDefined(addr outBytes[0], csize_t(32))

  echo "spike: derived public key first byte = ", outBytes[0]

main()
