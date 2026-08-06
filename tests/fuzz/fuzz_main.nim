## Coverage-guided fuzz campaign entry point (RFC-001 review finding 12):
## sello's audited attacker-facing surface (`pointDecode`, `verify`,
## `x25519`'s peer public u-coordinate), driven by COREY'S proptest
## library's in-process `fuzzWith` (IR mutation mode, coverage-guided
## admission). See `fuzz_common.nim`'s module doc comment for the full
## scope statement -- what is and isn't fuzzed, and why -- before reading
## results into this as more than it claims.
##
## Standalone, non-suite binary (mirrors `tests/ct/ct_main.nim`'s role):
## NOT part of scripts/test.sh. Run via `scripts/fuzz.sh`.
##
## Corpus seeding: proptest's `fuzzWith`/IR-mode corpus self-seeds by
## generating one random input through the strategy (see fuzz.nim's
## `fuzzWithIR` -- `initialIRCorpus` empty is the default path here) and
## grows it via IR-level mutation + coverage admission; there is no
## direct "seed from raw bytes" hook for IR mode (that's `fmBytes`'s
## contract, kept for external/libFuzzer-style byte harnesses -- see
## docs/fuzz/INTERFACE.md's `FuzzMutationMode`). Rather than fight the
## grain of the IR-mode API to splice existing RFC 8032/Wycheproof vector
## bytes in as literal byte seeds, this harness relies on proptest's
## generative IR mutation (perturb-integer, kind-boundary, span-splice/
## delete/duplicate -- fuzz.nim's five mutators) plus the fact that the
## known-good/known-bad structured vectors are already exhaustively
## covered by tests/unit/test_wycheproof*.nim and test_ed25519.nim; this
## harness's job is the UNSTRUCTURED space those miss by construction.
import std/[os, parseutils]
import proptest
import ./fuzz_common

proc secondsFromEnv(name: string; default: int): int =
  let s = getEnv(name, "")
  if s.len == 0: return default
  var v: int
  if parseutils.parseInt(s, v) <= 0: return default
  v

when isMainModule:
  let perTarget = secondsFromEnv("SELLO_FUZZ_SECONDS", 60)
  echo "sello fuzz harness (RFC-001 finding 12) -- ", perTarget,
       "s budget per target, ", perTarget * 3, "s total"

  runTarget("ed25519.pointDecode", bytes32(), coveredPointDecode,
            perTarget, 0xC0FFEE'u64)
  runTarget("ed25519.verify", verifyInputs(), coveredVerify,
            perTarget, 0xBADF00D'u64)
  runTarget("x25519 (attacker peer u-coordinate)", bytes32(), coveredX25519,
            perTarget, 0xDEADBEEF'u64)

  echo "fuzz campaign complete -- no crashes found on any target"
