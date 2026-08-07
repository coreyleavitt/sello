## Coverage-guided fuzz campaign entry point (RFC-001 review finding 12;
## reworked to an EXTERNAL SanitizerCoverage target by RFC-002 slice 3):
## sello's audited attacker-facing surface (`pointDecode`, `verify`,
## `x25519`'s peer public u-coordinate), driven by COREY'S proptest
## library's `externalTarget`/`fuzz` against the separately-compiled,
## SanitizerCoverage-instrumented `build/fuzz_external_target` binary
## (see `fuzz_external_target.nim`'s module doc for the oracle logic and
## wire format, and `fuzz_common.nim`'s module doc for why the driver
## process itself imports no `sello/*` module at all).
##
## Standalone, non-suite binary (mirrors `tests/ct/ct_main.nim`'s role):
## NOT part of scripts/test.sh. Run via `scripts/fuzz.sh`, which builds
## `build/fuzz_external_target` FIRST (instrumented) and only then
## compiles and runs this driver.
##
## Corpus seeding: proptest's `fuzz`/IR-mode corpus self-seeds by
## generating one random input through the strategy (`initialIRCorpus`
## empty is the default path here) and grows it via IR-level mutation +
## external-coverage admission (a new sancov edge in the CHILD process,
## not an in-process bitmap); there is no direct "seed from raw bytes"
## hook for IR mode. Rather than fight the grain of the IR-mode API to
## splice existing RFC 8032/Wycheproof vector bytes in as literal byte
## seeds, this harness relies on proptest's generative IR mutation
## (perturb-integer, kind-boundary, span-splice/delete/duplicate --
## fuzz.nim's five mutators) plus the fact that the known-good/known-bad
## structured vectors are already exhaustively covered by
## tests/unit/test_wycheproof*.nim and test_ed25519.nim; this harness's
## job is the UNSTRUCTURED space those miss by construction.
import std/[os, parseutils]
import ./fuzz_common

proc secondsFromEnv(name: string; default: int): int =
  let s = getEnv(name, "")
  if s.len == 0: return default
  var v: int
  if parseutils.parseInt(s, v) <= 0: return default
  v

when isMainModule:
  let perTarget = secondsFromEnv("SELLO_FUZZ_SECONDS", 60)
  let targetBin = getEnv("SELLO_FUZZ_TARGET_BIN", "build" / "fuzz_external_target")
  echo "sello fuzz harness (RFC-001 finding 12 / RFC-002 slice 3) -- ", perTarget,
       "s budget per target, ", perTarget * 3, "s total, external target: ", targetBin

  runExternalTarget("ed25519.pointDecode", bytes32(), encodePointDecode,
                     targetBin, perTarget, 0xC0FFEE'u64)
  runExternalTarget("ed25519.verify", verifyInputs(), encodeVerify,
                     targetBin, perTarget, 0xBADF00D'u64)
  runExternalTarget("x25519 (attacker peer u-coordinate)", bytes32(), encodeX25519,
                     targetBin, perTarget, 0xDEADBEEF'u64)

  echo "fuzz campaign complete -- no crashes found on any target, coverage gate passed"
