## Coverage-guided fuzz campaign entry point (RFC-001 review finding 12;
## reworked to an EXTERNAL SanitizerCoverage target by RFC-002 slice 3):
## sello's audited attacker-facing surface (`pointDecode`, `verify`,
## `x25519`'s peer public u-coordinate, and -- RFC-004 slice 8a --
## `ristretto.ristrettoDecode`), driven by COREY'S proptest
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
## Corpus seeding (round-3 fix batch B, finding B2 -- SPIKE VERDICT: YES):
## `FuzzSettings.initialIRCorpus: seq[seq[ChoiceNode]]` (`_deps/proptest/
## src/proptest/fuzz.nim`) DOES support seeding IR-mode's corpus with
## concrete inputs -- not via a raw-bytes hook (there genuinely is none
## for IR mode), but via the typed choice-IR itself: a hand-built
## `seq[ChoiceNode]` matching a strategy's own draw shape (`fuzz_common.
## nim`'s `byteChoices`/`listChoices`, built on `proptest/choice`'s
## `integerChoice`/`booleanChoice` constructors -- deliberately NOT
## re-exported by the top-level `proptest` module, reached via the
## submodule import per that module's own doc comment) replays correctly
## through `captureIR` and is admitted as a real seed, per `datasource.
## nim`'s documented "replay clamps the recorded value" contract. Each of
## the four campaigns below is seeded with a handful of known-valid
## concrete inputs (RFC 8032 §7.1 TEST 1/2/3 for `pointDecode`/`verify`,
## RFC 7748 §4.1/§5.2 for `x25519`'s peer u-coordinate, RFC 9496 Appendix
## A.1 for `ristrettoDecode` -- see `fuzz_common.nim`'s `pointDecodeSeeds`/
## `verifySeeds`/`x25519Seeds`/`ristrettoDecodeSeeds`) so mutation
## explores the ACCEPT boundary from real accepted structure outward,
## instead of only ever approaching it from the reject side (the prior
## framing's actual gap: self-seeding from one random input starts, on
## expectation, at a REJECTED point -- a random 32/64-byte string almost
## never decodes/verifies -- so every earlier campaign's mutation pressure
## was structurally biased toward the reject side of the boundary).
## `runExternalTarget` asserts `report.droppedSeeds == 0` so a future
## strategy-shape change that silently breaks a seed's replay fails the
## build instead of quietly losing this coverage.
##
## Corpus continuity (RFC-005 slice 24, A5): `SELLO_FUZZ_CORPUS_DIR`, when
## set, turns on cross-run corpus persistence via proptest's own
## `directoryBasedDatabase` -- see `fuzz_common.nim`'s "Run + report"
## section doc paragraph for the full design and `scripts/nightly-fuzz.sh`
## for the one caller that sets it. Unset (every other caller), behavior
## is byte-for-byte the pre-slice-24 one-shot-in-memory-corpus run.
import std/[os, parseutils]
import proptest  # ExampleDatabase / directoryBasedDatabase (db.nim, re-exported)
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
  let crashDir = getEnv("SELLO_FUZZ_CRASH_DIR", "build" / "fuzz-crashes")

  # Corpus continuity (RFC-005 slice 24, A5) -- OPT IN via
  # SELLO_FUZZ_CORPUS_DIR, unset by every pre-existing caller (a
  # maintainer's plain `scripts/fuzz.sh`): `scripts/nightly-fuzz.sh` is
  # the one caller that sets it, pointed at a directory restored from /
  # saved back to the GitHub Actions cache (that script's own header has
  # the full cache-key design). `directoryBasedDatabase` (proptest's
  # file-backed `ExampleDatabase`, re-exported by top-level `proptest`
  # via its `db` submodule) is a value-type closure record; one instance
  # here is shared across all four `runExternalTarget` calls below, each
  # under its own `persistKey` (so the one directory holds four
  # `<safeKey>.bin` files, one per campaign -- see `db.nim`'s own
  # `directoryBasedDatabase` doc comment for the on-disk shape). An empty
  # env value leaves `database` at its default inactive `ExampleDatabase()`
  # (see `fuzz_common.nim`'s own module-doc paragraph on this default).
  let corpusDir = getEnv("SELLO_FUZZ_CORPUS_DIR", "")
  let database = if corpusDir.len > 0: directoryBasedDatabase(corpusDir)
                 else: ExampleDatabase()

  echo "sello fuzz harness (RFC-001 finding 12 / RFC-002 slice 3 / RFC-004 slice 8a / RFC-005 slice 24) -- ",
       perTarget, "s budget per target, ", perTarget * 4, "s total, external target: ", targetBin
  if corpusDir.len > 0:
    echo "  corpus persistence ACTIVE: ", corpusDir, " (crash artifacts under ", crashDir, ")"
  else:
    echo "  corpus persistence: off (SELLO_FUZZ_CORPUS_DIR not set -- ordinary local/CI run)"

  runExternalTarget("ed25519.pointDecode", bytes32(), encodePointDecode,
                     targetBin, perTarget, 0xC0FFEE'u64, pointDecodeSeeds(),
                     database, "sello-pointDecode", crashDir)
  runExternalTarget("ed25519.verify", verifyInputs(), encodeVerify,
                     targetBin, perTarget, 0xBADF00D'u64, verifySeeds(),
                     database, "sello-verify", crashDir)
  runExternalTarget("x25519 (attacker peer u-coordinate)", bytes32(), encodeX25519,
                     targetBin, perTarget, 0xDEADBEEF'u64, x25519Seeds(),
                     database, "sello-x25519", crashDir)
  runExternalTarget("ristretto.ristrettoDecode", bytes32(), encodeRistrettoDecode,
                     targetBin, perTarget, 0xF00DBABE'u64, ristrettoDecodeSeeds(),
                     database, "sello-ristrettoDecode", crashDir)

  echo "fuzz campaign complete -- no crashes found on any target, coverage gate passed"
