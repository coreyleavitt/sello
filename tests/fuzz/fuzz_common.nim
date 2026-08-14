## Shared strategies, byte-encoders, and the run/report loop for sello's
## coverage-guided fuzz harness (RFC-001 review finding 12, reworked by
## RFC-002 slice 3 into an EXTERNAL SanitizerCoverage target). Imported by
## `fuzz_main.nim`; not a test itself, mirroring `tests/ct/dudect.nim`'s
## role as the engine behind `tests/ct/ct_main.nim`.
##
## SCOPE -- attacker-controlled-input surface ONLY. The four oracles
## (pointDecode, verify, x25519's peer public u-coordinate, and -- RFC-004
## slice 8a -- ristretto.ristrettoDecode) are exactly the boundary where
## sello parses bytes nobody had to prove well-formed before handing them
## to us. Deliberately NOT fuzzed: `backend.
## signDetached` and `scalar.geScalarmultBase` -- those hold the secret
## scalar and are branchless BY DESIGN (constant-time discipline,
## CLAUDE.md's verify/sign split); their risk is a TIMING side channel on
## secret data, which a mutation fuzzer cannot observe or usefully stress,
## and which `tests/ct/`'s dudect harness already owns.
##
## RFC-002 slice 3 rework: this file used to hold `{.cover.}`-instrumented
## in-process oracle wrappers driven by `fuzzWith` (IR mutation mode). That
## harness's coverage signal was "which outcome branch did the wrapper
## take" -- a 2-edge universe per target (decode ok/reject, verify accept/
## reject, x25519 some/none), saturated within the first few iterations,
## i.e. black-box random thereafter with no real guidance. It has been
## replaced by an EXTERNAL SanitizerCoverage target
## (`fuzz_external_target.nim`, compiled separately with
## `-fsanitize-coverage=trace-pc -fno-pie` and linked against proptest's
## vendored `proptest_cov.c` runtime -- see that file's module doc for the
## oracle logic and `scripts/fuzz.sh` for the two-stage build). This file
## now holds only the DRIVER side: strategies over the plain value types,
## byte-encoders that prepend the target binary's mode-selector byte, and
## the run/report loop over `proptest`'s `externalTarget`/`fuzz`. It has
## NO import of any `sello/*` module -- the driver process never touches
## sello source; only the separately-compiled, separately-instrumented
## `fuzz_external_target` binary does, one fresh subprocess per input
## (`[INV-fresh-exec]`, docs/fuzz/FUZZ_PLAN.md D2).
import std/[os, times]
import proptest
# `integerChoice`/`booleanChoice` (round-3 fix batch B, finding B2): the
# top-level `proptest` module deliberately does NOT re-export these
# constructors (see its own module doc: "reach for them via the submodule
# import only when you have a specific reason -- test fixtures that
# hand-craft sequences"). Hand-crafting a `seq[ChoiceNode]` for a
# KNOWN-VALID concrete input, to seed `FuzzSettings.initialIRCorpus`
# below, is exactly that reason.
import proptest/choice as ptchoice

# ---------------------------------------------------------------------------
# Strategies (unchanged in shape from the pre-slice-3 harness)
# ---------------------------------------------------------------------------

proc randByte*(): Strategy[byte] =
  integers(0, 255).map(proc(x: int): byte = byte(x))

proc bytes32*(): Strategy[array[32, byte]] =
  arrays[32, byte](randByte())

proc bytes64*(): Strategy[array[64, byte]] =
  arrays[64, byte](randByte())

type
  VerifyInput* = object
    sig*: array[64, byte]
    msg*: seq[byte]
    pk*: array[32, byte]

proc verifyInputs*(): Strategy[VerifyInput] =
  ## Composite strategy over sig || msg || pk -- everything `verify` reads.
  ## `newStrategy` is proptest's documented escape hatch for a strategy over
  ## a type its combinators don't build directly (no built-in tuple/record
  ## zip combinator; see strategy.nim's `newStrategy` doc comment).
  let sigS = bytes64()
  let msgS = bytes(0, 512)
  let pkS = bytes32()
  newStrategy[VerifyInput](proc(src: var DataSource): VerifyInput =
    VerifyInput(sig: sigS.run(src), msg: msgS.run(src), pk: pkS.run(src)))

# ---------------------------------------------------------------------------
# Byte-encoders -- mode byte + payload, matching
# `fuzz_external_target.nim`'s documented wire format exactly.
# ---------------------------------------------------------------------------

const
  ModePointDecode = 0'u8
  ModeVerify = 1'u8
  ModeX25519 = 2'u8
  ModeRistrettoDecode = 3'u8
    ## RFC-004 slice 8a: `ristretto.ristrettoDecode` joins the fuzz surface
    ## (it is squarely attacker-controlled wire input). Matches
    ## `fuzz_external_target.nim`'s wire-format doc comment exactly.

proc encodePointDecode*(b: array[32, byte]): seq[byte] =
  result = newSeq[byte](33)
  result[0] = ModePointDecode
  for i in 0 ..< 32: result[i + 1] = b[i]

proc encodeVerify*(inp: VerifyInput): seq[byte] =
  result = newSeq[byte](1 + 64 + 32 + inp.msg.len)
  result[0] = ModeVerify
  for i in 0 ..< 64: result[i + 1] = inp.sig[i]
  for i in 0 ..< 32: result[i + 65] = inp.pk[i]
  for i in 0 ..< inp.msg.len: result[i + 97] = inp.msg[i]

proc encodeX25519*(b: array[32, byte]): seq[byte] =
  result = newSeq[byte](33)
  result[0] = ModeX25519
  for i in 0 ..< 32: result[i + 1] = b[i]

proc encodeRistrettoDecode*(b: array[32, byte]): seq[byte] =
  ## RFC-004 slice 8a. Same shape as `encodePointDecode`/`encodeX25519`
  ## (both fixed-width `array[32, byte]` payloads); the byte-encoder's
  ## strategy is `bytes32()`, reused as-is -- ristretto255 encodings and
  ## Edwards point encodings are both bare 32-byte candidates from the
  ## fuzzer's point of view, so no new strategy type is needed.
  result = newSeq[byte](33)
  result[0] = ModeRistrettoDecode
  for i in 0 ..< 32: result[i + 1] = b[i]

# ---------------------------------------------------------------------------
# Corpus seeding (round-3 fix batch B, finding B2) -- SPIKE VERDICT: YES,
# proptest's external-target fuzz API supports seeding IR-mode's corpus
# with concrete inputs, via `FuzzSettings.initialIRCorpus: seq[seq[
# ChoiceNode]]` (`_deps/proptest/src/proptest/fuzz.nim`). Prior to this
# fix, `fuzz_main.nim`'s module doc claimed no such hook existed
# ("there is no direct 'seed from raw bytes' hook for IR mode") -- true
# for a raw-BYTES hook, but `initialIRCorpus` seeds via the typed
# choice-IR instead, which turns out to be the right level anyway: a
# hand-built `seq[ChoiceNode]` matching a strategy's own draw shape
# replays through `captureIR` and is admitted as a real seed.
#
# Evidence this works (not merely "the field exists"), read directly from
# `_deps/proptest` source (read-only reference, unmodified):
#   - `datasource.nim`'s `drawInteger` replay branch: "Replay clamps the
#     recorded value" (`value = clamp(ds.takeReplay(ckInteger).intVal, min,
#     max)`) -- a hand-built `integerChoice(byteVal, 0, 255, 0)` node
#     replays correctly against `randByte() = integers(0, 255).map(...)`
#     without needing to reconstruct that strategy's exact internal
#     `IntConstraints`; only the node's `kind` (`ckInteger`) and the
#     in-range value matter.
#   - `strategy.nim`'s `lists` doc comment spells out the exact
#     "why this matters for seed replay" draw shape (`2N+1` interleaved
#     boolean-continue / element nodes) that `bytes(minLen, maxLen)` (used
#     by `verifyInputs`'s `msg` field) is built on -- `listChoices` below
#     mirrors that shape byte-for-byte, including the same `p` thresholds
#     (`1.0` while below `minLen`, `0.0` at `maxLen`, `0.9` in between)
#     `lists`' own `run` closure uses.
#   - `fuzz.nim`'s `fuzz` proc: every `settings.initialIRCorpus` entry is
#     replayed through `captureIR(s, seed)` before the loop starts; a seed
#     that fails to replay (`cap.ok == false`) is counted in
#     `result.droppedSeeds` rather than silently discarded -- `
#     runExternalTarget` below asserts this is always 0, so a future
#     strategy-shape change that silently breaks a seed's replay is a
#     build failure, not quiet lost coverage.
#
# `arrays[N, T]` (the fixed-size `bytes32`/`bytes64` strategies) has no
# continue-booleans at all -- `byteChoices` alone covers `pointDecode`'s
# and `x25519`'s `bytes32()` targets and `verifyInputs`'s `sig`/`pk`
# fields; `listChoices` covers `verifyInputs`'s variable-length `msg`
# field on top of that.
proc byteChoices(bs: openArray[byte]): seq[ChoiceNode] =
  result = newSeq[ChoiceNode](bs.len)
  for i in 0 ..< bs.len:
    result[i] = ptchoice.integerChoice(int(bs[i]), 0, 255, 0)

proc boolNode(value: bool; p: float): ChoiceNode =
  let forced = p <= 0.0 or p >= 1.0
  ptchoice.booleanChoice(value, p, forced)

proc listChoices(bs: openArray[byte]; minLen, maxLen: int): seq[ChoiceNode] =
  ## Mirrors `strategy.nim`'s `lists` combinator's draw shape exactly:
  ## per element, a forced-or-biased "continue" boolean then the element
  ## itself, followed by one final "stop" boolean once `bs.len` elements
  ## have been emitted.
  result = @[]
  for i in 0 ..< bs.len:
    let p = if i < minLen: 1.0 elif i >= maxLen: 0.0 else: 0.9
    result.add boolNode(true, p)
    result.add ptchoice.integerChoice(int(bs[i]), 0, 255, 0)
  let n = bs.len
  let pFinal = if n < minLen: 1.0 elif n >= maxLen: 0.0 else: 0.9
  result.add boolNode(false, pFinal)

proc pointDecodeSeeds*(): seq[seq[ChoiceNode]] =
  ## A handful of valid RFC 8032 point encodings (public keys from the
  ## §7.1 TEST 1/2/3 vectors, reused here purely as convenient
  ## already-verified-canonical 32-byte points -- this harness is about
  ## exercising the decode ACCEPT boundary, not RFC vector coverage,
  ## which `test_ed25519.nim`/`test_wycheproof.nim` already own).
  const
    tv1Pk: array[32, byte] = [
      0xd7'u8, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
      0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
      0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
      0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a]
    tv2Pk: array[32, byte] = [
      0x3d'u8, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a,
      0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
      0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c,
      0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c]
    tv3Pk: array[32, byte] = [
      0xfc'u8, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3,
      0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30, 0xf0, 0x58,
      0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x03, 0xac,
      0x5d, 0xeb, 0x91, 0x15, 0x48, 0x90, 0x80, 0x25]
  @[byteChoices(tv1Pk), byteChoices(tv2Pk), byteChoices(tv3Pk)]

proc verifySeeds*(): seq[seq[ChoiceNode]] =
  ## RFC 8032 §7.1 TEST 1/2/3: three valid (pk, msg, sig) triples spanning
  ## empty/1-byte/2-byte messages, encoded in `verifyInputs`'s own
  ## sig-then-msg-then-pk field order (matches `VerifyInput`'s object
  ## constructor, which Nim evaluates left to right).
  const
    tv1Pk: array[32, byte] = [
      0xd7'u8, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
      0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
      0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
      0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a]
    tv1Sig: array[64, byte] = [
      0xe5'u8, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72,
      0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
      0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
      0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
      0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac,
      0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
      0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
      0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b]
    tv2Pk: array[32, byte] = [
      0x3d'u8, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a,
      0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
      0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c,
      0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c]
    tv2Msg: array[1, byte] = [0x72'u8]
    tv2Sig: array[64, byte] = [
      0x92'u8, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8,
      0x72, 0x0e, 0x82, 0x0b, 0x5f, 0x64, 0x25, 0x40,
      0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f,
      0xb3, 0x76, 0x22, 0x23, 0xeb, 0xdb, 0x69, 0xda,
      0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99, 0x6e,
      0x45, 0x8f, 0x36, 0x13, 0xd0, 0xf1, 0x1d, 0x8c,
      0x38, 0x7b, 0x2e, 0xae, 0xb4, 0x30, 0x2a, 0xee,
      0xb0, 0x0d, 0x29, 0x16, 0x12, 0xbb, 0x0c, 0x00]
    tv3Pk: array[32, byte] = [
      0xfc'u8, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3,
      0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30, 0xf0, 0x58,
      0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x03, 0xac,
      0x5d, 0xeb, 0x91, 0x15, 0x48, 0x90, 0x80, 0x25]
    tv3Msg: array[2, byte] = [0xaf'u8, 0x82]
    tv3Sig: array[64, byte] = [
      0x62'u8, 0x91, 0xd6, 0x57, 0xde, 0xec, 0x24, 0x02,
      0x48, 0x27, 0xe6, 0x9c, 0x3a, 0xbe, 0x01, 0xa3,
      0x0c, 0xe5, 0x48, 0xa2, 0x84, 0x74, 0x3a, 0x44,
      0x5e, 0x36, 0x80, 0xd7, 0xdb, 0x5a, 0xc3, 0xac,
      0x18, 0xff, 0x9b, 0x53, 0x8d, 0x16, 0xf2, 0x90,
      0xae, 0x67, 0xf7, 0x60, 0x98, 0x4d, 0xc6, 0x59,
      0x4a, 0x7c, 0x15, 0xe9, 0x71, 0x6e, 0xd2, 0x8d,
      0xc0, 0x27, 0xbe, 0xce, 0xea, 0x1e, 0xc4, 0x0a]
    emptyMsg: array[0, byte] = []
  @[
    byteChoices(tv1Sig) & listChoices(emptyMsg, 0, 512) & byteChoices(tv1Pk),
    byteChoices(tv2Sig) & listChoices(tv2Msg, 0, 512) & byteChoices(tv2Pk),
    byteChoices(tv3Sig) & listChoices(tv3Msg, 0, 512) & byteChoices(tv3Pk),
  ]

proc x25519Seeds*(): seq[seq[ChoiceNode]] =
  ## Valid peer u-coordinates from RFC 7748 -- the base point (§4.1's
  ## `u = 9`) plus the two §5.2 iteration-1 vector inputs. All three are
  ## canonical, non-small-order points that pair with
  ## `fuzz_external_target.nim`'s fixed `localSecretForFuzzing` to
  ## produce a non-all-zero shared secret (the accept path), the same way
  ## the RFC 8032/x25519 vectors above seed `verify`'s/`pointDecode`'s
  ## accept boundaries.
  const
    basePoint: array[32, byte] = [
      9'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    vec1U: array[32, byte] = [
      0xe6'u8, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb,
      0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1, 0x5f, 0x7c,
      0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b,
      0x10, 0xa9, 0x03, 0xa6, 0xd0, 0xab, 0x1c, 0x4c]
    vec2U: array[32, byte] = [
      0xe5'u8, 0x21, 0x0f, 0x12, 0x78, 0x68, 0x11, 0xd3,
      0xf4, 0xb7, 0x95, 0x9d, 0x05, 0x38, 0xae, 0x2c,
      0x31, 0xdb, 0xe7, 0x10, 0x6f, 0xc0, 0x3c, 0x3e,
      0xfc, 0x4c, 0xd5, 0x49, 0xc7, 0x15, 0xa4, 0x93]
  @[byteChoices(basePoint), byteChoices(vec1U), byteChoices(vec2U)]

proc ristrettoDecodeSeeds*(): seq[seq[ChoiceNode]] =
  ## RFC-004 slice 8a. All 16 RFC 9496 Appendix A.1 encodings (the
  ## multiples 0..15 of the canonical generator -- ristretto255's own
  ## already-verified-canonical accept-boundary vectors, the same role
  ## `pointDecodeSeeds`'s three RFC 8032 public keys play above), PLUS a
  ## few Appendix A.2 invalid encodings, one from each reject category
  ## (non-canonical field encoding, negative field element, non-square
  ## x^2, negative x*y, and the s = -1 / y = 0 degenerate case). A.1 seeds
  ## the accept side of the boundary; the A.2 handful seeds the reject
  ## side from real near-miss structure (a non-canonical/non-square/
  ## negative encoding one bit-flip away from a valid one) rather than
  ## leaving the reject side to be found only by drifting there from
  ## random mutation, mirroring `test_ristretto.nim`'s own A.1/A.2
  ## transcription (values re-derived here independently, not imported,
  ## since this file has no import of `sello/*` or the test tree).
  const
    a1_0: array[32, byte] = [
      0x00'u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00'u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00'u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00'u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]
    a1_1: array[32, byte] = [
      0xe2'u8, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71,
      0xa8'u8, 0x84, 0xa9, 0x61, 0xc5, 0x00, 0x51, 0x5f,
      0x58'u8, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d,
      0xb6'u8, 0xa6, 0x59, 0x45, 0xe0, 0x8d, 0x2d, 0x76,
    ]
    a1_2: array[32, byte] = [
      0x6a'u8, 0x49, 0x32, 0x10, 0xf7, 0x49, 0x9c, 0xd1,
      0x7f'u8, 0xec, 0xb5, 0x10, 0xae, 0x0c, 0xea, 0x23,
      0xa1'u8, 0x10, 0xe8, 0xd5, 0xb9, 0x01, 0xf8, 0xac,
      0xad'u8, 0xd3, 0x09, 0x5c, 0x73, 0xa3, 0xb9, 0x19,
    ]
    a1_3: array[32, byte] = [
      0x94'u8, 0x74, 0x1f, 0x5d, 0x5d, 0x52, 0x75, 0x5e,
      0xce'u8, 0x4f, 0x23, 0xf0, 0x44, 0xee, 0x27, 0xd5,
      0xd1'u8, 0xea, 0x1e, 0x2b, 0xd1, 0x96, 0xb4, 0x62,
      0x16'u8, 0x6b, 0x16, 0x15, 0x2a, 0x9d, 0x02, 0x59,
    ]
    a1_4: array[32, byte] = [
      0xda'u8, 0x80, 0x86, 0x27, 0x73, 0x35, 0x8b, 0x46,
      0x6f'u8, 0xfa, 0xdf, 0xe0, 0xb3, 0x29, 0x3a, 0xb3,
      0xd9'u8, 0xfd, 0x53, 0xc5, 0xea, 0x6c, 0x95, 0x53,
      0x58'u8, 0xf5, 0x68, 0x32, 0x2d, 0xaf, 0x6a, 0x57,
    ]
    a1_5: array[32, byte] = [
      0xe8'u8, 0x82, 0xb1, 0x31, 0x01, 0x6b, 0x52, 0xc1,
      0xd3'u8, 0x33, 0x70, 0x80, 0x18, 0x7c, 0xf7, 0x68,
      0x42'u8, 0x3e, 0xfc, 0xcb, 0xb5, 0x17, 0xbb, 0x49,
      0x5a'u8, 0xb8, 0x12, 0xc4, 0x16, 0x0f, 0xf4, 0x4e,
    ]
    a1_6: array[32, byte] = [
      0xf6'u8, 0x47, 0x46, 0xd3, 0xc9, 0x2b, 0x13, 0x05,
      0x0e'u8, 0xd8, 0xd8, 0x02, 0x36, 0xa7, 0xf0, 0x00,
      0x7c'u8, 0x3b, 0x3f, 0x96, 0x2f, 0x5b, 0xa7, 0x93,
      0xd1'u8, 0x9a, 0x60, 0x1e, 0xbb, 0x1d, 0xf4, 0x03,
    ]
    a1_7: array[32, byte] = [
      0x44'u8, 0xf5, 0x35, 0x20, 0x92, 0x6e, 0xc8, 0x1f,
      0xbd'u8, 0x5a, 0x38, 0x78, 0x45, 0xbe, 0xb7, 0xdf,
      0x85'u8, 0xa9, 0x6a, 0x24, 0xec, 0xe1, 0x87, 0x38,
      0xbd'u8, 0xcf, 0xa6, 0xa7, 0x82, 0x2a, 0x17, 0x6d,
    ]
    a1_8: array[32, byte] = [
      0x90'u8, 0x32, 0x93, 0xd8, 0xf2, 0x28, 0x7e, 0xbe,
      0x10'u8, 0xe2, 0x37, 0x4d, 0xc1, 0xa5, 0x3e, 0x0b,
      0xc8'u8, 0x87, 0xe5, 0x92, 0x69, 0x9f, 0x02, 0xd0,
      0x77'u8, 0xd5, 0x26, 0x3c, 0xdd, 0x55, 0x60, 0x1c,
    ]
    a1_9: array[32, byte] = [
      0x02'u8, 0x62, 0x2a, 0xce, 0x8f, 0x73, 0x03, 0xa3,
      0x1c'u8, 0xaf, 0xc6, 0x3f, 0x8f, 0xc4, 0x8f, 0xdc,
      0x16'u8, 0xe1, 0xc8, 0xc8, 0xd2, 0x34, 0xb2, 0xf0,
      0xd6'u8, 0x68, 0x52, 0x82, 0xa9, 0x07, 0x60, 0x31,
    ]
    a1_10: array[32, byte] = [
      0x20'u8, 0x70, 0x6f, 0xd7, 0x88, 0xb2, 0x72, 0x0a,
      0x1e'u8, 0xd2, 0xa5, 0xda, 0xd4, 0x95, 0x2b, 0x01,
      0xf4'u8, 0x13, 0xbc, 0xf0, 0xe7, 0x56, 0x4d, 0xe8,
      0xcd'u8, 0xc8, 0x16, 0x68, 0x9e, 0x2d, 0xb9, 0x5f,
    ]
    a1_11: array[32, byte] = [
      0xbc'u8, 0xe8, 0x3f, 0x8b, 0xa5, 0xdd, 0x2f, 0xa5,
      0x72'u8, 0x86, 0x4c, 0x24, 0xba, 0x18, 0x10, 0xf9,
      0x52'u8, 0x2b, 0xc6, 0x00, 0x4a, 0xfe, 0x95, 0x87,
      0x7a'u8, 0xc7, 0x32, 0x41, 0xca, 0xfd, 0xab, 0x42,
    ]
    a1_12: array[32, byte] = [
      0xe4'u8, 0x54, 0x9e, 0xe1, 0x6b, 0x9a, 0xa0, 0x30,
      0x99'u8, 0xca, 0x20, 0x8c, 0x67, 0xad, 0xaf, 0xca,
      0xfa'u8, 0x4c, 0x3f, 0x3e, 0x4e, 0x53, 0x03, 0xde,
      0x60'u8, 0x26, 0xe3, 0xca, 0x8f, 0xf8, 0x44, 0x60,
    ]
    a1_13: array[32, byte] = [
      0xaa'u8, 0x52, 0xe0, 0x00, 0xdf, 0x2e, 0x16, 0xf5,
      0x5f'u8, 0xb1, 0x03, 0x2f, 0xc3, 0x3b, 0xc4, 0x27,
      0x42'u8, 0xda, 0xd6, 0xbd, 0x5a, 0x8f, 0xc0, 0xbe,
      0x01'u8, 0x67, 0x43, 0x6c, 0x59, 0x48, 0x50, 0x1f,
    ]
    a1_14: array[32, byte] = [
      0x46'u8, 0x37, 0x6b, 0x80, 0xf4, 0x09, 0xb2, 0x9d,
      0xc2'u8, 0xb5, 0xf6, 0xf0, 0xc5, 0x25, 0x91, 0x99,
      0x08'u8, 0x96, 0xe5, 0x71, 0x6f, 0x41, 0x47, 0x7c,
      0xd3'u8, 0x00, 0x85, 0xab, 0x7f, 0x10, 0x30, 0x1e,
    ]
    a1_15: array[32, byte] = [
      0xe0'u8, 0xc4, 0x18, 0xf7, 0xc8, 0xd9, 0xc4, 0xcd,
      0xd7'u8, 0x39, 0x5b, 0x93, 0xea, 0x12, 0x4f, 0x3a,
      0xd9'u8, 0x90, 0x21, 0xbb, 0x68, 0x1d, 0xfc, 0x33,
      0x02'u8, 0xa9, 0xd9, 0x9a, 0x2e, 0x53, 0xe6, 0x4e,
    ]
    a2NonCanonical0: array[32, byte] = [
      0x00'u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff'u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff'u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff'u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ]
    a2NegativeFieldElement0: array[32, byte] = [
      0x01'u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00'u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00'u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00'u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]
    a2NonSquareXSq0: array[32, byte] = [
      0x26'u8, 0x94, 0x8d, 0x35, 0xca, 0x62, 0xe6, 0x43,
      0xe2'u8, 0x6a, 0x83, 0x17, 0x73, 0x32, 0xe6, 0xb6,
      0xaf'u8, 0xeb, 0x9d, 0x08, 0xe4, 0x26, 0x8b, 0x65,
      0x0f'u8, 0x1f, 0x5b, 0xbd, 0x8d, 0x81, 0xd3, 0x71,
    ]
    a2NegativeXY0: array[32, byte] = [
      0x3e'u8, 0xb8, 0x58, 0xe7, 0x8f, 0x5a, 0x72, 0x54,
      0xd8'u8, 0xc9, 0x73, 0x11, 0x74, 0xa9, 0x4f, 0x76,
      0x75'u8, 0x5f, 0xd3, 0x94, 0x1c, 0x0a, 0xc9, 0x37,
      0x35'u8, 0xc0, 0x7b, 0xa1, 0x45, 0x79, 0x63, 0x0e,
    ]
    a2SMinusOneYZero0: array[32, byte] = [
      0xec'u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff'u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff'u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff'u8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
    ]
  @[
    byteChoices(a1_0), byteChoices(a1_1), byteChoices(a1_2), byteChoices(a1_3),
    byteChoices(a1_4), byteChoices(a1_5), byteChoices(a1_6), byteChoices(a1_7),
    byteChoices(a1_8), byteChoices(a1_9), byteChoices(a1_10), byteChoices(a1_11),
    byteChoices(a1_12), byteChoices(a1_13), byteChoices(a1_14), byteChoices(a1_15),
    byteChoices(a2NonCanonical0), byteChoices(a2NegativeFieldElement0),
    byteChoices(a2NonSquareXSq0), byteChoices(a2NegativeXY0),
    byteChoices(a2SMinusOneYZero0),
  ]

# ---------------------------------------------------------------------------
# Run + report
# ---------------------------------------------------------------------------

const
  MinEdgesGate* = 50
    ## RFC-002 slice 3 item 1's smoke gate: "an edge count an order of
    ## magnitude above the old 1-2". Calibrated against real 20s/target
    ## campaign runs of this exact harness during development: observed
    ## 291-350 edges per target (pointDecode/verify/x25519), ~150x the
    ## retired in-process harness's 2-edge ceiling. 50 is set well below
    ## that observed floor (comfortable headroom for run-to-run variance
    ## in a short smoke-sized campaign, e.g. `scripts/fuzz.sh 15`) while
    ## still being unambiguous evidence real SanitizerCoverage guidance
    ## is happening, not a saturated/black-box run.

proc runExternalTarget*[T](name: string; strat: Strategy[T];
                            encode: proc(x: T): seq[byte];
                            targetBin: string; seconds: int; seedVal: uint64;
                            corpusSeeds: seq[seq[ChoiceNode]] = @[]) =
  echo "=== fuzzing ", name, " (", seconds, "s budget, external SanitizerCoverage target) ==="
  doAssert fileExists(targetBin),
    "external fuzz target binary not found: " & targetBin &
    " -- scripts/fuzz.sh must build it before running this driver"

  var frontier = newCoverageFrontier()
  let target = externalTarget[T](
    argv = @[targetBin],
    delivery = stdinDelivery(),
    oracle = signalOracle[T](),
    limits = ResourceLimits(perRunTimeout: initDuration(seconds = 2)),
    encode = encode)

  var settings = FuzzSettings(
    timeBudget: initDuration(seconds = seconds),
    seed: seedVal,
    mutationMode: fmIR,
    initialIRCorpus: corpusSeeds)
  let report = fuzz(strat, target, frontier, settings)

  # B2: a preloaded seed that fails to replay against this target's own
  # strategy shape (`captureIR`'s `ok: false` path in `fuzz.nim`) would
  # otherwise be silently dropped -- exactly the kind of quiet coverage
  # loss this whole feature exists to avoid. A nonzero count here means
  # `byteChoices`/`listChoices` above have drifted from the strategy's
  # real draw shape (e.g. a `bytes(minLen, maxLen)` bound changed) and is
  # a build-time bug, not a run-to-run fuzzing variance.
  if report.droppedSeeds > 0:
    echo "  !!! ", report.droppedSeeds, " preloaded corpus seed(s) DROPPED for ", name,
         " (seed encoding no longer matches the strategy's draw shape) !!!"
    quit(1)
  if corpusSeeds.len > 0:
    echo "  corpus seeds preloaded: ", corpusSeeds.len, " (0 dropped)"

  let corpusSize = case report.corpus.kind
                   of fckIR: report.corpus.irEntries.len
                   of fckBytes: report.corpus.byteEntries.len
  echo "  iterations:        ", report.iterations
  echo "  coverage edges hit: ", report.coverageHits
  echo "  corpus size:        ", corpusSize
  echo "  crashes found:      ", report.irCrashes.len
  echo "  time budget hit:    ", report.timedOut

  if report.irCrashes.len > 0:
    echo "  !!! CRASH FOUND in ", name, " !!!"
    for i, c in report.irCrashes:
      echo "    [", i, "] ", c.message
    quit(1)

  if report.coverageHits < MinEdgesGate:
    echo "  !!! COVERAGE GATE FAILED for ", name, ": ", report.coverageHits,
         " edges < required minimum ", MinEdgesGate, " !!!"
    quit(1)
