## External SanitizerCoverage fuzz target (RFC-002 slice 3 item 1).
##
## A small stdin-driven binary dispatching sello's three attacker-input
## oracles -- `ed25519.pointDecode`, `ed25519.verify`, and `x25519` over
## the peer's public u-coordinate -- the same scope `fuzz_common.nim`'s
## now-retired in-process `{.cover.}` wrappers covered. This file is
## compiled TWICE with two different purposes:
##
##   1. By `scripts/fuzz.sh`, with SanitizerCoverage instrumentation
##      (`-fsanitize-coverage=trace-pc -fno-pie`) and linked against the
##      vendored, UNFLAGGED `proptest_cov.c` runtime -- the real fuzz
##      target `fuzz_main.nim` drives as a subprocess via proptest's
##      `externalTarget`/`fuzz` (docs/fuzz/USAGE.md's Nim recipe in the
##      `_deps/proptest` checkout).
##   2. By `scripts/check-fuzz-target.sh`-equivalent `nim check` gates,
##      plain, uninstrumented -- this file imports ONLY `sello`'s public
##      verify-path modules, so a plain `nim check -d:release` catches
##      type errors without needing gcc's sancov flags at all.
##
## Wire format (stdin, one run = one process, [INV-fresh-exec]): the
## FIRST byte selects the oracle, the rest is that oracle's payload. An
## empty or too-short payload for the selected mode is a well-formed
## "reject early" input (exit 0), not a crash -- unstructured mutation
## produces truncated inputs constantly and that must never be a
## finding.
##
##   mode 0 (pointDecode): payload[0..31]            -- the encoded point
##   mode 1 (verify):      payload[0..63]  = sig
##                          payload[64..95] = pk
##                          payload[96..^1] = msg (may be empty)
##   mode 2 (x25519):      payload[0..31]            -- peer u-coordinate
##
## Oracle (both directions, RFC-002 slice 3 item 2):
##   - accept implies canonical re-encode (pre-existing direction, kept):
##     pointDecode(b).isSome => feBytesCanonical(pointEncode(pointDecode(b).get))
##   - reject direction, new: not feBytesCanonical(b) => pointDecode(b).isNone
##     (a direct corollary of pointDecode's own first line, but pinned here
##     as an executable invariant a future refactor could silently break)
##   - not scIsCanonical(sig[32..63]) => verify(...) == false (same rationale)
##   - determinism: calling verify (resp. x25519) twice on the identical
##     input yields an identical result -- a cheap, genuinely-free
##     self-consistency check that would catch e.g. uninitialized-memory
##     reads or a stray global mutated by a "pure" verify path.
##   - x25519 returning `some` implies the shared secret is not all-zero
##     (pre-existing check, kept from fuzz_common.nim's old wrapper).
##
## A `doAssert` failure raises `AssertionDefect`, which (unhandled) aborts
## the process (SIGABRT) -- proptest's `signalOracle` maps any terminating
## signal to `vInteresting`, i.e. a retained crash. This target never
## catches exceptions itself: an uncaught `IndexDefect`/`RangeDefect` from
## a bug in the dispatch logic below is exactly as much a finding as an
## assertion failure.
import std/options
import sello/ed25519
import sello/scalar
import sello/field
import sello/x25519

const
  ModePointDecode = 0'u8
  ModeVerify = 1'u8
  ModeX25519 = 2'u8

let localSecretForFuzzing = toX25519StaticSecret([
  1'u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
  17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32])
  ## Fixed, non-secret placeholder scalar -- see fuzz_common.nim's old
  ## copy of this constant (now retired) for the full rationale: the
  ## fuzzed surface is the PEER's public u-coordinate only, so the local
  ## scalar is a constant unstructured mutation never touches, and this
  ## is not a timing-sensitive use (dudect owns that).

proc handlePointDecode(payload: openArray[byte]) =
  if payload.len < 32: return
  var b: array[32, byte]
  for i in 0 ..< 32: b[i] = payload[i]

  let r1 = pointDecode(b)
  let r2 = pointDecode(b)
  doAssert r1.isSome == r2.isSome, "pointDecode nondeterministic (Some/None disagreement)"

  if not feBytesCanonical(b):
    doAssert r1.isNone, "pointDecode accepted a non-canonical encoding"

  if r1.isSome:
    let e1 = pointEncode(r1.get)
    let e2 = pointEncode(r2.get)
    doAssert e1 == e2, "pointDecode nondeterministic (re-encode mismatch)"
    doAssert feBytesCanonical(e1),
      "pointDecode accepted an input whose canonical re-encode isn't canonical"

proc handleVerify(payload: openArray[byte]) =
  if payload.len < 96: return
  var sigBytes: array[64, byte]
  var pkBytes: array[32, byte]
  for i in 0 ..< 64: sigBytes[i] = payload[i]
  for i in 0 ..< 32: pkBytes[i] = payload[64 + i]
  let msg = payload[96 .. ^1]

  let pk = toPublicKey(pkBytes)
  let sig = toSignature(sigBytes)

  let v1 = verify(pk, msg, sig)
  let v2 = verify(pk, msg, sig)
  doAssert v1 == v2, "verify nondeterministic on identical input"

  var sArr: array[32, byte]
  for i in 0 ..< 32: sArr[i] = sigBytes[32 + i]
  if not scIsCanonical(sArr):
    doAssert not v1, "verify accepted a signature with a non-canonical S"

proc handleX25519(payload: openArray[byte]) =
  if payload.len < 32: return
  var peerBytes: array[32, byte]
  for i in 0 ..< 32: peerBytes[i] = payload[i]
  let peer = toX25519Public(peerBytes)

  let r1 = x25519(localSecretForFuzzing, peer)
  let r2 = x25519(localSecretForFuzzing, peer)
  doAssert r1.isSome == r2.isSome, "x25519 nondeterministic (Some/None disagreement)"

  if r1.isSome:
    let s1 = toBytes(r1.get)
    let s2 = toBytes(r2.get)
    doAssert s1 == s2, "x25519 nondeterministic (shared-secret mismatch)"
    var acc: byte = 0
    for b in s1: acc = acc or b
    doAssert acc != 0'u8, "x25519 returned Some(...) with an all-zero shared secret"

proc readAllStdinBytes(): seq[byte] =
  let s = stdin.readAll()
  result = newSeq[byte](s.len)
  for i in 0 ..< s.len: result[i] = byte(s[i])

when isMainModule:
  let data = readAllStdinBytes()
  if data.len < 1:
    quit(0)
  let mode = data[0]
  let payload = data[1 .. ^1]
  case mode
  of ModePointDecode: handlePointDecode(payload)
  of ModeVerify: handleVerify(payload)
  of ModeX25519: handleX25519(payload)
  else: discard  # unrecognized mode byte: well-formed reject, not a finding
  quit(0)
