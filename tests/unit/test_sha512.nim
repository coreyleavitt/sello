## tests/unit/test_sha512.nim — RFC-006 (in-house SHA-512, FIPS 180-4).
##
## Slice 1a landed `cavp_vectors.nim`'s `.rsp` loader coverage (parser
## correctness against hand-written fixtures, then the real vendored NIST
## CAVP corpus) and a shape sanity check on the boundary-digest
## generator's JSON output. Slice 1b (this extension) adds the hash KATs
## against `sello/private/sha512` itself: the CAVP ShortMsg/LongMsg
## sweeps and the padding-boundary cases, both one-shot and incremental,
## per the RFC's slice-1b scope.

import std/[unittest, json, strutils]
import ./cavp_vectors
import ../../src/sello/private/sha512
import ../../src/sello/private/ct

suite "cavp_vectors: Len/Msg/MD loader (hand-written fixture)":
  test "parses records; Len = 0's placeholder Msg = 00 is trimmed to zero bytes":
    const fixture = """# CAVS 11.0
#  "SHA-512 ShortMsg" information
#  SHA-512 tests are configured for BYTE oriented implementations
#  Generated on Tue Mar 15 08:23:49 2011

[L = 64]

Len = 0
Msg = 00
MD = cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e

Len = 8
Msg = 21
MD = 3831a6a6155e509dee59a7f451eb35324d8f8f2df6e3708894740f98fdee23889f4de5adb0c5010dfb555cda77c8ab5dc902094c52de3278f35a75ebc25f093a
"""
    let records = loadShaByteVectors(fixture)
    check records.len == 2

    check records[0].lenBits == 0
    check records[0].msg.len == 0
    check records[0].md == hexToArray64(
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")

    check records[1].lenBits == 8
    check records[1].msg == @[byte(0x21)]
    check records[1].md == hexToArray64(
      "3831a6a6155e509dee59a7f451eb35324d8f8f2df6e3708894740f98fdee23889f4de5adb0c5010dfb555cda77c8ab5dc902094c52de3278f35a75ebc25f093a")

suite "cavp_vectors: Monte Carlo loader (hand-written fixture)":
  test "parses Seed plus COUNT/MD checkpoint pairs, no Msg field":
    # Synthetic hex throughout (repeated-nibble patterns, not real SHA-512
    # output) -- this fixture exercises parsing mechanics only; digest
    # correctness is the real corpus's job (slice 1b's KATs, once
    # `sha512.nim` exists).
    const seedHex = "11".repeat(64)
    const md0Hex = "22".repeat(64)
    const md1Hex = "33".repeat(64)
    const fixture = "# CAVS 11.1\r\n" &
      "#  \"SHA-512 Monte\" information for \"sha_values\"\r\n" &
      "#  SHA-512 tests are configured for BYTE oriented implementations\r\n" &
      "#  Generated on Wed May 11 17:26:11 2011\r\n" &
      "\r\n" &
      "[L = 64]\r\n" &
      "\r\n" &
      "Seed = " & seedHex & "\r\n" &
      "\r\n" &
      "COUNT = 0\r\n" &
      "MD = " & md0Hex & "\r\n" &
      "\r\n" &
      "COUNT = 1\r\n" &
      "MD = " & md1Hex & "\r\n"
    let monte = loadMonteVector(fixture)
    check monte.seed == hexToArray64(seedHex)
    check monte.checkpoints.len == 2
    check monte.checkpoints[0] == hexToArray64(md0Hex)
    check monte.checkpoints[1] == hexToArray64(md1Hex)

suite "cavp_vectors: real CAVP corpus":
  test "SHA512ShortMsg.rsp: 129 records (Len 0..1024 step 8), spot-checked":
    const raw = staticRead("../vectors/SHA512ShortMsg.rsp")
    let records = loadShaByteVectors(raw)
    check records.len == 129
    check records[0].lenBits == 0
    check records[^1].lenBits == 1024

    # Every Len from 0 to 1024 in steps of 8 appears exactly once, in order.
    for i, r in records:
      check r.lenBits == i * 8

    # Spot-check the first record's fields against the literal bytes in
    # the vendored file (SHA-512("") -- also a well-known standalone
    # value, an independent sanity cross-check).
    check records[0].msg.len == 0
    check records[0].md == hexToArray64(
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")

    # Spot-check the Len = 1024 (128-byte) record too.
    check records[^1].msg.len == 128
    check records[^1].md == hexToArray64(
      "a21b1077d52b27ac545af63b32746c6e3c51cb0cb9f281eb9f3580a6d4996d5c9917d2a6e484627a9d5a06fa1b25327a9d710e027387fc3e07d7c4d14c6086cc")

  test "SHA512LongMsg.rsp: 128 records, spot-checked":
    const raw = staticRead("../vectors/SHA512LongMsg.rsp")
    let records = loadShaByteVectors(raw)
    check records.len == 128
    check records[0].lenBits == 1816
    check records[0].msg.len == 227
    check records[0].md == hexToArray64(
      "a9db490c708cc72548d78635aa7da79bb253f945d710e5cb677a474efc7c65a2aab45bc7ca1113c8ce0f3c32e1399de9c459535e8816521ab714b2a6cd200525")

  test "SHA512Monte.rsp: Seed present, 100 checkpoints, spot-checked":
    const raw = staticRead("../vectors/SHA512Monte.rsp")
    let monte = loadMonteVector(raw)
    check monte.seed == hexToArray64(
      "5c337de5caf35d18ed90b5cddfce001ca1b8ee8602f367e7c24ccca6f893802fb1aca7a3dae32dcd60800a59959bc540d63237876b799229ae71a2526fbc52cd")
    check monte.checkpoints.len == 100
    check monte.checkpoints[0] == hexToArray64(
      "ada69add0071b794463c8806a177326735fa624b68ab7bcab2388b9276c036e4eaaff87333e83c81c0bca0359d4aeebcbcfd314c0630e0c2af68c1fb19cc470e")
    check monte.checkpoints[99] == hexToArray64(
      "4aa7dad74eb51d09a6ae7735c4b795b078f51c314f14f42a0d63071e13bdc5fd9f51612e77b36d44567502a3b5eb66c609ec017e51d8df93e58d1a44f3c1e375")

suite "sha512 one-shot: empty message (slice 1b, first RED)":
  test "sha512(\"\") matches the parsed ShortMsg Len=0 KAT":
    const raw = staticRead("../vectors/SHA512ShortMsg.rsp")
    let records = loadShaByteVectors(raw)
    let empty: seq[byte] = @[]
    check sha512(empty) == records[0].md

suite "sha512 one-shot: full CAVP ShortMsg sweep (129 records)":
  test "every ShortMsg record's digest matches sha512(msg)":
    const raw = staticRead("../vectors/SHA512ShortMsg.rsp")
    let records = loadShaByteVectors(raw)
    check records.len == 129
    for r in records:
      check sha512(r.msg) == r.md

suite "sha512 one-shot: full CAVP LongMsg sweep (128 records)":
  test "every LongMsg record's digest matches sha512(msg)":
    const raw = staticRead("../vectors/SHA512LongMsg.rsp")
    let records = loadShaByteVectors(raw)
    check records.len == 128
    for r in records:
      check sha512(r.msg) == r.md

suite "gen_sha512_boundary_vectors.py output (shape only)":
  test "9 entries, one per named padding-boundary length, 64-byte digests":
    const raw = staticRead("../vectors/sha512_boundary_test.json")
    let root = parseJson(raw)
    let vectors = root["vectors"]
    check vectors.len == 9

    const expectedLengths = [0, 1, 111, 112, 127, 128, 129, 239, 240]
    for i in 0 ..< vectors.len:
      let v = vectors[i]
      check v["length"].getInt == expectedLengths[i]
      check v["msg"].getStr.len == expectedLengths[i] * 2
      check v["digest"].getStr.len == 128 # 64 bytes, hex-encoded

type
  BoundaryVector = object
    length: int
    msg: seq[byte]
    digest: array[64, byte]

proc loadBoundaryVectors(): seq[BoundaryVector] =
  const raw = staticRead("../vectors/sha512_boundary_test.json")
  let root = parseJson(raw)
  result = @[]
  for v in root["vectors"]:
    result.add BoundaryVector(
      length: v["length"].getInt,
      msg: hexToBytes(v["msg"].getStr),
      digest: hexToArray64(v["digest"].getStr))

suite "sha512 one-shot: padding-boundary lengths (0,1,111,112,127,128,129,239,240)":
  test "sha512(msg) matches the independent Python hashlib digest at every boundary length":
    for bv in loadBoundaryVectors():
      check sha512(bv.msg) == bv.digest

suite "sha512 streaming: incremental split exactly at padding-boundary thresholds":
  test "init/update/update/finish matches the one-shot digest with the update boundary placed at 0/1/111/112/127/128 wherever that split point fits inside the message":
    # Deliberate boundary placement (RFC-006 slice 1b), not random split-point
    # sampling (that is slice 2's nelli job) -- these candidates are
    # exactly the thresholds a buffer-fill-off-by-one bug would hide behind.
    const candidateSplits = [0, 1, 111, 112, 127, 128]
    for bv in loadBoundaryVectors():
      for p in candidateSplits:
        if p <= bv.length:
          var ctx: Sha512Context
          ctx.init()
          ctx.update(bv.msg[0 ..< p])
          ctx.update(bv.msg[p ..< bv.length])
          var digest: array[64, byte]
          ctx.finish(digest)
          check digest == bv.digest

suite "sha512 one-shot: 2-arg/3-arg agreement with the concatenated 1-arg call":
  test "sha512(a, b) == sha512(a & b)":
    let cases: seq[(seq[byte], seq[byte])] = @[
      (newSeq[byte](0), newSeq[byte](0)),
      (@[byte(1), 2, 3], newSeq[byte](0)),
      (newSeq[byte](0), @[byte(9), 8, 7]),
      (@[byte(0xAA), 0xBB], @[byte(0xCC), 0xDD, 0xEE]),
      (newSeq[byte](130), @[byte(0x01)]), # crosses a block boundary
    ]
    for (a, b) in cases:
      check sha512(a, b) == sha512(a & b)

  test "sha512(a, b, c) == sha512(a & b & c)":
    let cases: seq[(seq[byte], seq[byte], seq[byte])] = @[
      (newSeq[byte](0), newSeq[byte](0), newSeq[byte](0)),
      (@[byte(1)], newSeq[byte](0), @[byte(2)]),
      (newSeq[byte](0), @[byte(5), 6], newSeq[byte](0)),
      (newSeq[byte](111), @[byte(0xFF)], newSeq[byte](20)), # crosses a block boundary
    ]
    for (a, b, c) in cases:
      check sha512(a, b, c) == sha512(a & b & c)

suite "sha512 streaming: init-after-finish reuse (supported per the type's contract)":
  test "reusing a context via init after finish produces correct digests for two distinct messages in sequence":
    var ctx: Sha512Context
    var d1, d2: array[64, byte]

    ctx.init()
    ctx.update(@[byte(0x61), 0x62, 0x63]) # "abc"
    ctx.finish(d1)

    ctx.init()
    ctx.update(@[byte(0x64), 0x65, 0x66]) # "def"
    ctx.finish(d2)

    check d1 == sha512(@[byte(0x61), 0x62, 0x63])
    check d2 == sha512(@[byte(0x64), 0x65, 0x66])
    check d1 != d2

suite "sha512 Monte Carlo (SHAVS chain, RFC-006 slice 2)":
  test "all 100 checkpoints match, per SHAVS: MDi = sha512(MDi-3, MDi-2, MDi-1), 1000 inner steps per checkpoint, reseeded between checkpoints":
    # All 100 checkpoints run unconditionally, by default -- the RFC's
    # named fallback (a 10-checkpoint default prefix behind
    # -d:selloSha512MonteFull) is a contingency for exceeding the current
    # slowest standing unit file's debug runtime, measured at slice-2
    # implementation time and recorded in the handoff: the full 100-
    # checkpoint chain (100,000 sequential sha512(a, b, c) calls, the
    # three-part production one-shot) adds roughly 1.5-2s over this file's
    # own no-Monte baseline (~3.4s), nowhere near
    # test_properties_ristretto.nim's ~125s (the slowest standing unit
    # test file at measurement time) -- so the contingency does not
    # trigger and no ifdef split is needed.
    const raw = staticRead("../vectors/SHA512Monte.rsp")
    let monte = loadMonteVector(raw)
    var md0 = monte.seed
    var md1 = monte.seed
    var md2 = monte.seed
    for j in 0 ..< 100:
      for i in 0 ..< 1000:
        let mdNext = sha512(md0, md1, md2)
        md0 = md1
        md1 = md2
        md2 = mdNext
      check md2 == monte.checkpoints[j]
      # SHAVS reseed: MD0 = MD1 = MD2 = the just-verified checkpoint value,
      # before the next outer round's 1000 inner iterations begin.
      md0 = md2
      md1 = md2

suite "sha512 context hygiene: smoke test (full test_ct.nim migration is slice 3's job)":
  test "ct.wipe zeroes an entire Sha512Context, whole-object byte scan":
    var ctx: Sha512Context
    ctx.init()
    ctx.update(@[byte(1), 2, 3, 4, 5])
    ct.wipe(ctx)
    let bytes = cast[ptr UncheckedArray[byte]](addr ctx)
    for i in 0 ..< sizeof(Sha512Context):
      check bytes[i] == 0
