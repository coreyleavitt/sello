## tests/unit/test_sha512.nim — RFC-006 (in-house SHA-512, FIPS 180-4).
##
## Slice 1a scope only: coverage for `cavp_vectors.nim`'s `.rsp` loader
## (parser correctness against hand-written fixtures, then the real
## vendored NIST CAVP corpus) and a shape sanity check on the
## boundary-digest generator's JSON output. No `sello/private/sha512`
## import here yet -- that module does not exist until slice 1b, which
## extends this same file with the hash KATs (per the RFC's own slice
## split: "the parser and the core have independent RED cycles").

import std/[unittest, json, strutils]
import ./cavp_vectors

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

suite "gen_sha512_boundary_vectors.py output (shape only -- no sha512.nim yet)":
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
