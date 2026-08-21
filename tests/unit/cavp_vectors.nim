## tests/unit/cavp_vectors.nim — shared NIST CAVP `.rsp` vector loader
## (RFC-006 slice 1a), `wycheproof_vectors.nim`'s sibling: a line-oriented
## parser for the CAVS/SHAVS response-file format, rather than JSON.
##
## The corpus is TWO record shapes, not one -- ShortMsg/LongMsg's
## `Len`/`Msg`/`MD` triples vs. Monte's single `Seed` plus 100
## `COUNT`/`MD` checkpoint pairs (no `Msg` field at all; Monte inputs are
## chain-derived, never read from the file -- see RFC-006's Design/slice
## 2 for the chain formula) -- so this module is two typed loaders
## sharing low-level hex/line helpers, mirroring
## `wycheproof_vectors.nim`'s `loadEd25519Vectors`/`loadX25519Vectors`
## precedent for a differently-shaped corpus.
##
## Format notes, verified against the real vendored files (not assumed
## from the RFC alone):
## - Lines end CRLF; `#` comment lines, blank lines, and the `[L = 64]`
##   bracket header are all skipped uniformly by both loaders.
## - `Len` is in BITS and is authoritative. The `Len = 0` ShortMsg record
##   carries a placeholder `Msg = 00` (one zero byte) purely so the file
##   format always has a Msg field to print; this loader trims the
##   message to exactly `Len div 8` bytes, so `msg.len == 0` for that
##   record, not 1. A `Len` that is not a multiple of 8 is a parse error
##   (these are byte-oriented vector files, per the CAVP header comment
##   itself, "SHA-512 tests are configured for BYTE oriented
##   implementations").
##
## Error posture mirrors `wycheproof_vectors.nim`: these are trusted
## vendored files, not attacker input, so malformed input fails loudly
## via `doAssert`, not a `Result`/`Option` return.

import std/strutils

type
  ShaByteVector* = object
    lenBits*: int
      ## Length of `msg`, in BITS -- see the Len = 0 / Msg = 00 note
      ## above.
    msg*: seq[byte]
      ## Exactly `lenBits div 8` bytes.
    md*: array[64, byte]

  MonteRecord* = object
    seed*: array[64, byte]
    checkpoints*: seq[array[64, byte]]
      ## checkpoints[i] is COUNT = i's MD, i in 0..99 (100 checkpoints
      ## per SHAVS).

proc hexToBytes*(s: string): seq[byte] =
  doAssert s.len mod 2 == 0, "odd-length hex string: " & s
  result = newSeq[byte](s.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(s[2 * i .. 2 * i + 1]))

proc hexToArray64*(s: string): array[64, byte] =
  doAssert s.len == 128, "expected a 64-byte (128 hex char) digest, got " & $s.len & " chars"
  for i in 0 ..< 64:
    result[i] = byte(parseHexInt(s[2 * i .. 2 * i + 1]))

proc isSkippable(line: string): bool =
  let t = line.strip()
  t.len == 0 or t.startsWith("#") or (t.startsWith("[") and t.endsWith("]"))

proc significantLines(raw: string): seq[string] =
  ## Strips comment/blank/bracket-header lines. `splitLines` already
  ## normalizes CRLF/CR/LF, so no manual `\r` handling is needed here
  ## even though the real vendored files are CRLF (verified with `od`).
  result = @[]
  for line in raw.splitLines():
    if not isSkippable(line): result.add line

proc fieldValue(line, name: string): string =
  ## Splits a "Name = value" line, asserting the field name matches --
  ## fails loudly on anything else, per this module's trusted-input
  ## posture.
  let parts = line.split(" = ", 1)
  doAssert parts.len == 2, "malformed CAVP line (expected 'Name = value'): " & line
  doAssert parts[0].strip() == name,
    "expected a '" & name & "' field, got: " & line
  parts[1].strip()

proc loadShaByteVectors*(raw: string): seq[ShaByteVector] =
  ## Parses the ShortMsg/LongMsg `Len`/`Msg`/`MD` triple format.
  let lines = significantLines(raw)
  result = @[]
  var i = 0
  while i < lines.len:
    let lenBits = parseInt(fieldValue(lines[i], "Len"))
    inc i
    let msgHex = fieldValue(lines[i], "Msg")
    inc i
    let mdHex = fieldValue(lines[i], "MD")
    inc i

    doAssert lenBits mod 8 == 0, "Len not a multiple of 8 bits: " & $lenBits
    let byteLen = lenBits div 8
    var msgBytes = hexToBytes(msgHex)
    doAssert msgBytes.len == byteLen or (byteLen == 0 and msgBytes.len == 1),
      "Msg length (" & $msgBytes.len & " bytes) does not match Len (" &
      $byteLen & " bytes) for record with Len = " & $lenBits
    msgBytes.setLen(byteLen)

    result.add ShaByteVector(lenBits: lenBits, msg: msgBytes, md: hexToArray64(mdHex))

proc loadMonteVector*(raw: string): MonteRecord =
  ## Parses the Monte Carlo `Seed` + 100 `COUNT`/`MD` checkpoint format.
  let lines = significantLines(raw)
  doAssert lines.len >= 1, "empty Monte vector file"
  result.seed = hexToArray64(fieldValue(lines[0], "Seed"))
  result.checkpoints = @[]

  var i = 1
  var expectedCount = 0
  while i < lines.len:
    let count = parseInt(fieldValue(lines[i], "COUNT"))
    doAssert count == expectedCount,
      "COUNT out of sequence: expected " & $expectedCount & ", got " & $count
    inc i
    let mdHex = fieldValue(lines[i], "MD")
    inc i
    result.checkpoints.add hexToArray64(mdHex)
    inc expectedCount
