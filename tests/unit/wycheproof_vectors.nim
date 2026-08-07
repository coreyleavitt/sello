## tests/unit/wycheproof_vectors.nim — shared Wycheproof JSON vector
## loaders (round-3 fix batch B, finding B1).
##
## Extracted out of `test_wycheproof.nim`/`test_wycheproof_x25519.nim`'s
## previously-inline JSON parsing so a third consumer --
## `test_libsodium_interop.nim`'s new differential suites (sello vs.
## libsodium's own verifier/scalarmult over the FULL Wycheproof corpus,
## round-3 B1) -- can walk the identical typed vector list instead of a
## second hand-copied `parseJson`/`hexToBytes` loop that could silently
## drift from the original. Not a test itself (no `unittest` import, no
## `when isMainModule`) and not registered in
## `scripts/lib/unit-test-files.sh` on its own -- it is a leaf library
## module the three test files above `import`.
##
## Deliberately dependency-light: `std/json` + `std/strutils` only, no
## `sello/*` import -- callers decide which sello API (pure verify/x25519,
## or the libsodium adapter) to feed these vectors through.

import std/[json, strutils]

type
  Ed25519Vector* = object
    tcId*: int
    pk*: array[32, byte]
    msg*: seq[byte]
    sig*: seq[byte]
      ## Kept at its raw on-the-wire length (not `array[64, byte]`) --
      ## some Wycheproof vectors are deliberately truncated/oversized
      ## signatures; callers must check `sig.len == 64` before handing
      ## it to a fixed-size 64-byte signature API (both sello's
      ## `Signature` and libsodium's `crypto_sign_verify_detached`, whose
      ## C prototype has no separate siglen parameter at all, require
      ## exactly that).
    expectedValid*: bool
      ## `result == "valid"` per the eddsa_verify schema (Ed25519 vectors
      ## carry no "acceptable" tier).
    comment*: string

  X25519Vector* = object
    tcId*: int
    pub*: array[32, byte]
    priv*: array[32, byte]
    shared*: array[32, byte]
    zeroExpected*: bool
      ## The "ZeroSharedSecret" flag: `priv` is expected to produce an
      ## all-zero (small-order-rejected) shared secret with `pub`.
    comment*: string

proc hexToBytes*(s: string): seq[byte] =
  doAssert s.len mod 2 == 0
  result = newSeq[byte](s.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(s[2 * i .. 2 * i + 1]))

proc hexToArray32*(s: string): array[32, byte] =
  doAssert s.len == 64
  for i in 0 ..< 32:
    result[i] = byte(parseHexInt(s[2 * i .. 2 * i + 1]))

proc loadEd25519Vectors*(raw: string): seq[Ed25519Vector] =
  ## Parses the project-Wycheproof / C2SP `eddsa_verify` schema
  ## (`tests/vectors/ed25519_test.json`). One flattened entry per
  ## `testGroups[].tests[]`, with the group's shared public key folded
  ## into each entry -- the schema nests `pk` at the group level, but a
  ## flat vector list is the shape every consumer here wants.
  let root = parseJson(raw)
  result = @[]
  for g in root["testGroups"]:
    let pkBytes = hexToBytes(g["publicKey"]["pk"].getStr)
    doAssert pkBytes.len == 32
    var pkArr: array[32, byte]
    for i in 0 ..< 32: pkArr[i] = pkBytes[i]

    for t in g["tests"]:
      result.add Ed25519Vector(
        tcId: t["tcId"].getInt,
        pk: pkArr,
        msg: hexToBytes(t["msg"].getStr),
        sig: hexToBytes(t["sig"].getStr),
        expectedValid: t["result"].getStr == "valid",
        comment: t["comment"].getStr)
  doAssert result.len == root["numberOfTests"].getInt

proc loadX25519Vectors*(raw: string): seq[X25519Vector] =
  ## Parses the project-Wycheproof / C2SP `xdh_comp` schema
  ## (`tests/vectors/x25519_test.json`).
  let root = parseJson(raw)
  result = @[]
  for g in root["testGroups"]:
    for t in g["tests"]:
      var zeroExpected = false
      for f in t["flags"]:
        if f.getStr == "ZeroSharedSecret": zeroExpected = true
      result.add X25519Vector(
        tcId: t["tcId"].getInt,
        pub: hexToArray32(t["public"].getStr),
        priv: hexToArray32(t["private"].getStr),
        shared: hexToArray32(t["shared"].getStr),
        zeroExpected: zeroExpected,
        comment: t["comment"].getStr)
  doAssert result.len == root["numberOfTests"].getInt
