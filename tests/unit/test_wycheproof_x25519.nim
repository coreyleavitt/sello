## Google Wycheproof adversarial vectors for X25519
## (project Wycheproof / C2SP testvectors_v1, xdh_comp schema).
##
## Semantics: every vector's shared secret must match, including the
## "acceptable" twist and non-canonical-public cases (X25519 is defined
## on all inputs). Vectors flagged ZeroSharedSecret have a small-order
## public key; sello's x25519 must return none for exactly those.

import std/[unittest, json, strutils, options]
import sello/x25519

const rawVectors = staticRead("../vectors/x25519_test.json")

proc fromHex32(s: string): array[32, byte] =
  doAssert s.len == 64
  for i in 0 ..< 32:
    result[i] = byte(parseHexInt(s[2 * i .. 2 * i + 1]))

suite "Wycheproof X25519":
  test "all vectors give the expected shared secret":
    let root = parseJson(rawVectors)
    var checked = 0
    var failures = 0
    for g in root["testGroups"]:
      for t in g["tests"]:
        let tcId = t["tcId"].getInt
        let pub = toX25519Public(fromHex32(t["public"].getStr))
        let priv = toX25519Secret(fromHex32(t["private"].getStr))
        var zeroExpected = false
        for f in t["flags"]:
          if f.getStr == "ZeroSharedSecret": zeroExpected = true

        let got = x25519(priv, pub)
        var ok: bool
        if zeroExpected:
          ok = got.isNone
        else:
          ok = got.isSome and toBytes(got.get) == fromHex32(t["shared"].getStr)

        if not ok:
          inc failures
          echo "  MISMATCH tcId=", tcId, " comment=", t["comment"].getStr
        inc checked

    check failures == 0
    check checked == root["numberOfTests"].getInt
