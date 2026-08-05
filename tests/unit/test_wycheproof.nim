## Google Wycheproof adversarial vectors for ed25519 verification
## (project Wycheproof / C2SP testvectors_v1, eddsa_verify schema).
##
## Every malleable, non-canonical, truncated, or forged signature in the
## set must be rejected; every valid one must verify. This is the
## adversarial half of the validation bar (RFC 8032 vectors are the
## functional half).

import std/[unittest, json, strutils]
import sello

const rawVectors = staticRead("../vectors/ed25519_test.json")

proc hexToBytes(s: string): seq[byte] =
  doAssert s.len mod 2 == 0
  result = newSeq[byte](s.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(s[2 * i .. 2 * i + 1]))

suite "Wycheproof ed25519 verify":
  test "all vectors give the expected verdict":
    let root = parseJson(rawVectors)
    var checked = 0
    var failures = 0
    for g in root["testGroups"]:
      let pkBytes = hexToBytes(g["publicKey"]["pk"].getStr)
      doAssert pkBytes.len == 32
      var pk: PublicKey
      for i in 0 ..< 32: pk[i] = pkBytes[i]

      for t in g["tests"]:
        let msg = hexToBytes(t["msg"].getStr)
        let sigBytes = hexToBytes(t["sig"].getStr)
        let expected = t["result"].getStr == "valid"

        # A signature is 64 bytes by definition; anything else is
        # rejected before it can reach verify's fixed-size API.
        var got = false
        if sigBytes.len == 64:
          var sig: Signature
          for i in 0 ..< 64: sig[i] = sigBytes[i]
          got = verify(sig, msg, pk)

        if got != expected:
          inc failures
          echo "  MISMATCH tcId=", t["tcId"].getInt,
               " expected=", expected, " got=", got,
               " comment=", t["comment"].getStr
        inc checked

    check failures == 0
    check checked == root["numberOfTests"].getInt
