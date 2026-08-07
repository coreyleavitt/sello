## Google Wycheproof adversarial vectors for ed25519 verification
## (project Wycheproof / C2SP testvectors_v1, eddsa_verify schema).
##
## Every malleable, non-canonical, truncated, or forged signature in the
## set must be rejected; every valid one must verify. This is the
## adversarial half of the validation bar (RFC 8032 vectors are the
## functional half).
##
## JSON parsing lives in `wycheproof_vectors.nim` (round-3 fix batch B,
## finding B1) -- shared with `test_libsodium_interop.nim`'s differential
## suite, which walks this same typed vector list against libsodium's own
## verifier instead of (or in addition to) the `expectedValid` this file
## checks.

import std/unittest
import sello
import ./wycheproof_vectors

const rawVectors = staticRead("../vectors/ed25519_test.json")

suite "Wycheproof ed25519 verify":
  test "all vectors give the expected verdict":
    let vectors = loadEd25519Vectors(rawVectors)
    var checked = 0
    var failures = 0
    for v in vectors:
      # A signature is 64 bytes by definition; anything else is rejected
      # before it can reach verify's fixed-size API.
      var got = false
      if v.sig.len == 64:
        var sigArr: array[64, byte]
        for i in 0 ..< 64: sigArr[i] = v.sig[i]
        got = verify(toPublicKey(v.pk), v.msg, toSignature(sigArr))

      if got != v.expectedValid:
        inc failures
        echo "  MISMATCH tcId=", v.tcId,
             " expected=", v.expectedValid, " got=", got,
             " comment=", v.comment
      inc checked

    check failures == 0
    check checked == vectors.len
