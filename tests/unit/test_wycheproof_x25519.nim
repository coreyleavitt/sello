## Google Wycheproof adversarial vectors for X25519
## (project Wycheproof / C2SP testvectors_v1, xdh_comp schema).
##
## Semantics: every vector's shared secret must match, including the
## "acceptable" twist and non-canonical-public cases (X25519 is defined
## on all inputs). Vectors flagged ZeroSharedSecret have a small-order
## public key; sello's x25519 must return none for exactly those.
##
## JSON parsing lives in `wycheproof_vectors.nim` (round-3 fix batch B,
## finding B1) -- shared with `test_libsodium_interop.nim`'s differential
## suite, which walks this same typed vector list against libsodium's own
## `crypto_scalarmult` instead of the fixed `shared`/`zeroExpected` this
## file checks.

import std/[unittest, options]
import sello/x25519
import ./wycheproof_vectors

const rawVectors = staticRead("../vectors/x25519_test.json")

suite "Wycheproof X25519":
  test "all vectors give the expected shared secret":
    let vectors = loadX25519Vectors(rawVectors)
    var checked = 0
    var failures = 0
    for v in vectors:
      let pub = toX25519Public(v.pub)
      let priv = toX25519StaticSecret(v.priv)

      let got = x25519(priv, pub)
      var ok: bool
      if v.zeroExpected:
        ok = got.isNone
      else:
        ok = got.isSome and toBytes(got.get) == v.shared

      if not ok:
        inc failures
        echo "  MISMATCH tcId=", v.tcId, " comment=", v.comment
      inc checked

    check failures == 0
    check checked == vectors.len
