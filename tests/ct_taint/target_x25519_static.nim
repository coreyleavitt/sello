## tests/ct_taint/target_x25519_static.nim -- RFC-005 slice 19 (A1), Stage
## 2. Taint target for `x25519.x25519(secret: X25519StaticSecret; peer)`:
## SCALAR tainted, both verdict arms driven (A1's own "per-target
## input-class coverage is part of the definition of done").
##
## `-d:x25519SmallOrderPeer` selects the small-order-peer verdict arm
## (peer = the all-zero RFC 7748 u=0 point, order 1: `ladder(k, 0) == 0`
## for any `k`, so this arm always drives the `none` branch) instead of
## the default normal-peer arm (`some`).
##
## The zero-annotation red->green arc is driven the same way
## `target_sign.nim` documents (its own header comment has the full
## writeup): `scripts/ct-taint.sh` runs this SAME, unmodified file against
## the real pre-declassify and post-declassify states of
## `src/sello/x25519.nim` -- no simulated/reimplemented branch logic here.
##
## The normal-peer arm's `X25519Shared` output is the boundary-rule case
## (A1's own text): declassified via the harness-side `markDefined`, NOT
## a registered `DeclassId` -- disclosing a secret DH output is never
## sanctioned; the harness needs it defined only for its own inspection.
import std/options
import sello/x25519
import sello/private/taint

var secretBytes: array[32, byte]
for i in 0 ..< 32: secretBytes[i] = byte(i * 5 + 17)
markUndefined(secretBytes)
let secret = toX25519StaticSecret(secretBytes)

when defined(x25519SmallOrderPeer):
  # All-zero -- RFC 7748's u=0 small-order point (order 1).
  var peerBytes: array[32, byte]
  let peer = toX25519Public(peerBytes)
else:
  var otherBytes: array[32, byte]
  for i in 0 ..< 32: otherBytes[i] = byte(211 - i)
  let otherSecret = toX25519StaticSecret(otherBytes)
  # A real, non-secret static public key -- guaranteed not small-order (a
  # derived public key is a valid curve point of the expected order).
  let peer = x25519Base(otherSecret)

let shared = x25519(secret, peer)
  ## Calls the real, shipped `declassify(diX25519ZeroVerdict, acc)` call
  ## site immediately before the branch that reads `acc` (GREEN state
  ## only).

when defined(x25519SmallOrderPeer):
  doAssert shared.isNone, "expected the small-order peer arm to yield none"
  echo "target_x25519_static(small-order peer): none, as expected"
else:
  doAssert shared.isSome, "expected the normal peer arm to yield some"
  var sharedBytes = toBytes(shared.get())
  # Boundary rule: harness-side MAKE_MEM_DEFINED on the harness's own
  # copy of the secret DH output, for this target's own inspection --
  # deliberately NOT a registered DeclassId (see this file's own header
  # comment).
  markDefined(sharedBytes)
  checkDefined(sharedBytes)
  echo "target_x25519_static(normal peer): shared secret first byte = ", sharedBytes[0]

echo "target_x25519_static: diX25519ZeroVerdict exercises = ", exerciseCount(diX25519ZeroVerdict)
