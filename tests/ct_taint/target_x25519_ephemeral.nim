## tests/ct_taint/target_x25519_ephemeral.nim -- RFC-005 slice 21 (A1).
## Taint target for the `X25519EphemeralSecret` role: `x25519Base(secret:
## X25519EphemeralSecret)` (SCALAR tainted, public u-coordinate output
## declassified at return, sharing `diX25519BasePublicKey` with the
## static overload -- see `x25519.x25519Base`'s own doc comment) and the
## CONSUMING `x25519(secret: sink X25519EphemeralSecret; peer)` overload
## (SCALAR tainted, OR-accumulated all-zero verdict declassified via
## `diX25519ZeroVerdict`, shared with the static role's overload -- see
## that DeclassId's own doc comment).
##
## **Harness-side cast route (A1's own text, stated):** `X25519EphemeralSecret`
## has no from-bytes constructor and a private field -- the only way to
## get one is fresh from `std/sysrand` via `x25519EphemeralSecret()`. To
## taint it, this target reaches past the public API with a raw pointer
## cast to the type's own one-field byte representation (the type is a
## plain, non-inheriting, single-`array[32, byte]`-field object, so a
## `ptr array[32, byte]` at the object's own address aliases that field
## exactly) and marks it undefined retroactively, simulating "this
## freshly-generated scalar is secret" for the harness's own purposes --
## the one place this harness reaches past the API, per `private/
## taint.nim`'s own module doc.
##
## `-d:x25519SmallOrderPeer` selects the small-order-peer verdict arm (the
## all-zero RFC 7748 u=0 point, order 1) instead of the default
## normal-peer arm -- both verdict arms per A1's own "definition of done".
##
## The zero-annotation red->green arc is driven the same way every other
## target in this directory documents (see `target_sign.nim`'s own header
## comment for the full writeup): `scripts/ct-taint.sh` runs this SAME,
## unmodified file against the real pre-/post-declassify states of
## `src/sello/x25519.nim`.
##
## The normal-peer arm's `X25519Shared` output is the boundary-rule case
## (A1's own text): declassified via the harness-side `markDefined`, NOT
## a registered `DeclassId` -- see `target_x25519_static.nim`'s own
## header comment for the identical reasoning.
import std/options
import sello/x25519
import sello/private/taint

var secret = x25519EphemeralSecret()
markUndefined(cast[ptr array[32, byte]](addr secret)[])

let pub = x25519Base(secret)
  ## Calls the real, shipped `declassify(diX25519BasePublicKey, pub)`
  ## call site inside `x25519Base` (GREEN state only).
checkDefined(toBytes(pub))
echo "target_x25519_ephemeral: derived public u-coordinate first byte = ", toBytes(pub)[0]

when defined(x25519SmallOrderPeer):
  # All-zero -- RFC 7748's u=0 small-order point (order 1).
  var peerBytes: array[32, byte]
  let peer = toX25519Public(peerBytes)
else:
  var otherBytes: array[32, byte]
  for i in 0 ..< 32: otherBytes[i] = byte(97 - i)
  let otherSecret = toX25519StaticSecret(otherBytes)
  let peer = x25519Base(otherSecret)

# `secret` was already referenced above (the cast/addr, and the
# x25519Base borrow), so the consuming call below needs the explicit
# `move()` idiom -- see x25519(sink X25519EphemeralSecret, ...)'s own
# doc comment for the full empirical Nim-ownership writeup this
# cross-references.
let shared = x25519(move(secret), peer)
  ## Calls the real, shipped `declassify(diX25519ZeroVerdict, acc)` call
  ## site immediately before the branch that reads `acc` (GREEN state
  ## only).

when defined(x25519SmallOrderPeer):
  doAssert shared.isNone, "expected the small-order peer arm to yield none"
  echo "target_x25519_ephemeral(small-order peer): none, as expected"
else:
  doAssert shared.isSome, "expected the normal peer arm to yield some"
  var sharedBytes = toBytes(shared.get())
  markDefined(sharedBytes)
  checkDefined(sharedBytes)
  echo "target_x25519_ephemeral(normal peer): shared secret first byte = ", sharedBytes[0]

echo "target_x25519_ephemeral: diX25519BasePublicKey exercises = ", exerciseCount(diX25519BasePublicKey)
echo "target_x25519_ephemeral: diX25519ZeroVerdict exercises = ", exerciseCount(diX25519ZeroVerdict)
