## tests/ct_taint/target_ristretto_ephemeral.nim -- RFC-005 slice 21 (A1).
## Taint target for the `RistrettoEphemeralSecret` role's consuming call,
## `ristrettoScalarmult(secret: sink RistrettoEphemeralSecret; p):
## Option[RistrettoShared]`: SCALAR tainted (harness-side cast, the same
## route `target_x25519_ephemeral.nim` documents in full -- not repeated
## here), OR-accumulated all-zero identity-encoding verdict declassified
## via `diRistrettoEphemeralZeroVerdict`.
##
## `-d:ristrettoIdentityPeer` selects the degenerate-peer verdict arm
## (`p = RistrettoIdentity`, so `S = k*identity = identity` for any `k` --
## RFC 9496 SS4.3.2's canonical identity encoding is exactly 32 zero
## bytes) instead of the default normal-peer arm -- both verdict arms per
## A1's own "definition of done".
##
## The `RistrettoShared` output on the normal-peer arm is the
## boundary-rule case: declassified via the harness-side `markDefined`,
## NOT a registered `DeclassId` -- see `target_x25519_static.nim`'s own
## header comment for the identical reasoning.
##
## `ristrettoScalarmultBase(secret)` (the non-consuming borrow, `C1` in
## the type's own ElGamal-style doc comment) is exercised first, ahead of
## the consuming call, matching the real protocol shape the type exists
## to serve -- `secret` therefore needs `move()` at the consuming call
## below (an earlier reference already touched it), the same empirical
## Nim-ownership requirement `x25519(sink X25519EphemeralSecret, ...)`'s
## own doc comment documents in full.
import std/options
import sello/ristretto
import sello/private/taint

var secret = ristrettoEphemeralSecret()
markUndefined(cast[ptr array[32, byte]](addr secret)[])

let c1 = ristrettoScalarmultBase(secret)
discard c1  # C1, sent alongside the ciphertext in the real protocol shape -- not itself under test here (no interior branch/declassify of its own; see stRistrettoScalarmultBase's own register entry).

when defined(ristrettoIdentityPeer):
  let peer = RistrettoIdentity
else:
  let peer = RistrettoBasePoint

let shared = ristrettoScalarmult(move(secret), peer)
  ## Calls the real, shipped
  ## `declassify(diRistrettoEphemeralZeroVerdict, acc)` call site
  ## immediately before the branch that reads `acc` (GREEN state only).

when defined(ristrettoIdentityPeer):
  doAssert shared.isNone, "expected the identity-peer arm to yield none"
  echo "target_ristretto_ephemeral(identity peer): none, as expected"
else:
  doAssert shared.isSome, "expected the normal peer arm to yield some"
  var sharedBytes = toBytes(shared.get())
  markDefined(sharedBytes)
  checkDefined(sharedBytes)
  echo "target_ristretto_ephemeral(normal peer): shared secret first byte = ", sharedBytes[0]

echo "target_ristretto_ephemeral: diRistrettoEphemeralZeroVerdict exercises = ", exerciseCount(diRistrettoEphemeralZeroVerdict)
