## tests/ct_taint/target_x25519_base.nim -- RFC-005 slice 21 (A1). Taint
## target for `x25519.x25519Base(secret: X25519StaticSecret)`: SCALAR
## tainted, public u-coordinate output declassified at return
## (`diX25519BasePublicKey`, the assign-result/declassify/return idiom --
## see `x25519.x25519Base`'s own doc comment).
##
## The zero-annotation red->green arc is driven the same way
## `target_sign.nim`/`target_x25519_static.nim` document (their own header
## comments have the full writeup): `scripts/ct-taint.sh` runs this SAME,
## unmodified file against the real pre-declassify and post-declassify
## states of `src/sello/x25519.nim` -- no simulated/reimplemented branch
## logic here.
import sello/x25519
import sello/private/taint

var secretBytes: array[32, byte]
for i in 0 ..< 32: secretBytes[i] = byte(i * 13 + 3)
markUndefined(secretBytes)
let secret = toX25519StaticSecret(secretBytes)

let pub = x25519Base(secret)
  ## Calls the real, shipped `declassify(diX25519BasePublicKey, pub)`
  ## call site inside `x25519Base` (GREEN state only).

let pubBytes = toBytes(pub)
checkDefined(pubBytes)
echo "target_x25519_base: derived public u-coordinate first byte = ", pubBytes[0]

echo "target_x25519_base: diX25519BasePublicKey exercises = ", exerciseCount(diX25519BasePublicKey)
