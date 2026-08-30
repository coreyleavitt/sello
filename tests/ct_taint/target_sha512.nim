## tests/ct_taint/target_sha512.nim -- RFC-005 slice 21 (A1). Taint
## target for `private/sha512.sha512` (the one-shot production face):
## MESSAGE tainted, DIGEST declassified for the harness's own KAT-style
## inspection -- the inverted disclosure class the Stage-3 schema
## proof-spike (slice 19) drafted, promoted to a live target this slice.
##
## **`diSha512DigestKat` declassified HERE, at this call site, not inside
## `sha512.sha512` itself** -- see that function's own doc comment (and
## `private/taint.nim`'s register entry) for why: `sha512` is reused for
## genuinely secret-derivation hashing inside `backend.derivePublic`/
## `signDetached` (already exercised, undeclassified at that internal
## level, by `target_sign.nim`), so an interior declassify inside
## `sha512` itself would silently un-taint those secret intermediates.
## This target's own message is intentionally test data whose digest is
## meant to be inspected, so declassifying this target's OWN copy here is
## the sanctioned, correct place -- `sha512`/`compress` has no interior
## branch of its own to protect (pure ARX), so nothing is lost by
## declassifying after the call returns.
##
## Exercises all three one-shot overloads (1-, 2-, and 3-buffer), the
## same shapes `backend.nim`'s own seed hash / nonce hash / `challenge`
## calls use internally (with different call sites, per the reasoning
## above).
import sello/private/sha512
import sello/private/taint

var msg1: array[64, byte]
for i in 0 ..< 64: msg1[i] = byte(i * 3 + 1)
markUndefined(msg1)

var digest1 = sha512(msg1)
declassify(diSha512DigestKat, digest1)
checkDefined(digest1)
echo "target_sha512: 1-arg digest first byte = ", digest1[0]

var msgA: array[16, byte]
var msgB: array[16, byte]
for i in 0 ..< 16:
  msgA[i] = byte(i * 5 + 2)
  msgB[i] = byte(i * 7 + 3)
markUndefined(msgA)
markUndefined(msgB)

var digest2 = sha512(msgA, msgB)
declassify(diSha512DigestKat, digest2)
checkDefined(digest2)
echo "target_sha512: 2-arg digest first byte = ", digest2[0]

var msgC: array[8, byte]
for i in 0 ..< 8: msgC[i] = byte(i * 13 + 5)
markUndefined(msgC)

var digest3 = sha512(msgA, msgB, msgC)
declassify(diSha512DigestKat, digest3)
checkDefined(digest3)
echo "target_sha512: 3-arg digest first byte = ", digest3[0]

echo "target_sha512: diSha512DigestKat exercises = ", exerciseCount(diSha512DigestKat)
