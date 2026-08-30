## tests/ct_taint/target_sign.nim -- RFC-005 slice 19 (A1), Stage 2. Taint
## target for `signing.keypair`/`signing.sign` (which route through
## `private/backend.derivePublic`/`signDetached`): SEED tainted.
##
## The zero-annotation red->green arc (A1's own text: "run the target
## with no declassifications first -- the harness MUST error at every
## documented disclosure point") is driven by `scripts/ct-taint.sh`
## running THIS SAME, unmodified file against two different states of
## `src/sello/private/backend.nim` -- the real pre-declassify commit (RED:
## the interior branches/return-copies inside `derivePublic`/
## `signDetached` read `result` while it is still undefined, since no
## `declassify` call has cleared it) and the real post-declassify commit
## (GREEN: this repository's shipped state). This is the actual historical
## arc, not a simulation: no separate "-d:undeclassified" flag or
## reimplemented branch logic in this file, so what the harness measures
## is genuinely the library's own compiled code either way. See
## `scripts/ct-taint.sh`'s own header comment for the exact git-stash
## mechanics and `docs/rfc-005-validation-infra.handoff.md`'s slice 19
## entry for the recorded transcripts.
import sello/signing
import sello/wire
import sello/private/taint

var seedBytes: array[32, byte]
for i in 0 ..< 32: seedBytes[i] = byte(i * 7 + 11)
markUndefined(seedBytes)

let kp = keypair(toSeed(seedBytes))
  ## Calls `backend.derivePublic` -- the real, shipped `declassify(diDerivePublicKey, result)`
  ## call site fires here (GREEN state only).

let pubBytes = toBytes(kp.public())
checkDefined(pubBytes)
echo "target_sign: derived public key first byte = ", pubBytes[0]

let msg = [byte(1), 2, 3, 4, 5]
let sig = sign(kp, msg)
  ## Calls `backend.signDetached` -- the real, shipped
  ## `declassify(diSignDetachedSignature, result)` call site fires here
  ## (GREEN state only).

let sigBytes = toBytes(sig)
checkDefined(sigBytes)
echo "target_sign: signature first byte = ", sigBytes[0]

echo "target_sign: diDerivePublicKey exercises = ", exerciseCount(diDerivePublicKey)
echo "target_sign: diSignDetachedSignature exercises = ", exerciseCount(diSignDetachedSignature)
