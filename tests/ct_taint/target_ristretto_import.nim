## tests/ct_taint/target_ristretto_import.nim -- RFC-005 slice 21 (A1).
## Taint target for `ristretto.toRistrettoStaticSecret(bytes: array[32,
## byte]): Option[RistrettoStaticSecret]`: IMPORT bytes tainted, both
## CANONICAL (accept) and NON-CANONICAL (reject) arms driven via
## `-d:ristrettoImportNonCanonical` (A1's own "both verdict arms"
## definition of done) -- the `scIsCanonicalCT` verdict entry the Stage-3
## schema proof-spike (slice 19) drafted, promoted to a live target this
## slice.
##
## The zero-annotation red->green arc is driven the same way every other
## target in this directory documents: `scripts/ct-taint.sh` runs this
## SAME, unmodified file against the real pre-/post-declassify states of
## `src/sello/ristretto.nim`.
##
## **Genuine design confirmation, caught by an early draft of this
## target:** on the ACCEPT arm, `secret.get()`'s own bytes correctly
## remain TAINTED -- `toRistrettoStaticSecret` declassifies only the
## 1-byte accept/reject VERDICT (`diRistrettoStaticSecretImportReject`),
## never the imported secret scalar itself (that would be a genuine
## boundary-rule violation: `RistrettoStaticSecret` IS secret material,
## same register as the `X25519Shared`/`RistrettoShared` DH-output
## boundary rule). An earlier draft of this file called `checkDefined`
## on the accepted secret's own bytes and correctly turned RED for
## exactly this reason -- not a bug in `toRistrettoStaticSecret`, a
## confirmation that it does NOT leak the caller's import bytes past the
## verdict. This target therefore checks only the verdict path (via
## `isSome`/`isNone`), never the secret's own definedness.
import std/options
import sello/ristretto
import sello/private/taint

when defined(ristrettoImportNonCanonical):
  # All-0xFF is far above L (ristretto255's ~2^252 group order) -- a
  # certain reject.
  var importBytes: array[32, byte]
  for i in 0 ..< 32: importBytes[i] = 0xFF'u8
else:
  # A small, certainly-canonical residue.
  var importBytes: array[32, byte]
  importBytes[0] = 7'u8

markUndefined(importBytes)

let secret = toRistrettoStaticSecret(importBytes)
  ## Calls the real, shipped
  ## `declassify(diRistrettoStaticSecretImportReject, verdict)` call site
  ## immediately before the branch that reads it (GREEN state only).

when defined(ristrettoImportNonCanonical):
  doAssert secret.isNone, "expected the non-canonical arm to reject"
  echo "target_ristretto_import(non-canonical): none, as expected"
else:
  doAssert secret.isSome, "expected the canonical arm to accept"
  echo "target_ristretto_import(canonical): some, as expected"

echo "target_ristretto_import: diRistrettoStaticSecretImportReject exercises = ", exerciseCount(diRistrettoStaticSecretImportReject)
