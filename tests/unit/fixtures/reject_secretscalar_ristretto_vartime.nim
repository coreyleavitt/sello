## Negative-compile fixture (RFC-004 slice 5a): `RistrettoStaticSecret` vs.
## `ristrettoScalarmultVartime`'s type boundary. `ristrettoScalarmultVartime`
## accepts only a plain `array[32, byte]` -- a `RistrettoStaticSecret` (the
## reusable Ristretto secret-scalar role type, `sello/ristretto`) has no
## converter to it, so passing one where a bare scalar array is expected
## must be a compile error -- the same `scalar.SecretScalar`-vs-
## `scalarmultVartime` register (`reject_secretscalar_vartime.nim`), reused
## for this module's own secret role.
##
## Deliberately invalid, same methodology as
## `reject_secretscalar_vartime.nim`: an ordinary type mismatch that
## `compiles()` can already see at the semantic-checking stage, included as
## a subprocess fixture for consistency with this directory's established
## methodology and as a literal pinned compiler diagnostic.
import std/options
import sello/ristretto

let secretOpt = toRistrettoStaticSecret(default(array[32, byte]))
let secret = secretOpt.get()
discard ristrettoScalarmultVartime(secret, RistrettoBasePoint)
