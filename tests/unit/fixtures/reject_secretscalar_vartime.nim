## Negative-compile fixture (SecretScalar type boundary, round-3 finding
## A3). `scalarmultVartime` accepts only a plain `array[32, byte]` -- a
## `SecretScalar` (the nominal type marking a scalar as secret,
## `sello/scalar`) has no converter to it, so passing one where
## `scalarmultVartime` expects a scalar must be a compile error, not merely
## a naming convention (contrast the pre-A3 state, where nothing but the
## `Vartime` suffix and a doc comment stopped a secret scalar from reaching
## the verify-only vartime path).
##
## Deliberately invalid. Unlike the `=copy`/sink violations elsewhere in
## this directory (which only the later `injectdestructors` pass
## surfaces), a `SecretScalar` argument where `array[32, byte]` is expected
## is an ordinary type mismatch that `compiles()` can already see at the
## semantic-checking stage -- this subprocess fixture exists for
## consistency with this directory's established methodology (and as a
## literal pinned compiler diagnostic), not because `compiles()` is blind
## to this particular error class.
import sello/scalar

var r: GeP3
let secretScalar = toSecretScalar(default(array[32, byte]))
let p = geBasePoint()
scalarmultVartime(r, secretScalar, p)
