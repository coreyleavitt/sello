## tests/ct_taint/target_ristretto_scalarmult.nim -- RFC-005 slice 21
## (A1). Taint target for the static-secret ristretto255 group ops:
## `ristrettoScalarmultBase(secret: RistrettoStaticSecret)`,
## `ristrettoScalarmult(secret: RistrettoStaticSecret; p)`,
## `ristrettoEncode`, and `` `==` `` -- SCALAR/coordinates tainted.
##
## `toRistrettoStaticSecretWide` builds the secret INSIDE this target from
## raw 64-byte input, mirroring `tests/ct/ct_main.nim`'s own
## `opRistrettoScalarmult` construction (TOTAL, no reject-vs-accept
## branch) -- genuinely exercising that constructor too (see this
## target's own register entry, `stToRistrettoStaticSecretWide`, `taint:
## ckCoveredBy(stRistrettoScalarmultStatic)`).
##
## **`diRistrettoEncodeOutput` declassified HERE, at this call site, not
## inside `ristretto.ristrettoEncode` itself** -- see that function's own
## doc comment (and `private/taint.nim`'s register entry) for why: this
## target's own point is genuinely public (about to be published/
## inspected), so declassifying its own copy of the encoding here is the
## sanctioned, correct place, since `ristrettoEncode` has no interior
## branch of its own to protect.
##
## `` `==` ``'s own interior `declassify(diRistrettoEqualVerdict, ...)`
## call site DOES fire inside the library (it has no ephemeral-secret-path
## reuse conflict the way `ristrettoEncode` does), exercised below by
## comparing the scalarmultBase and scalarmult results against themselves.
import sello/ristretto
import sello/private/taint

var secretBytes: array[64, byte]
for i in 0 ..< 64: secretBytes[i] = byte(i * 3 + 5)
markUndefined(secretBytes)
let secret = toRistrettoStaticSecretWide(secretBytes)

let basePt = ristrettoScalarmultBase(secret)
var baseEnc = toBytes(ristrettoEncode(basePt))
declassify(diRistrettoEncodeOutput, baseEnc)
checkDefined(baseEnc)
echo "target_ristretto_scalarmult: scalarmultBase encoding first byte = ", baseEnc[0]

let varPt = ristrettoScalarmult(secret, RistrettoBasePoint)
var varEnc = toBytes(ristrettoEncode(varPt))
declassify(diRistrettoEncodeOutput, varEnc)
checkDefined(varEnc)
echo "target_ristretto_scalarmult: scalarmult encoding first byte = ", varEnc[0]

let selfEqual = basePt == basePt
  ## Calls the real, shipped `declassify(diRistrettoEqualVerdict, verdict)`
  ## call site inside `` `==` `` (GREEN state only).
checkDefined(cast[array[1, byte]]([byte(selfEqual)]))
echo "target_ristretto_scalarmult: basePt == basePt -> ", selfEqual

let crossEqual = basePt == varPt
checkDefined(cast[array[1, byte]]([byte(crossEqual)]))
echo "target_ristretto_scalarmult: basePt == varPt -> ", crossEqual

echo "target_ristretto_scalarmult: diRistrettoEncodeOutput exercises = ", exerciseCount(diRistrettoEncodeOutput)
echo "target_ristretto_scalarmult: diRistrettoEqualVerdict exercises = ", exerciseCount(diRistrettoEqualVerdict)
