## tests/ct_taint/target_ristretto_from_uniform.nim -- RFC-005 slice 21
## (A1). Taint target for `ristretto.ristrettoFromUniformBytes(b:
## array[64, byte]): RistrettoPoint` (RFC 9496 SS4.3.4 element
## derivation): INPUT tainted -- the RFC's own named curated-annex
## example (an OPRF client's blinding input is exactly this shape).
##
## `ristrettoFromUniformBytes`/`ristrettoMap` are total functions with no
## accept/reject verdict (every step is unconditional straight-line field
## arithmetic plus `feCMove` selects, per `ristrettoMap`'s own doc
## comment) -- there is no interior branch to protect, so (matching
## `ristretto_scalarmult`'s own target) the resulting point's encoding is
## inspected by encoding it and declassifying THIS target's own copy,
## not via an interior call site inside the library.
import sello/ristretto
import sello/private/taint

var uniformBytes: array[64, byte]
for i in 0 ..< 64: uniformBytes[i] = byte(i * 11 + 7)
markUndefined(uniformBytes)

let pt = ristrettoFromUniformBytes(uniformBytes)
var enc = toBytes(ristrettoEncode(pt))
declassify(diRistrettoEncodeOutput, enc)
checkDefined(enc)
echo "target_ristretto_from_uniform: mapped point encoding first byte = ", enc[0]

echo "target_ristretto_from_uniform: diRistrettoEncodeOutput exercises = ", exerciseCount(diRistrettoEncodeOutput)
