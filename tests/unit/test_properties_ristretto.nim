## Property-based coverage for sello/ristretto (RFC-004 slice 3).
##
## See test_properties_field.nim's module doc comment for the proptest
## wiring notes (optional milpa dep, z3-avoidance) -- not repeated here.
##
## Born this slice: `randomRistrettoPoints()`, THE random-element generator
## for every ristretto255 property in this file, this slice and every later
## one (RFC-004's Validation battery "Properties" bullet specifies it once,
## here). Rejection-samples `ristrettoDecode` over uniformly random 32-byte
## strings (~1/16 acceptance, per the RFC) rather than generating points
## through the library's own encode/scalarmult machinery, so this generator
## does not presuppose the correctness of the operations its properties
## exist to test. Available from slice 2 (`ristrettoDecode`) onward -- no
## property here or in a later slice needs to wait on the map or scalarmult
## for its point source.

import std/[unittest, options]
import proptest
import sello/ristretto

proc randByte(): Strategy[byte] =
  integers(0, 255).map(proc(x: int): byte = byte(x))

proc randomBytes32(): Strategy[array[32, byte]] =
  arrays[32, byte](randByte())

proc randomValidEncodings(): Strategy[array[32, byte]] =
  ## Uniformly random 32-byte strings, filtered down to those
  ## `ristrettoDecode` accepts (~1/16 acceptance, per the RFC). Deliberately
  ## NOT derived by encoding a `randomRistrettoPoints()` value (i.e. NOT
  ## `randomRistrettoPoints().map(p => toBytes(ristrettoEncode(p)))`): a
  ## property that checks `ristrettoEncode`'s own behavior must not route
  ## its input generation through `ristrettoEncode` first, or a systematic
  ## encode bug could go uncaught by construction.
  randomBytes32().filter(proc(b: array[32, byte]): bool =
    ristrettoDecode(toRistrettoEncoded(b)).isSome)

proc randomRistrettoPoints(): Strategy[RistrettoPoint] =
  ## THE random-element generator -- see the module doc comment above. On
  ## top of `randomValidEncodings()`, decoding each accepted string into the
  ## `RistrettoPoint` it names.
  randomValidEncodings().map(proc(b: array[32, byte]): RistrettoPoint =
    ristrettoDecode(toRistrettoEncoded(b)).get())

proc settingsWithExamples(n: int): Settings =
  ## `defaultSettings()` (fixed seed, reproducible) with `maxExamples`
  ## dialed per-property (the `test_properties_x25519.nim`/
  ## `test_properties_scalar.nim` precedent) AND `maxRejections` raised well
  ## above the library default (1000): the generators above accept only
  ## ~1/16 of their underlying raw draws, so reaching `n` examples needs
  ## roughly `16*n` total draws' worth of rejection headroom -- the default
  ## cap, sized for near-total-acceptance strategies, would exhaust before
  ## reaching `n` examples past a few dozen. `n * 64` is a comfortable
  ## four-times-expected margin over the ~16*n draws needed.
  result = defaultSettings()
  result.maxExamples = n
  result.maxRejections = max(1000, n * 64)
  result.coverageGuided = true

let propertySettings50 = settingsWithExamples(50)

# ---------------------------------------------------------------------------
# encode/decode round-trips over random elements (RFC 9496 SS4.3.1/SS4.3.2).
# ---------------------------------------------------------------------------

suite "ristretto property: encode/decode round-trips":
  property "encode . decode == id (decode(bytes) |> encode reproduces the canonical bytes)":
    with propertySettings50
    given bytes in randomValidEncodings()
    let decoded = ristrettoDecode(toRistrettoEncoded(bytes))
    ensure decoded.isSome
    ensure toBytes(ristrettoEncode(decoded.get())) == bytes

  property "decode . encode == id (encode(p) |> decode reproduces p)":
    with propertySettings50
    given p in randomRistrettoPoints()
    let decoded = ristrettoDecode(ristrettoEncode(p))
    ensure decoded.isSome
    ensure decoded.get() == p
