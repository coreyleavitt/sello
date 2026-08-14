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
import sello/field
import sello/scalar

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
  ## THE random-element generator -- see the module doc comment above.
  ##
  ## Built via `Strategy[RistrettoPoint](run: ...)` directly (the same
  ## low-level constructor `proptest/strategy.filter` itself uses), NOT
  ## `randomValidEncodings().filter(...)`/`.map(...)` (slice 3's original
  ## shape), as of RFC-004 slice 4: `.filter()` raises `Rejection` up to
  ## the engine's OWN per-property `maxRejections` counter on every miss,
  ## which is fine for a property drawing exactly one random point (~1/16
  ## acceptance comfortably fits `settingsWithExamples`'s `n*64` budget --
  ## slice 3's round-trip properties still do this, unchanged), but slice
  ## 4's group-axiom properties draw SEVERAL independent random points in
  ## one `given` clause (associativity's a/b/c, binary minus's a/b); the
  ## DSL composes those into one combined per-example draw, so a `Rejection`
  ## from ANY one of them aborts and retries the WHOLE combined draw --
  ## composing the ~1/16 acceptance rates MULTIPLICATIVELY ((1/16)^3 for
  ## three independent points), which exhausted even a generously
  ## multiplied `maxRejections` budget in practice (round-4 slice-4 TDD
  ## cycle). Looping INSIDE `run` instead means this strategy always
  ## "succeeds" from the engine's perspective -- no `Rejection` ever
  ## propagates out, so combining several of these in one `given` clause
  ## costs no shared rejection budget at all, only this proc's own
  ## constant ~16-draws-per-call retry loop, same as before.
  proc drawOne(src: var DataSource): RistrettoPoint =
    while true:
      let bytes = randomBytes32().run(src)
      let decoded = ristrettoDecode(toRistrettoEncoded(bytes))
      if decoded.isSome:
        return decoded.get()
  Strategy[RistrettoPoint](run: drawOne)

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
  ##
  ## `coverageGuided = true` here (the RFC-002 slice 3 item 3 convention,
  ## every `test_properties_*.nim` file's default): safe for
  ## `randomValidEncodings()` below, the one generator in this file still
  ## built via `.filter()` over a fixed-shape `array[32, byte]` draw. NOT
  ## used for anything drawing `randomRistrettoPoints()` -- see
  ## `settingsForPoints`'s doc comment just below for why that generator
  ## needs a different settings proc entirely.
  result = defaultSettings()
  result.maxExamples = n
  result.maxRejections = max(1000, n * 64)
  result.coverageGuided = true

proc settingsForPoints(n: int): Settings =
  ## The settings proc for every property that draws `randomRistrettoPoints()`
  ## (below): identical to `settingsWithExamples` except `coverageGuided` is
  ## OFF, which is EMPIRICALLY REQUIRED, not a style choice (round-4 slice-4
  ## TDD cycle finding, isolated in a standalone repro before this fix):
  ## proptest's coverage-guided mutation/exploration engine, run against
  ## `randomRistrettoPoints()`'s internal-retry `Strategy.run` (a variable,
  ## data-dependent number of underlying byte-array draws per call, not the
  ## fixed-shape-per-call pattern `arbitrary`/`filter`-composed strategies
  ## have), does not terminate in practical time -- confirmed hung past 90s
  ## wall-clock on a 3-point property even with a hard 5000-iteration-per-
  ## draw cap that was never hit (so the individual retry loop itself was
  ## not the runaway; the coverage-guided engine's OWN exploration around
  ## that generator was), and the SAME property completes in well under a
  ## second with `coverageGuided = false`. `randomValidEncodings()` above
  ## has no such issue (proven by the original slice-3 round-trip
  ## properties, still coverage-guided, unchanged) since its
  ## `.filter()`-over-`arrays[32,byte]` shape is exactly what the
  ## coverage-guided engine's assumptions fit.
  result = defaultSettings()
  result.maxExamples = n
  result.maxRejections = max(1000, n * 64)
  result.coverageGuided = false

let propertySettings50 = settingsWithExamples(50)
let pointPropertySettings50 = settingsForPoints(50)

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
    with pointPropertySettings50
    given p in randomRistrettoPoints()
    let decoded = ristrettoDecode(ristrettoEncode(p))
    ensure decoded.isSome
    ensure decoded.get() == p

# ---------------------------------------------------------------------------
# Group axioms over random elements (RFC-004 slice 4).
# ---------------------------------------------------------------------------

suite "ristretto property: group axioms":
  property "associativity: (a + b) + c == a + (b + c)":
    with pointPropertySettings50
    given a in randomRistrettoPoints(), b in randomRistrettoPoints(), c in randomRistrettoPoints()
    ensure ((a + b) + c) == (a + (b + c))

  property "identity: p + RistrettoIdentity == p":
    with pointPropertySettings50
    given p in randomRistrettoPoints()
    ensure (p + RistrettoIdentity) == p

  property "inverse: p + (-p) == RistrettoIdentity":
    with pointPropertySettings50
    given p in randomRistrettoPoints()
    ensure (p + (-p)) == RistrettoIdentity

  property "binary minus consistent: a - b == a + (-b)":
    with pointPropertySettings50
    given a in randomRistrettoPoints(), b in randomRistrettoPoints()
    ensure (a - b) == (a + (-b))

# ---------------------------------------------------------------------------
# Torsion invariance over random elements (RFC-004 slice 4, Stage-3
# amendment: E[4]-only, not E/E[8] -- see docs/rfc-004-ristretto255.md's
# "Stage-3 amendment (2026-08-14)"). This IS the quotient construction,
# tested directly: for each of the four E[4] points, translating a random
# RistrettoPoint by it must not change the encoding. The deterministic
# two-fixed-point spot check (plus the order-8 NEGATIVE companion pinning
# the [2]E boundary) lives in test_ristretto.nim, which runs even without
# proptest fetched; this is the random-P analog.
# ---------------------------------------------------------------------------

let e4Points = block:
  var negOne, negSqrtM1: Fe
  feNeg(negOne, FeOne)
  feNeg(negSqrtM1, FeSqrtM1)
  [
    RistrettoIdentity,
    ristrettoUnchecked(GeP3(x: FeZero, y: negOne, z: FeOne, t: FeZero)),
    ristrettoUnchecked(GeP3(x: FeSqrtM1, y: FeZero, z: FeOne, t: FeZero)),
    ristrettoUnchecked(GeP3(x: negSqrtM1, y: FeZero, z: FeOne, t: FeZero)),
  ]

suite "ristretto property: E[4] torsion invariance":
  property "encode(P + T) == encode(P), for random P and each of the four E[4] points T":
    with pointPropertySettings50
    given p in randomRistrettoPoints()
    for t in e4Points:
      ensure toBytes(ristrettoEncode(p + t)) == toBytes(ristrettoEncode(p))
