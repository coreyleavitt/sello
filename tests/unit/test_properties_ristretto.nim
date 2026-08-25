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
##
## RFC-004 slice 6 adds `ristrettoFromUniformBytes`'s determinism and
## valid-output properties (`randomBytes64`, a plain total generator with no
## internal retry loop -- unlike `randomRistrettoPoints()` above, it needs no
## special coverage-guided-engine handling).

import std/[unittest, options]
import proptest
import sello/ristretto
import sello/field
import sello/scalar
import ./property_crank

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
  ##
  ## `n` routed through `cranked()` (RFC-005 slice 26) BEFORE computing
  ## `maxRejections`, not after -- the rejection budget must scale with
  ## the CRANKED example count, or a cranked run would exhaust its
  ## rejection headroom well before reaching its (now larger) target
  ## `maxExamples`. See tests/unit/property_crank.nim.
  let nCranked = cranked(n)
  result = defaultSettings()
  result.maxExamples = nCranked
  result.maxRejections = max(1000, nCranked * 64)
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
  ##
  ## `n` routed through `cranked()` the same way `settingsWithExamples`
  ## does, immediately above (RFC-005 slice 26) -- see
  ## tests/unit/property_crank.nim.
  let nCranked = cranked(n)
  result = defaultSettings()
  result.maxExamples = nCranked
  result.maxRejections = max(1000, nCranked * 64)
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

# ---------------------------------------------------------------------------
# Equality-operator consistency with encoding equality (docs/rfc-004-
# ristretto255.md's Validation battery "Properties" bullet promises this one
# by name -- "equality-operator consistency with encoding equality" -- but it
# was never implemented; this closes that gap). `RistrettoPoint`'s `==` is
# the CT quotient-equality check (RFC 9496 SS4.3.3's cross-product test);
# `RistrettoEncoded`'s `==` (reached here via `toBytes`) is the ordinary
# vartime byte-compare on the canonical encoding -- see ristretto.nim's own
# module doc comment for why the two live in different CT registers. They
# must still always AGREE on the same verdict: two representations name the
# same group element (`==` true) iff their canonical encodings are byte-
# identical (`toBytes(ristrettoEncode(_)) ==` true), since encoding IS
# choosing the one canonical representative per RFC 9496 SS4.3.2.
# ---------------------------------------------------------------------------

proc randomCanonicalScalarBytes(): Strategy[array[32, byte]] =
  ## Random CANONICAL (< L) scalar bytes, via wide-reduction (`scReduce`)
  ## of a uniformly random 64-byte draw -- the same route
  ## `ristrettoStaticSecret()`/`toRistrettoStaticSecretWide` use internally,
  ## so this generator draws from the type's own invariant domain (always
  ## a canonical residue mod L) rather than from raw unreduced bytes, which
  ## `toRistrettoStaticSecret` would reject roughly `1 - L/2^256` of the
  ## time (astronomically rare, but the wide-reduce route is both correct
  ## and total, so there is no reason to court that rejection at all).
  arrays[64, byte](randByte()).map(proc(wide: array[64, byte]): array[32, byte] =
    scReduce(result, wide))

suite "ristretto property: equality-operator consistency with encoding equality":
  property "(p == q) == (toBytes(encode(p)) == toBytes(encode(q))), for independently drawn random points":
    with pointPropertySettings50
    given p in randomRistrettoPoints(), q in randomRistrettoPoints()
    ensure (p == q) == (toBytes(ristrettoEncode(p)) == toBytes(ristrettoEncode(q)))

  property "equal case: p == p (a copy) and (a+b)G == aG + bG (a differently-derived representation of the same element) both agree with encoding equality":
    with propertySettings50
    given aBytes in randomCanonicalScalarBytes(), bBytes in randomCanonicalScalarBytes()
    # p == p via a plain copy -- the trivial equal case.
    let pA = ristrettoUnchecked(geScalarmultBase(toSecretScalar(aBytes)))
    let pCopy = pA
    ensure (pA == pCopy) == (toBytes(ristrettoEncode(pA)) == toBytes(ristrettoEncode(pCopy)))
    ensure pA == pCopy
    # p == p via two genuinely different derivations of the SAME element:
    # (a+b)G computed directly by one scalarmult (`scMulAdd(aBytes, 1, bBytes)`
    # reduces a+b mod L in one step) vs aG + bG computed as two independent
    # scalarmults combined by the group operator -- exercising `==`'s
    # cross-product check against non-degenerate, differently-z-scaled
    # representations, not just an aliased copy of the same `GeP3`.
    let pB = ristrettoUnchecked(geScalarmultBase(toSecretScalar(bBytes)))
    var one: array[32, byte]
    one[0] = 1
    let sumBytes = scMulAdd(aBytes, toSecretScalar(one), toSecretScalar(bBytes))
    let viaScalarmult = ristrettoUnchecked(geScalarmultBase(toSecretScalar(sumBytes)))
    let viaAddition = pA + pB
    ensure (viaScalarmult == viaAddition) ==
      (toBytes(ristrettoEncode(viaScalarmult)) == toBytes(ristrettoEncode(viaAddition)))
    ensure viaScalarmult == viaAddition

suite "ristretto property: ristrettoScalarmultBase / ristrettoScalarmultVartime agreement":
  property "ristrettoScalarmultBase(secret) == ristrettoScalarmultVartime(secret.toBytes, RistrettoBasePoint)":
    with propertySettings50
    given bytes in randomCanonicalScalarBytes()
    let secretOpt = toRistrettoStaticSecret(bytes)
    ensure secretOpt.isSome
    let secret = secretOpt.get()
    ensure ristrettoScalarmultBase(secret) == ristrettoScalarmultVartime(toBytes(secret), RistrettoBasePoint)

# ---------------------------------------------------------------------------
# ristrettoScalarmult -- CT variable-base three-way agreement (RFC-004
# slice 7a): geScalarmultCT vs scalarmultVartime over a random point, and
# (at the base point specifically) vs geScalarmultBase too.
# ---------------------------------------------------------------------------

suite "ristretto property: ristrettoScalarmult (CT variable-base) agreement":
  property "ristrettoScalarmult(secret, p) == ristrettoScalarmultVartime(secret.toBytes, p), for random secret and random point":
    with pointPropertySettings50
    given bytes in randomCanonicalScalarBytes(), p in randomRistrettoPoints()
    let secretOpt = toRistrettoStaticSecret(bytes)
    ensure secretOpt.isSome
    let secret = secretOpt.get()
    ensure ristrettoScalarmult(secret, p) == ristrettoScalarmultVartime(toBytes(secret), p)

  property "ristrettoScalarmult(secret, RistrettoBasePoint) == ristrettoScalarmultBase(secret), for random secret (three-way agreement at the base point)":
    with propertySettings50
    given bytes in randomCanonicalScalarBytes()
    let secretOpt = toRistrettoStaticSecret(bytes)
    ensure secretOpt.isSome
    let secret = secretOpt.get()
    ensure ristrettoScalarmult(secret, RistrettoBasePoint) == ristrettoScalarmultBase(secret)

# ---------------------------------------------------------------------------
# ristrettoFromUniformBytes -- determinism and valid-output (RFC-004 slice 6,
# RFC 9496 SS4.3.4). `randomBytes64` is total (a plain `arrays[64, byte]`
# draw, no `.filter()`), so `propertySettings50`'s coverage-guided default is
# safe here -- unlike `randomRistrettoPoints()`, this generator has no
# internal retry loop for the coverage-guided engine to get lost around (see
# `settingsForPoints`'s doc comment above for that empirically-required
# exception).
# ---------------------------------------------------------------------------

proc randomBytes64(): Strategy[array[64, byte]] =
  arrays[64, byte](randByte())

suite "ristretto property: ristrettoFromUniformBytes":
  property "determinism: the same 64-byte input maps to equal points":
    with propertySettings50
    given bytes in randomBytes64()
    let p1 = ristrettoFromUniformBytes(bytes)
    let p2 = ristrettoFromUniformBytes(bytes)
    ensure p1 == p2

  property "valid output: the result always re-decodes to itself (the map is total)":
    with propertySettings50
    given bytes in randomBytes64()
    let p = ristrettoFromUniformBytes(bytes)
    let decoded = ristrettoDecode(ristrettoEncode(p))
    ensure decoded.isSome
    ensure decoded.get() == p
