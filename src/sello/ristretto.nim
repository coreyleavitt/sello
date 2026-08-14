## sello/ristretto — the ristretto255 prime-order group (RFC 9496)
##
## Quotients the Edwards curve's cofactor-8 subgroup down to a genuine
## prime-order group: every `RistrettoPoint` names one element of that
## group, with exactly one canonical 32-byte encoding, closing the
## cofactor-malleability class of bug that a raw `scalar.GeP3` invites
## (small-order components, non-unique encodings). Builds on
## `sello/field` + `sello/scalar` only -- never `ed25519.nim` (the
## verify-only module), `challenge.nim`, a signing backend, or nimcrypto.
## A sibling of `x25519.nim` in the layering: below `ed25519.nim`/
## `signing.nim`, above the field/curve core, with its own types living
## here rather than in `wire.nim` (the `x25519.nim` precedent -- no
## second module needs to share them yet).
##
## **The CT posture (load-bearing, read this before adding an
## operation):** decode, encode, equality, and the one-way map are all CT
## BY CONSTRUCTION -- straight-line field arithmetic plus `feCMove`-based
## selects, no secret-dependent branch or array index anywhere in their
## bodies. Scope of that claim, stated once here rather than re-litigated
## per operation: the final accept/reject VERDICT (decode's `none`,
## `==`'s result) is inherently CALLER-VISIBLE and carries no CT
## obligation of its own -- what is branch-free is everything computed ON
## THE WAY to that verdict, not the single branch that returns it. This
## follows RFC 9496 directly: ristretto255 group elements are routinely
## *derived from* secrets in the protocols this module exists to serve
## (a Pedersen commitment before publication, an OPRF blinded element, a
## DH share) even though the encoding eventually goes on the wire, so
## "verify-only, no CT requirement" (this codebase's `ed25519.verify`
## posture) does not apply here the way it does there.
##
## **Full v1 surface (RFC-004 slices 1a-8d, this file is complete as of
## slice 8d):** `RistrettoPoint`/`RistrettoEncoded` and their basic borrows,
## the `ristrettoUnchecked` construction door (module-internal only, never
## facade-exported), quotient `==`, `ristrettoDecode`, `ristrettoEncode`
## plus its `InvSqrtAMinusD` constant, the fixed
## `RistrettoIdentity`/`RistrettoBasePoint` consts, the group operators
## `+`/binary `-`/unary `-` (this codebase's first operators -- see their
## own doc comments for the canonical-spacing note), the reusable static
## secret-scalar role (`RistrettoStaticSecret`, the
## `x25519.X25519StaticSecret` shape -- copyable, self-wiping, always a
## canonical residue mod L) and its scalarmults
## (`ristrettoScalarmultBase`/`ristrettoScalarmultVartime`/
## `ristrettoScalarmult`, the last one CT variable-base over
## `scalar.geScalarmultCT` -- the operation that makes this group usable
## for OPRF evaluation, Pedersen commitments, and DH shares, where the
## point IS secret-derived even though the group element itself carries no
## CT hygiene of its own), the single-use ephemeral secret role
## (`RistrettoEphemeralSecret`, the `x25519.X25519EphemeralSecret` shape --
## move-only, fresh-only, no `toBytes`) with its borrow-only
## `ristrettoScalarmultBase` overload and its own CONSUMING
## `ristrettoScalarmult(sink RistrettoEphemeralSecret, ...)` overload (the
## `x25519.x25519(sink X25519EphemeralSecret, ...)` precedent, reused
## verbatim, pinned by
## `tests/unit/fixtures/reject_ristretto_ephemeral_reuse.nim`), the one-way
## hash-to-group map (RFC 9496 SS4.3.4: `ristrettoFromUniformBytes`, its
## private `ristrettoMap` helper, and the three remaining SS4.1
## implementation constants `OneMinusDSq`/`DMinusOneSq`/`SqrtAdMinusOne` --
## `InvSqrtAMinusD` landed with encode). Facade-exported (slice 8d) as the
## ENUMERATED symbol list in `src/sello.nim` -- see that module's doc
## comment; `ristrettoUnchecked` and `scalar.SecretScalar` are deliberately
## NOT among them. `RistrettoPoint` has deliberately no `wipe` overload
## even now that every scalarmult is present: see its own doc comment
## below.
##
## **The scalar-arithmetic boundary (Schnorr / OPRF-client honesty):** this
## module ships the GROUP -- decode/encode/equality/the map/group
## ops/scalarmult -- and nothing that does mod-L arithmetic ON an exposed
## scalar. That is enough for commitment/DH/blinding-shaped protocols
## (Pedersen commit/open, ElGamal/ECIES-style encryption, an OPRF SERVER's
## evaluation step -- one CT scalarmult each) but NOT for protocols whose
## secret math goes further: a Schnorr response `s = k + c*x` needs
## `scalar.scMulAdd`, which exists in this codebase (mutation- and
## dudect-covered, takes `SecretScalar` operands) but stays
## submodule-only, never facade-exported -- exporting it would drag the
## bare, hygiene-free `scalar.SecretScalar` into the public surface,
## exactly what `RistrettoStaticSecret`/`RistrettoEphemeralSecret` exist to
## avoid. An OPRF CLIENT's unblind step needs scalar INVERSION mod L,
## which exists NOWHERE in sello at any layer (`field.feInvert` is mod-p
## field inversion, an unrelated operation). So of the OPRF roles this
## module's motivating protocols repeatedly invoke, v1 fully serves the
## SERVER and cannot serve the CLIENT even by reaching into `scalar.nim`
## directly. This boundary is documented, not implied -- see RFC-004's
## Non-goals section for the full reasoning; a future scalar-arithmetic RFC
## is the closing move, not a silent gap in this one.
##
## **Hash-the-encoding, not the point:** there is deliberately no
## `hash(RistrettoPoint)`. A hash must agree with `==`, and hashing any
## particular internal `GeP3` representation would diverge from quotient
## equality (two different-looking representations of the SAME element
## must hash the same, which only the canonical encoding guarantees).
## Key/dedupe on `RistrettoEncoded` (encode first), never on the point.
##
## **Encode-then-compare silently downgrades CT to vartime:** `==` on
## `RistrettoPoint` is CT; `==` on `RistrettoEncoded` is the ordinary
## `wire.nim`-style vartime byte-compare (an operator cannot carry a
## `Vartime` suffix, so this register switch is silent at the call site).
## The two predicates can never disagree ON VALUE (RFC 9496's encoding is
## unique per element), only on TIMING -- so the rule, stated outright:
## compare `RistrettoPoint`s directly in any timing-sensitive position;
## calling `ristrettoEncode` on both sides first (the natural move for a
## caller about to serialize anyway) silently trades CT equality for
## vartime. See `RistrettoEncoded`'s own doc comment for the full writeup.

import std/[hashes, options, sysrand]
import sello/field
import sello/scalar
import sello/private/ct
import sello/private/secret_hooks

## Compiler-enforced effect contract (janus consumer finding 3) -- see
## `signing.nim`'s module doc for the surface-wide policy.
{.push raises: [], gcsafe.}

# ---------------------------------------------------------------------------
# RistrettoPoint
# ---------------------------------------------------------------------------

type
  RistrettoPoint* = object
    ## One ristretto255 group element. Wraps a `scalar.GeP3` (extended
    ## Edwards coordinates), field PRIVATE: the invariant this type
    ## carries is "was produced by decode, the map, the constants, or a
    ## group operation on one of those" -- never built from raw
    ## coordinates by application code. `ristrettoUnchecked` below is the
    ## one audited exception.
    ##
    ## Freely copyable, no destructor, and (see the module doc above) no
    ## `wipe` overload -- deliberately, not an oversight. Elements are
    ## PUBLIC-register values in every protocol this type serves: the
    ## published group element is never itself the secret, the secret is
    ## the scalar that derived it (a blinding factor, an OPRF key, a DH
    ## exponent), and CT hygiene belongs on THAT scalar's role type and
    ## the scalarmult that consumes it -- not here. An "unpublished
    ## intermediate" (a Pedersen commitment before it is sent, an OPRF
    ## blinded element before the response) does not need wiping either:
    ## it is hiding/blinding BY CONSTRUCTION, so the point value alone
    ## reveals nothing without the scalar. A `wipe(var RistrettoPoint)`
    ## would also carry a silently WEAKER contract than every sibling
    ## `wipe` in this codebase: each of those is an early-wipe
    ## accelerant in front of a `=destroy` net that cleans up regardless,
    ## so "forgetting wipe costs timing, not correctness" is a trained
    ## reflex from the rest of this API -- misapplying it here (a
    ## freely-copyable type with no destructor backstop) would mean
    ## forgetting, or copying, leaves the value never-wiped, full stop.
    p: GeP3

func ristrettoUnchecked*(p: GeP3): RistrettoPoint {.inline.} =
  ## The one audited door onto `RistrettoPoint` from a raw `GeP3` (the
  ## `field.feFromLimbs` precedent -- a narrow, documented exception to
  ## "never construct by hand"). Legitimate callers are limited to: this
  ## module's own constructors and group operations (decode today; encode,
  ## the map, and `+`/`-` in later slices, all of which compute a `GeP3`
  ## internally and need to wrap it), and `tests/unit/test_ristretto.nim`'s
  ## white-box oracles -- slice 2's independent decode-correctness check
  ## against `scalar.geScalarmultBase`-computed multiples of the
  ## generator, and (a later slice) torsion-point construction. Do not
  ## call this from application code: it bypasses every invariant
  ## `RistrettoPoint` is supposed to carry, which is exactly why it is
  ## exported from this module but never re-exported from the `sello`
  ## facade.
  ##
  ## Debug-only (`when not defined(release)`) assert: checks the point is
  ## actually a well-formed extended-coordinate representation --
  ## `X*Y == Z*T` (the extended-coordinate invariant relating T to X, Y,
  ## Z) and the twisted Edwards curve equation itself, `Y^2 - X^2 ==
  ## Z^2 + d*T^2` (the defining equation `-x^2 + y^2 = 1 + d*x^2*y^2`
  ## cleared of denominators via `x = X/Z`, `y = Y/Z`, `X*Y = T*Z`) --
  ## so a typo'd hand-built test point fails loudly instead of silently
  ## entering this layer. Same register as `field.feFromLimbs`'s bounds
  ## assert and `scalar.geScalarmultBase`'s bit-255 assert.
  when not defined(release):
    {.push assertions: on.}
    var xy, zt: Fe
    feMul(xy, p.x, p.y)
    feMul(zt, p.z, p.t)
    assert feEqualCT(xy, zt),
      "ristrettoUnchecked: X*Y != Z*T (not a valid extended-coordinate point)"

    var y2, x2, z2, dt2, lhs, rhs: Fe
    feSq(y2, p.y)
    feSq(x2, p.x)
    feSq(z2, p.z)
    feSq(dt2, p.t)
    feMul(dt2, dt2, feFromLimbs(Ed25519D_Raw))
    feSub(lhs, y2, x2)
    feAdd(rhs, z2, dt2)
    assert feEqualCT(lhs, rhs),
      "ristrettoUnchecked: point does not satisfy the twisted Edwards curve equation"
    {.pop.}
  RistrettoPoint(p: p)

func `==`*(a, b: RistrettoPoint): bool =
  ## RFC 9496 §4.3.3 quotient equality: two internal representations name
  ## the same ristretto255 element iff
  ## `CT_EQ(x1*y2, y1*x2) | CT_EQ(y1*y2, x1*x2)`.
  ##
  ## CT end to end, by design (diverging on purpose from `wire.nim`'s
  ## vartime `==`): protocols compare ristretto255 elements in
  ## timing-sensitive positions this codebase's other `==` operators
  ## never see -- a DH-share or PAKE-style equality check on a value
  ## derived from a live secret, not two `PublicKey` wire blobs being
  ## deduplicated. Both `feEqualCT` comparisons below are ALWAYS
  ## evaluated (no short-circuit skips the second once the first is
  ## known), and combined with a BITWISE or on their `uint8` word
  ## representation -- never Nim's `or` on `bool`, which is a
  ## short-circuiting template (`if x: true else: y`) and would silently
  ## reintroduce exactly the secret-dependent branch this function exists
  ## to avoid, at the one place (the top-level combine) a mutation or
  ## property test cannot see -- it is a timing-only hazard.
  ##
  ## A vartime companion (`==Vartime`, cheaper via two encodes) was
  ## considered and declined: CT equality here is already cheaper than
  ## two encode calls, so unlike the scalarmult family there is no real
  ## vartime speedup on offer to justify the second name.
  var x1y2, y1x2, y1y2, x1x2: Fe
  feMul(x1y2, a.p.x, b.p.y)
  feMul(y1x2, a.p.y, b.p.x)
  feMul(y1y2, a.p.y, b.p.y)
  feMul(x1x2, a.p.x, b.p.x)
  let eq1 = feEqualCT(x1y2, y1x2)
  let eq2 = feEqualCT(y1y2, x1x2)
  bool(uint8(eq1) or uint8(eq2))

# ---------------------------------------------------------------------------
# RistrettoEncoded -- the 32-byte canonical wire form
# ---------------------------------------------------------------------------

type
  RistrettoEncoded* = distinct array[32, byte]
    ## The canonical wire encoding of a `RistrettoPoint` (RFC 9496
    ## §4.3.1/§4.3.2). `distinct array[32, byte]`, with the `wire.nim`-
    ## style borrows below (`toBytes`/`==`/`hash`/`$`/
    ## `toRistrettoEncoded`) -- a public value with no secret to protect,
    ## same reasoning as `wire.PublicKey`/`wire.Signature`.
    ##
    ## **Stronger fact than `Signature`'s malleability caveat:**
    ## ristretto255 encodings are unique PER ELEMENT by construction (the
    ## whole point of the RFC 9496 quotient), so on valid encodings
    ## byte-equality of `RistrettoEncoded` and quotient-equality of
    ## `RistrettoPoint` are PROVABLY THE SAME PREDICATE -- the two `==`
    ## operators can never disagree on VALUE, foreclosing the
    ## dual-equality footgun `Signature`'s doc comment warns about.
    ##
    ## **They DO differ in TIMING register, and this is the trap:**
    ## `RistrettoEncoded`'s `==` below is the `wire.nim` vartime
    ## byte-compare; `RistrettoPoint`'s `==` above is CT. An operator
    ## cannot carry a `Vartime` suffix (the same naming limitation this
    ## module's `+`/`-`/scalarmult design declines `*` for), so the
    ## register switch is silent at the call site. **The rule, stated
    ## outright rather than left implicit: compare `RistrettoPoint`s
    ## directly in any timing-sensitive position; encode-then-compare
    ## silently downgrades a CT comparison to vartime** -- exactly the
    ## natural move a caller about to serialize anyway would reach for.
    ##
    ## No `hash(RistrettoPoint)` exists (see the module doc comment) --
    ## key/dedupe on this type, always encoding first.

func toRistrettoEncoded*(bytes: array[32, byte]): RistrettoEncoded {.inline.} =
  ## Explicit construction from raw bytes (e.g. a value off the wire).
  RistrettoEncoded(bytes)

func toBytes*(e: RistrettoEncoded): array[32, byte] {.inline.} =
  ## Raw bytes back out, e.g. for serialization.
  array[32, byte](e)

func `==`*(a, b: RistrettoEncoded): bool {.borrow.}
  ## Vartime byte-compare -- see `RistrettoEncoded`'s own doc comment for
  ## the CT-downgrade trap this creates if used on a value derived from a
  ## live secret. Compare `RistrettoPoint`s directly in that position.
func `$`*(e: RistrettoEncoded): string {.borrow.}

func hash*(e: RistrettoEncoded): Hash {.inline.} =
  ## Hash of the underlying bytes -- unblocks Table/HashSet keying. No
  ## constant-time requirement, same reasoning as `==` above. There is
  ## deliberately no `hash(RistrettoPoint)`; see the module doc comment.
  hash(array[32, byte](e))

# ---------------------------------------------------------------------------
# InvSqrtAMinusD -- RFC 9496 §4.1 implementation constant
# ---------------------------------------------------------------------------

const InvSqrtAMinusD* = feFromBytes([
  0xea'u8, 0x40, 0x5d, 0x80, 0xaa, 0xfd, 0xc8, 0x99,
  0xbe, 0x72, 0x41, 0x5a, 0x17, 0x16, 0x2f, 0x9d,
  0x40, 0xd8, 0x01, 0xfe, 0x91, 0x7b, 0xc2, 0x16,
  0xa2, 0xfc, 0xaf, 0xcf, 0x05, 0x89, 0x6c, 0x78,
])
  ## RFC 9496 §4.1: `INVSQRT_A_MINUS_D = 1/sqrt(a - d)` where `a = -1` and
  ## `d` is the Curve25519 Edwards `d` parameter -- the correction constant
  ## `ristrettoEncode`'s "enchanted denominator" step below multiplies by.
  ##
  ## Built via the compile-time-`feFromBytes` mechanism the RFC's Operations
  ## section specifies for every new constant it introduces (`field.FeSqrtM1`
  ## and `scalar.Ed25519D_Raw`/`Ed25519Gx_Raw`/`Ed25519Gy_Raw` are the
  ## existing precedent for hand-decomposed-limb constants; this file's
  ## constants instead decode RFC 9496's own published byte encoding, never
  ## a hand radix-converted limb array -- exactly the transcription-risk
  ## avoidance the RFC calls out). `GeBaseTable` in `scalar.nim` already
  ## proves the Nim VM evaluates far heavier compile-time `Fe`/point
  ## arithmetic than this one `feFromBytes` call, empirically confirmed
  ## again here: this file compiles and this constant's own defining-
  ## equation test (`tests/unit/test_ristretto.nim`) passes.
  ##
  ## The 32 bytes above are the little-endian encoding of the decimal value
  ## RFC 9496 §4.1 publishes for `INVSQRT_A_MINUS_D`
  ## (5446930700890931692099581386874514160539359729292745692120531289631172101
  ## 7578) -- the ONE transcribed artifact, per the RFC's own risk register;
  ## everything else (the byte encoding, the field arithmetic) is mechanical
  ## and machine-checked. Cross-checked against its defining equation in
  ## `tests/unit/test_ristretto.nim`: `InvSqrtAMinusD^2 * (a - d) == 1` where
  ## `a = -1` and `d = feFromLimbs(scalar.Ed25519D_Raw)` -- verified
  ## independently (outside this codebase) against the decimal value before
  ## the byte encoding above was derived from it, so the test is a
  ## cross-check of the transcription, not merely of arithmetic closure.

# ---------------------------------------------------------------------------
# ristrettoDecode -- RFC 9496 §4.3.1
# ---------------------------------------------------------------------------

func ristrettoDecode*(e: RistrettoEncoded): Option[RistrettoPoint] =
  ## RFC 9496 §4.3.1 Decode. `none` on any of: a non-canonical field
  ## encoding (>= p), negative `s`, `was_square = false`, negative `t`,
  ## or `y = 0` -- matching `x25519`'s established `Option` register for
  ## "invalid peer input" (`none` on reject, no exception). Consumers
  ## import `std/options` themselves; this module (and, per the existing
  ## convention, the facade once this is re-exported) does not re-export
  ## it.
  ##
  ## CT per this module's headline posture EXCEPT the final verdict: every
  ## field-arithmetic step below runs unconditionally, on every input,
  ## regardless of what the canonicity/sign/square checks will eventually
  ## decide -- no branch depends on secret-shaped data anywhere in the
  ## computation itself. The single `if` at the bottom, deciding `none`
  ## vs. `some`, IS the caller-visible verdict the module doc's carve-out
  ## names: ordinary short-circuiting bool logic there is correct, not a
  ## lapse.
  ##
  ## Canonicity is checked via `feBytesCanonicalCT` -- NEVER the existing
  ## `feBytesCanonical`, which is explicitly vartime (an early-exit
  ## per-byte loop that leaks WHICH byte first diverges) and verify-path
  ## only; using it here would be the same-shaped, adjacent, WRONG-register
  ## helper `field.feBytesCanonicalCT`'s own doc comment names as the trap
  ## an implementer following the `ed25519.pointDecode` precedent-pattern
  ## would naturally reach for instead.
  let bytes = toBytes(e)

  # RFC 9496 §4.3.1 step 1: the encoding must be canonical (< p). CT via
  # feBytesCanonicalCT (see the trap this function's doc comment names).
  let canonical = feBytesCanonicalCT(bytes)

  let s = feFromBytes(bytes)

  # Step 2: negative s rejects.
  let sNegative = feIsNegative(s)

  # Step 3: the decode dance itself (RFC 9496 §4.3.1), computed
  # unconditionally -- see the doc comment above.
  var ss, u1, u2, u2Sqr: Fe
  feSq(ss, s)
  feSub(u1, FeOne, ss)              # u1 = 1 - s^2
  feAdd(u2, FeOne, ss)              # u2 = 1 + s^2
  feSq(u2Sqr, u2)                   # u2_sqr = u2^2

  var u1Sq, dU1Sq, negDu1Sq, v: Fe
  feSq(u1Sq, u1)
  feMul(dU1Sq, feFromLimbs(Ed25519D_Raw), u1Sq)  # D * u1^2
  feNeg(negDu1Sq, dU1Sq)                          # -(D * u1^2)
  feSub(v, negDu1Sq, u2Sqr)                       # v = -(D*u1^2) - u2_sqr

  var vu2Sqr: Fe
  feMul(vu2Sqr, v, u2Sqr)
  let (wasSquare, invsqrt) = feSqrtRatioM1(FeOne, vu2Sqr)

  var denX, denY: Fe
  feMul(denX, invsqrt, u2)           # den_x = invsqrt * u2
  feMul(denY, invsqrt, denX)
  feMul(denY, denY, v)               # den_y = invsqrt * den_x * v

  var twoS, x, y, t: Fe
  feAdd(twoS, s, s)
  feMul(x, twoS, denX)
  feAbs(x)                           # x = CT_ABS(2*s*den_x)
  feMul(y, u1, denY)                 # y = u1 * den_y
  feMul(t, x, y)                     # t = x*y

  # Step 4: the remaining reject conditions.
  let tNegative = feIsNegative(t)
  let yZero = feIsZeroCT(y)

  # The verdict (see the doc comment's CT scope note above).
  if (not canonical) or sNegative or (not wasSquare) or tNegative or yZero:
    return none(RistrettoPoint)

  var p: GeP3
  p.x = x
  p.y = y
  p.z = FeOne
  p.t = t
  some(ristrettoUnchecked(p))

# ---------------------------------------------------------------------------
# ristrettoEncode -- RFC 9496 §4.3.2
# ---------------------------------------------------------------------------

func ristrettoEncode*(pt: RistrettoPoint): RistrettoEncoded =
  ## RFC 9496 §4.3.2 Encode: the torsion-quotienting direction, taking one
  ## internal extended-coordinate representative (x0, y0, z0, t0) of `pt`'s
  ## group element to its unique canonical 32-byte encoding. CT throughout,
  ## per this module's headline posture -- every step below runs
  ## unconditionally, and the two conditional steps the spec itself calls
  ## out (the sqrt(-1) "rotation" and the final sign correction) are
  ## `feCMove` selects, never a branch.
  ##
  ## `i = 0` (the identity) is the degenerate case worth naming explicitly:
  ## `SQRT_RATIO_M1(1, 0)` -- `u1 = (z0+y0)*(z0-y0) = 0` for the identity's
  ## `(0, 1, 1, 0)` representation, so `u1*u2^2 = 0` and `feSqrtRatioM1`
  ## takes its `v = 0, u != 0` branch, returning `(false, 0)`. Every
  ## downstream product involving `invsqrt` collapses to zero, and the
  ## function lands on the all-zero 32-byte encoding -- RFC 9496 Appendix
  ## A.1's own `i=0` vector, and `tests/unit/test_ristretto.nim` pins this
  ## exact path by name rather than leaving it as incidental i=0 coverage.
  let x0 = pt.p.x
  let y0 = pt.p.y
  let z0 = pt.p.z
  let t0 = pt.p.t

  var zPlusY, zMinusY, u1, u2: Fe
  feAdd(zPlusY, z0, y0)
  feSub(zMinusY, z0, y0)
  feMul(u1, zPlusY, zMinusY)          # u1 = (z0 + y0) * (z0 - y0)
  feMul(u2, x0, y0)                   # u2 = x0 * y0

  var u2Sq, u1u2Sq: Fe
  feSq(u2Sq, u2)
  feMul(u1u2Sq, u1, u2Sq)
  let (_, invsqrt) = feSqrtRatioM1(FeOne, u1u2Sq)
    # "Ignore was_square since this is always square" (RFC 9496 §4.3.2) --
    # every valid RistrettoPoint's internal representation makes u1*u2^2 a
    # square by construction, so the accept flag carries no information
    # here; only the root is consumed.

  var den1, den2: Fe
  feMul(den1, invsqrt, u1)            # den1 = invsqrt * u1
  feMul(den2, invsqrt, u2)            # den2 = invsqrt * u2

  var zInv: Fe
  feMul(zInv, den1, den2)
  feMul(zInv, zInv, t0)               # z_inv = den1 * den2 * t0

  var ix0, iy0: Fe
  feMul(ix0, x0, FeSqrtM1)            # ix0 = x0 * SQRT_M1
  feMul(iy0, y0, FeSqrtM1)            # iy0 = y0 * SQRT_M1

  var enchantedDenominator: Fe
  feMul(enchantedDenominator, den1, InvSqrtAMinusD)

  var tZinv: Fe
  feMul(tZinv, t0, zInv)
  let rotate = feIsNegative(tZinv)    # rotate = IS_NEGATIVE(t0 * z_inv)

  # Conditionally rotate x and y (CT_SELECT via feCMove -- no branch).
  var x, y, denInv: Fe
  x = x0
  feCMove(x, iy0, rotate)
  y = y0
  feCMove(y, ix0, rotate)
  denInv = den2
  feCMove(denInv, enchantedDenominator, rotate)

  var xZinv, negY: Fe
  feMul(xZinv, x, zInv)
  feNeg(negY, y)
  feCMove(y, negY, feIsNegative(xZinv))
    # y = CT_SELECT(-y IF IS_NEGATIVE(x * z_inv) ELSE y)

  var zMinusFinalY, s: Fe
  feSub(zMinusFinalY, z0, y)          # z = z0 (unchanged; spec's "z")
  feMul(s, denInv, zMinusFinalY)      # s = den_inv * (z - y)
  feAbs(s)                            # s = CT_ABS(...)

  toRistrettoEncoded(feToBytes(s))

# ---------------------------------------------------------------------------
# Fixed compile-time constants -- the identity and the canonical generator
# ---------------------------------------------------------------------------

const RistrettoIdentity* = ristrettoUnchecked(
  GeP3(x: FeZero, y: FeOne, z: FeOne, t: FeZero))
  ## The ristretto255 group identity. Fixed value, `const` per the codebase
  ## convention for fixed group elements (`x25519.X25519BasePoint`) rather
  ## than a zero-arg constructor proc. Internal representation is the
  ## Edwards identity `(0, 1, 1, 0)` -- one of the eight extended-coordinate
  ## representatives this module's quotient construction treats as the same
  ## ristretto255 element; `ristrettoUnchecked`'s debug-only curve-identity
  ## assert (evaluated here at compile time) confirms it is a well-formed
  ## point before this constant is ever consumed.

const RistrettoBasePoint* = ristrettoUnchecked(geBasePoint())
  ## The ristretto255 canonical generator: internally the SAME `GeP3` as the
  ## RFC 8032 Curve25519 base point `B` (`scalar.geBasePoint()`) -- RFC 9496
  ## §4.1 chooses this generator specifically so implementations can reuse
  ## existing Curve25519 base-point precomputation (`scalar.GeBaseTable`)
  ## for ristretto255 scalar multiplication. Its encoding (checked in
  ## `tests/unit/test_ristretto.nim` against `ristrettoEncode`) is RFC 9496
  ## §3's own published canonical-generator encoding, matching Appendix
  ## A.1's `i=1` vector.

# ---------------------------------------------------------------------------
# Group operators: +, binary -, unary - (slice 4)
#
# This module's -- and the whole codebase's -- FIRST operators (RFC-004's
# Design/Operations note): `RistrettoPoint` is a genuine abelian-group
# public type (unlike `Fe`/`GeP3`, which are internal representations), so
# `+`/`-` are the first-principles notation for it, a deliberate departure
# from this codebase's usual verb-prefixed-proc convention. `*` for scalar
# mult was considered and declined (an operator cannot carry a `Vartime`
# suffix -- see the scalarmult family, a later slice); that reasoning does
# not apply to `+`/`-`, which have no CT/vartime register to silently
# switch.
#
# **Whitespace note, pinned for every example in this file/the README
# (these being the first operators, there is no existing habit to fall
# back on):** write `a - b` and `-p`, WITH a space before a binary `-`'s
# right operand when the left side is a bare identifier that could parse
# as a call -- `a -b` in call position parses as `a(-b)` (unary negation
# applied to `b` first, then `a` called with that result), not the binary
# operator. `a - b` (space on both sides) and `-p` (no left operand) are
# the two unambiguous forms and are what every example below uses.
# ---------------------------------------------------------------------------

func geCachedNegate(q: GeCached): GeCached {.inline.} =
  ## Private: the standard ref10-family cached-point negation, the ONE
  ## place in this file (RFC 9496's group-op slice) that constructs a
  ## negated point -- both operators below route through it, verified
  ## against `scalar.cmovCached`'s own conditional negation (RFC-001),
  ## which performs exactly the same two-step transform on its selected
  ## `GeCached` for negative signed-radix-16 digits: swap `yPlusX`/
  ## `yMinusX` (negating `x` swaps which sum, `y+x` or `y-x`, is which),
  ## negate `t2d`, leave `z` unchanged. `cmovCached` applies this
  ## conditionally (masked, for CT secret-digit selection); this helper
  ## applies it unconditionally, since a `RistrettoPoint` is public
  ## register data with no secret-dependent branch to avoid (see the
  ## module doc's CT-posture headline). `GeCached` -- not `GeP3` -- is
  ## what this module's one addition primitive (`scalar.geAdd`) consumes
  ## as its second operand, so negation stays in that representation
  ## rather than adding a second, GeP3-level negation formula (raw `feNeg`
  ## on `x`/`t`) to this file.
  result.yPlusX = q.yMinusX
  result.yMinusX = q.yPlusX
  result.z = q.z
  feNeg(result.t2d, q.t2d)

func `+`*(a, b: RistrettoPoint): RistrettoPoint =
  ## RFC 9496's group addition on the underlying `GeP3`s: `b` -> `GeCached`
  ## -> `geAdd` -> `geP1P1ToP3` -> wrap through the door -- exactly
  ## `scalarmultVartime`'s own table-build step (`scalar.nim`), applied
  ## here to two arbitrary `RistrettoPoint`s instead of table rows.
  var bCached: GeCached
  geP3ToCached(bCached, b.p)
  var sum: GeP1P1
  geAdd(sum, a.p, bCached)
  var p3: GeP3
  geP1P1ToP3(p3, sum)
  ristrettoUnchecked(p3)

func `-`*(a, b: RistrettoPoint): RistrettoPoint =
  ## Binary subtraction: `a + (-b)`, but computed directly against `b`'s
  ## NEGATED cached form (`geCachedNegate`) rather than by calling the
  ## unary operator below and re-deriving `+` -- the two operators below
  ## are independent implementations sharing only `geCachedNegate`, so the
  ## "a - b == a + (-b)" spot check in `tests/unit/test_ristretto.nim` is a
  ## genuine cross-check of both code paths, not a tautology true by
  ## construction.
  var bCached: GeCached
  geP3ToCached(bCached, b.p)
  let negBCached = geCachedNegate(bCached)
  var diff: GeP1P1
  geAdd(diff, a.p, negBCached)
  var p3: GeP3
  geP1P1ToP3(p3, diff)
  ristrettoUnchecked(p3)

func `-`*(p: RistrettoPoint): RistrettoPoint =
  ## Unary negation: the group inverse of `p`, computed as
  ## `RistrettoIdentity + (-p)` via the SAME `geCachedNegate` helper binary
  ## `-` uses above -- `geAdd(identity, negate(cached(p)))` -- rather than
  ## negating `GeP3`'s raw `x`/`t` coordinates directly (see
  ## `geCachedNegate`'s own doc comment for why negation stays in the
  ## `GeCached` representation).
  var pCached: GeCached
  geP3ToCached(pCached, p.p)
  let negCached = geCachedNegate(pCached)
  var negP1P1: GeP1P1
  geAdd(negP1P1, RistrettoIdentity.p, negCached)
  var negP3: GeP3
  geP1P1ToP3(negP3, negP1P1)
  ristrettoUnchecked(negP3)

# ---------------------------------------------------------------------------
# RistrettoStaticSecret -- the reusable secret-scalar role (RFC-004 slice 5a)
# ---------------------------------------------------------------------------

type
  RistrettoStaticSecret* = object
    ## A reusable ristretto255 secret scalar -- the Pedersen-key/OPRF-
    ## server-key role. One-field object over `array[32, byte]`, NOT
    ## `distinct array[32, byte]`, for the exact empirically-established
    ## reason `signing.Seed`/`x25519.X25519StaticSecret` are: a bare
    ## `distinct array` local's `=destroy` silently never fires under ORC
    ## on Nim 2.2.10 -- see `signing.Seed`'s doc comment for the full
    ## writeup (confirmed there by inspecting the generated C, not
    ## assumed).
    ##
    ## `secretHooks`-instantiated below: `=destroy` wipes via `ct.wipe`,
    ## and -- like `X25519StaticSecret`, unlike `Keypair`/`Seed` -- this
    ## type is deliberately COPYABLE: no `=copy` override, so every copy
    ## carries its own destructor and self-wipes independently at its own
    ## scope exit. Falls under the copyable-self-wiping-holder half of the
    ## move-only-vs-copyable policy `X25519StaticSecret`'s own doc comment
    ## states (round-4 finding R9 on the X25519 side): a reusable
    ## long-term secret holder, with no paired public value whose
    ## invariant a second live copy could violate, so duplication costs
    ## nothing beyond the copy itself.
    ##
    ## **Invariant: always a canonical residue mod L** (`bytes < L`),
    ## load-bearing twice over -- reduced means `< L < 2^253`, so
    ## `scalar.recodeScalarRadix16`'s bit-255-clear precondition (which
    ## `geScalarmultBase`'s own debug-only assert checks) holds by
    ## construction for every value this type can hand to a CT scalarmult
    ## (an unreduced scalar with bit 255 set would otherwise SILENTLY
    ## compute a wrong multiple -- `cmovCached` matches nothing for an
    ## out-of-range digit and contributes the identity, no diagnostic) --
    ## and it matches the dalek convention that a scalar IS a canonical
    ## residue. Every constructor below establishes this: the fresh
    ## constructors wide-reduce via `scalar.scReduce` (uniform sampling mod
    ## L), the 32-byte import REJECTS non-canonical input (`Option`,
    ## dalek's `from_canonical_bytes` register) rather than silently
    ## reducing it, and the 64-byte wide import reduces (it is total --
    ## see each constructor's own doc comment for why reduce-vs-reject
    ## differs between the two).
    ##
    ## **Repr-disclosure line (this family's first explicit one, RFC-004
    ## round-3 pin):** no `$` is defined for this type -- `echo secret`
    ## fails to compile -- but Nim's `repr`/reflective dumps print any
    ## object's raw fields regardless of that. Out of scope to prevent, in
    ## scope to disclose: every sello secret type shares this residual gap;
    ## this is simply the first one to state it explicitly.
    bytes: array[32, byte]

## Type hooks must be declared immediately after the type they attach to --
## see `signing.nim`'s module doc comment for why (Nim may otherwise
## synthesize a default hook first and reject an explicit one declared
## later). Copyable (no `=copy` restriction): every copy self-wipes
## independently at its own scope exit, the same register as
## `x25519.X25519StaticSecret`.
secretHooks(RistrettoStaticSecret, bytes)

func toRistrettoStaticSecret*(bytes: array[32, byte]): Option[RistrettoStaticSecret] =
  ## Key IMPORT (dalek's `from_canonical_bytes` register): REJECTS a
  ## non-canonical scalar (`>= L`) via `scalar.scIsCanonical` rather than
  ## silently reducing it -- reduce-vs-reject is a security-semantic
  ## difference (silent reduction would accept corrupted or
  ## cross-protocol key material and make `toBytes` round-trip to a
  ## DIFFERENT value than was imported), so this is a distinct behavior
  ## from `toRistrettoStaticSecretWide` below, not an overload of it (see
  ## that constructor's own doc comment for why they must have different
  ## names). `none` on reject.
  ##
  ## Both paths wipe this proc's own local scratch copy of the caller's
  ## input before returning (the `signing.keypair(seed, expectedPublic)`
  ## none-path-wipe register): nothing secret-derived that passed through
  ## this proc's own stack survives past the call, on either verdict --
  ## the object handed back on the `some` path already holds its own
  ## independent copy of the bytes by then, made before the wipe below
  ## runs, so the wipe cannot affect the returned value.
  var scratch = bytes
  try:
    if scIsCanonical(scratch):
      result = some(RistrettoStaticSecret(bytes: scratch))
    else:
      result = none(RistrettoStaticSecret)
  finally:
    ct.wipe(scratch)

func toRistrettoStaticSecretWide*(bytes: array[64, byte]): RistrettoStaticSecret =
  ## TOTAL key import (dalek's `from_bytes_mod_order_wide` register): every
  ## 64-byte input reduces mod L via `scalar.scReduce`, the unbiased
  ## KDF/hash-derived route. Named DISTINCTLY from `toRistrettoStaticSecret`
  ## above rather than as a same-name overload-by-array-length (round-3 of
  ## the RFC's review): reject-vs-silently-reduce is a security-semantic
  ## difference an overload would hide from a call-site skim, and dalek
  ## itself separates these two constructors by name for exactly this
  ## reason. Wideness is why no canonicity expectation exists to violate
  ## here, unlike the 32-byte import -- reduce-not-reject is correct HERE
  ## and only here.
  ##
  ## Constructor-internal reduction scratch is wiped before return.
  var reduced: array[32, byte]
  scReduce(reduced, bytes)
  result = RistrettoStaticSecret(bytes: reduced)
  ct.wipe(reduced)

proc ristrettoStaticSecret*(): RistrettoStaticSecret {.raises: [OSError].} =
  ## Fresh secret via `std/sysrand`: 64 random bytes, wide-reduced mod L
  ## via `scalar.scReduce` (uniform sampling mod L -- the
  ## `x25519.x25519StaticSecret()` in-place-fill/`OSError`-on-failure
  ## discipline, adapted to ristretto255's prime-order-group shape rather
  ## than X25519's raw-clamped-scalar one). Constructor-internal secret
  ## temporaries (the sysrand buffer, the reduction scratch) are wiped
  ## before return.
  var raw: array[64, byte]
  if not urandom(raw):
    raise newException(OSError, "sello.ristrettoStaticSecret: sysrand.urandom failed")
  var reduced: array[32, byte]
  scReduce(reduced, raw)
  result = RistrettoStaticSecret(bytes: reduced)
  ct.wipe(raw)
  ct.wipe(reduced)

proc ristrettoStaticPair*(): tuple[secret: RistrettoStaticSecret, public: RistrettoPoint] {.raises: [OSError].} =
  ## Fresh static secret plus its `ristrettoScalarmultBase` image, in one
  ## call -- `x25519.x25519StaticPair()`'s ergonomic (RFC-003 slice 1 item
  ## 5 there): the common case ("I want a reusable identity and its public
  ## element together") needs one call instead of two. Computes the public
  ## element via the same `toSecretScalar`/`geScalarmultBase` sequence
  ## `ristrettoScalarmultBase` below uses, rather than calling that public
  ## wrapper directly (`x25519.x25519StaticPair`'s own precedent, calling
  ## the private `ladder` rather than `x25519Base`): Nim requires a callee
  ## be declared earlier in the module, and `ristrettoScalarmultBase` is
  ## declared below this proc. Constructor-internal secret temporaries are
  ## wiped before return, same as `ristrettoStaticSecret()` above.
  var raw: array[64, byte]
  if not urandom(raw):
    raise newException(OSError, "sello.ristrettoStaticPair: sysrand.urandom failed")
  var reduced: array[32, byte]
  scReduce(reduced, raw)
  result.secret = RistrettoStaticSecret(bytes: reduced)
  var sc = toSecretScalar(reduced)
  result.public = ristrettoUnchecked(geScalarmultBase(sc))
  ct.wipe(raw)
  ct.wipe(reduced)
  ct.wipe(sc)

func toBytes*(s: RistrettoStaticSecret): array[32, byte] {.inline.} =
  ## Deliberate export for persistence/interop. The returned copy is
  ## caller-owned and NOT wiped by this call -- wipe it yourself (e.g.
  ## `wipe(var RistrettoStaticSecret)` below) once you are done with it.
  s.bytes

proc wipe*(s: var RistrettoStaticSecret) =
  ## Explicit early wipe, e.g. right after deriving a public element when
  ## the caller does not need to retain the raw secret. `=destroy`
  ## performs the same wipe automatically at scope exit; this exists for
  ## callers that want it sooner. Calls `ct.wipe` directly (round-4
  ## finding R10's simplification, `x25519.nim`'s own register), not a
  ## named `zeroize<Type>` proc.
  ct.wipe(s.bytes)

func ristrettoScalarmultBase*(secret: RistrettoStaticSecret): RistrettoPoint =
  ## CT fixed-base scalar multiplication over the static secret role, via
  ## `scalar.geScalarmultBase` (already CT, already dudect-covered,
  ## already R1-wipe-disciplined internally). Bridges
  ## `RistrettoStaticSecret` to `scalar.SecretScalar` at this module's
  ## boundary -- the `signing.nim` -> `private/backend.nim` pattern: the
  ## `SecretScalar` is assembled here (`secret.bytes` is always a
  ## canonical residue mod L by this type's own invariant, discharging
  ## `geScalarmultBase`'s bit-255-clear precondition by construction),
  ## consumed by `geScalarmultBase`, and wiped once no longer needed --
  ## `geScalarmultBase` independently wipes its OWN internal copy of the
  ## scalar it receives; the wipe below is of THIS proc's separate local
  ## copy (`sc`), which `geScalarmultBase`'s pass-by-value parameter does
  ## not touch.
  var sc = toSecretScalar(secret.bytes)
  try:
    result = ristrettoUnchecked(geScalarmultBase(sc))
  finally:
    ct.wipe(sc)

func ristrettoScalarmultVartime*(s: array[32, byte]; p: RistrettoPoint): RistrettoPoint =
  ## Vartime variable-base scalar multiplication, via
  ## `scalar.scalarmultVartime` -- the verify-path-style register, for
  ## protocol steps where the scalar is public. Accepts ONLY a bare
  ## `array[32, byte]`: neither `RistrettoStaticSecret` nor
  ## `scalar.SecretScalar` has a converter to it, so passing secret-typed
  ## material here is an ordinary compile-time type mismatch, not merely a
  ## naming-convention violation -- see
  ## `tests/unit/fixtures/reject_secretscalar_ristretto_vartime.nim`, the
  ## `scalar.SecretScalar`-vs-`scalarmultVartime` type boundary (round-3
  ## finding A3) reused for this module's secret role. `p` need not be
  ## reduced or canonical in any sense beyond already being a valid
  ## `RistrettoPoint` -- `s` itself need not be canonical either:
  ## `scalarmultVartime` computes the literal 256-bit multiple, with no
  ## reduction assumed (the boundary scalar `s = L` deliberately reaches
  ## this path unreduced in `tests/unit/test_ristretto.nim`, landing on the
  ## identity for any point of order L).
  var r: GeP3
  scalarmultVartime(r, s, p.p)
  ristrettoUnchecked(r)

func ristrettoScalarmult*(secret: RistrettoStaticSecret; p: RistrettoPoint): RistrettoPoint =
  ## CT variable-base scalar multiplication over the static secret role
  ## (RFC-004 slice 7a), via `scalar.geScalarmultCT` -- the operation that
  ## makes this group usable for OPRF evaluation, Pedersen commitments, and
  ## DH shares over an ARBITRARY (not fixed) point, where that point IS
  ## secret-derived even though the group element itself carries no CT
  ## hygiene of its own (see the module doc's CT-posture headline: the
  ## SECRET is the scalar, and CT protection belongs on this bridge and the
  ## ladder it calls into, not on `RistrettoPoint`). Same
  ## `RistrettoStaticSecret` -> `scalar.SecretScalar` bridge as
  ## `ristrettoScalarmultBase` above -- see that function's doc comment for
  ## the wipe-of-this-proc's-own-copy rationale, identical here (this
  ## proc's own local `sc`; `geScalarmultCT` independently wipes its own
  ## copy of the scalar it receives).
  var sc = toSecretScalar(secret.bytes)
  try:
    result = ristrettoUnchecked(geScalarmultCT(sc, p.p))
  finally:
    ct.wipe(sc)

# ---------------------------------------------------------------------------
# RistrettoEphemeralSecret -- the single-use secret-scalar role (RFC-004 slice 5b)
# ---------------------------------------------------------------------------

type
  RistrettoEphemeralSecret* = object
    ## A SINGLE-USE ristretto255 secret scalar -- the ElGamal/ECIES-style
    ## hybrid-encryption role, round-3 proof-spiked rather than inherited
    ## from `x25519.X25519EphemeralSecret` by analogy alone: ephemeral k,
    ## `C1 = ristrettoScalarmultBase(k)` (the non-consuming borrow below)
    ## sent alongside the ciphertext, then `S = k*P` against the
    ## recipient's public element (the ONE consuming variable-base call --
    ## `ristrettoScalarmult(sink RistrettoEphemeralSecret, ...)`, arriving
    ## in slice 7a over `scalar.geScalarmultCT`), k dead thereafter. This
    ## lands on the borrow-then-consume shape exactly, and needs no scalar
    ## arithmetic of its own -- the Non-goals boundary (Schnorr responses,
    ## OPRF client unblinding, both needing mod-L scalar inversion this
    ## library does not ship) does not defang it.
    ##
    ## **The honest boundary, not a defect:** a CPace-style PAKE's
    ## per-session scalar is "ephemeral" in protocol terms but needs TWO
    ## variable-base multiplications with the SAME scalar (once against the
    ## mapped generator, once against the peer's share) -- a move-only,
    ## single-use type CANNOT express that by design, since the first
    ## consuming call moves the scalar away before a second could run. That
    ## caller wants `RistrettoStaticSecret` plus an explicit `wipe`
    ## instead: a reusable secret held for exactly the two calls it needs,
    ## then wiped early. Do not reach for this type for a PAKE-shaped
    ## protocol; reach for it for a genuine one-shot DH share.
    ##
    ## Mechanics mirror `x25519.X25519EphemeralSecret` exactly -- see that
    ## type's doc comment for the full empirical Nim-ownership writeup this
    ## one cross-references rather than re-derives (the `move()` requirement
    ## after any earlier touch of the same variable, and its honest,
    ## inherent `move()`-override residual gap): `secretHooksMoveOnly`
    ## below (`=copy {.error.}`), constructed ONLY via
    ## `ristrettoEphemeralSecret()` / `ristrettoEphemeralPair()` (fresh from
    ## `std/sysrand`, wide-reduced mod L via `scalar.scReduce` -- no
    ## from-bytes route of any kind: freshness by construction), and NO
    ## `toBytes` (unpersistable by design -- a value meant to be used once
    ## and discarded). This slice ships only the non-consuming
    ## `ristrettoScalarmultBase` borrow below; the consuming
    ## `ristrettoScalarmult(sink RistrettoEphemeralSecret, ...)` overload
    ## and its reuse fixture arrive in slice 7a alongside
    ## `scalar.geScalarmultCT`.
    ##
    ## **Invariant: always a canonical residue mod L**, the same load-
    ## bearing double duty `RistrettoStaticSecret`'s own doc comment states
    ## (the `recodeScalarRadix16` bit-255-clear precondition held by
    ## construction; matches the dalek convention that a scalar IS a
    ## canonical residue) -- established here by wide-reducing every fresh
    ## value mod L, the same as the static role's fresh constructors.
    ##
    ## One-field object, not `distinct array[32, byte]`, for the same
    ## empirically-established reason as `RistrettoStaticSecret`/
    ## `signing.Seed`/`x25519.X25519StaticSecret` (see `signing.Seed`'s doc
    ## comment): a bare `distinct array` local's `=destroy` silently never
    ## fires under ORC on Nim 2.2.10.
    ##
    ## **Repr-disclosure line** (same as `RistrettoStaticSecret`'s): no `$`
    ## is defined for this type -- `echo secret` fails to compile -- but
    ## Nim's `repr`/reflective dumps print any object's raw fields
    ## regardless of that. Out of scope to prevent, in scope to disclose.
    bytes: array[32, byte]

## Type hooks must be declared immediately after the type they attach to --
## see `signing.nim`'s module doc comment for why. Move-only, the
## `Keypair`/`x25519.X25519EphemeralSecret` pattern: a second live copy of a
## single-use secret is a compile error, not a hygiene footnote. Legitimate
## transfers move (slice 7a's `sink` parameter).
secretHooksMoveOnly(RistrettoEphemeralSecret, bytes)

proc ristrettoEphemeralSecret*(): RistrettoEphemeralSecret {.raises: [OSError].} =
  ## Fresh secret via `std/sysrand`: 64 random bytes, wide-reduced mod L via
  ## `scalar.scReduce` (uniform sampling mod L -- the
  ## `ristrettoStaticSecret()`/`x25519.x25519EphemeralSecret()` in-place-
  ## fill/`OSError`-on-failure discipline, adapted to this role's single-use
  ## shape). Deliberately no `toBytes(bytes)` counterpart: this is the ONLY
  ## way to get one (see the type's doc comment -- freshness-by-construction
  ## is the whole point). Constructor-internal secret temporaries (the
  ## sysrand buffer, the reduction scratch) are wiped before return. Prefer
  ## `ristrettoEphemeralPair()` when you also need the derived public
  ## element -- deriving it inside the constructor keeps the caller's
  ## secret binding referenced exactly once, avoiding the `move()`
  ## ceremony `x25519.x25519EphemeralPair()`'s own doc comment documents in
  ## full.
  var raw: array[64, byte]
  if not urandom(raw):
    raise newException(OSError, "sello.ristrettoEphemeralSecret: sysrand.urandom failed")
  var reduced: array[32, byte]
  scReduce(reduced, raw)
  result = RistrettoEphemeralSecret(bytes: reduced)
  ct.wipe(raw)
  ct.wipe(reduced)

proc ristrettoEphemeralPair*(): tuple[secret: RistrettoEphemeralSecret, public: RistrettoPoint] {.raises: [OSError].} =
  ## Fresh ephemeral secret plus its `ristrettoScalarmultBase` image, in one
  ## call -- the primary way to get an ephemeral secret (mirrors
  ## `x25519.x25519EphemeralPair()`'s ergonomic and `ristrettoStaticPair()`'s
  ## exact construction shape above). Computes the public element via the
  ## same `toSecretScalar`/`geScalarmultBase` sequence
  ## `ristrettoScalarmultBase` below uses, rather than calling that overload
  ## directly, for the same reason `ristrettoStaticPair()` does above: Nim
  ## requires a callee be declared earlier in the module, and
  ## `ristrettoScalarmultBase(RistrettoEphemeralSecret)` is declared below
  ## this proc. Constructor-internal secret temporaries are wiped before
  ## return, same as `ristrettoEphemeralSecret()` above.
  var raw: array[64, byte]
  if not urandom(raw):
    raise newException(OSError, "sello.ristrettoEphemeralPair: sysrand.urandom failed")
  var reduced: array[32, byte]
  scReduce(reduced, raw)
  result.secret = RistrettoEphemeralSecret(bytes: reduced)
  var sc = toSecretScalar(reduced)
  result.public = ristrettoUnchecked(geScalarmultBase(sc))
  ct.wipe(raw)
  ct.wipe(reduced)
  ct.wipe(sc)

proc wipe*(s: sink RistrettoEphemeralSecret) =
  ## Early disposal of an ephemeral secret that was generated but never
  ## consumed by `ristrettoScalarmult` (e.g. the caller decided not to
  ## complete the ElGamal/ECIES exchange) -- the
  ## `x25519.wipe(sink X25519EphemeralSecret)` precedent, reused verbatim
  ## for this role. `=destroy` performs the same wipe automatically at
  ## scope exit; this exists for callers that want it sooner.
  ##
  ## Takes `sink`, not `var` (the same round-4 finding R4 reasoning as the
  ## X25519 counterpart): a `var` `wipe` would not consume its argument, so
  ## a caller could write `wipe(eph)` and then still reach the consuming
  ## `ristrettoScalarmult(move(eph), p)` -- which would compile and run the
  ## CT ladder on just-zeroed scalar bytes (all-zero reduces to scalar 0,
  ## a valid if degenerate input -- `geScalarmultCT` has no small-order
  ## rejection to catch it the way `x25519`'s ladder does), silently
  ## defeating the single-use guarantee. With `sink`, `wipe(move(eph))`
  ## consumes `eph`; any later reference (including a second `wipe`, or the
  ## consuming scalarmult) is a compile error, not a runtime hazard.
  ct.wipe(s.bytes)

func ristrettoScalarmultBase*(secret: RistrettoEphemeralSecret): RistrettoPoint =
  ## CT fixed-base scalar multiplication over the ephemeral secret role --
  ## a BORROW, deliberately non-consuming: a plain by-value
  ## `RistrettoEphemeralSecret` parameter (not `sink`) is a borrow when this
  ## is not the argument's last use, exactly the
  ## `x25519.x25519Base(secret: X25519EphemeralSecret)` precedent (see that
  ## proc's doc comment for the full empirical writeup). Only slice 7a's
  ## consuming `ristrettoScalarmult(sink RistrettoEphemeralSecret, ...)`
  ## overload takes ownership of this role's secret. Same
  ## `RistrettoEphemeralSecret`-to-`scalar.SecretScalar` bridge as the
  ## static-role overload above -- see its doc comment for the
  ## wipe-of-this-proc's-own-copy rationale, identical here.
  var sc = toSecretScalar(secret.bytes)
  try:
    result = ristrettoUnchecked(geScalarmultBase(sc))
  finally:
    ct.wipe(sc)

func ristrettoScalarmult*(secret: sink RistrettoEphemeralSecret; p: RistrettoPoint): RistrettoPoint =
  ## CT variable-base scalar multiplication that CONSUMES the ephemeral
  ## secret (RFC-004 slice 7a) -- the ONE consuming call in the
  ## ElGamal/ECIES-style flow `RistrettoEphemeralSecret`'s own doc comment
  ## names: ephemeral k, `C1 = ristrettoScalarmultBase(k)` (the
  ## non-consuming borrow above) sent alongside the ciphertext, then
  ## `S = k*P` against the recipient's public element -- this proc -- k
  ## dead thereafter. `sink` plus `RistrettoEphemeralSecret`'s move-only
  ## `=copy {.error.}` together make reuse a compile error rather than a
  ## documented caller obligation -- the
  ## `x25519.x25519(sink X25519EphemeralSecret, ...)` precedent, reused
  ## verbatim: see that function's doc comment for the full empirical
  ## Nim-ownership writeup this one cross-references rather than
  ## re-derives, including the `move()` requirement after any earlier
  ## touch of the same variable (a plain `ristrettoScalarmultBase(secret)`
  ## borrow counts) and its honest, inherent `move()`-override residual
  ## gap. Pinned by
  ## `tests/unit/fixtures/reject_ristretto_ephemeral_reuse.nim`, subprocess
  ## `nim c`-verified -- same methodology as `reject_ephemeral_reuse.nim`:
  ## the `=copy` violation this raises is only surfaced by the
  ## `injectdestructors` pass, later in the pipeline than `compiles()`/
  ## `nim check` reach.
  ##
  ## Same `RistrettoEphemeralSecret` -> `scalar.SecretScalar` bridge as the
  ## static-role `ristrettoScalarmult` overload above -- see its doc
  ## comment for the wipe-of-this-proc's-own-copy rationale, identical
  ## here. `secret` itself is a local owned by this proc for the duration
  ## of the call and is wiped by its own `=destroy` when it goes out of
  ## scope at return, the same automatic-wipe guarantee every other
  ## secret-holding type in this codebase carries.
  var sc = toSecretScalar(secret.bytes)
  try:
    result = ristrettoUnchecked(geScalarmultCT(sc, p.p))
  finally:
    ct.wipe(sc)

# ---------------------------------------------------------------------------
# Hash-to-group -- RFC 9496 SS4.3.4 (RFC-004 slice 6)
# ---------------------------------------------------------------------------

const OneMinusDSq* = feFromBytes([
  0x76'u8, 0xc1, 0x5f, 0x94, 0xc1, 0x09, 0x7c, 0xe2,
  0x0f, 0x35, 0x5e, 0xcd, 0x38, 0xa1, 0x81, 0x2c,
  0xe4, 0xdf, 0x70, 0xbe, 0xdd, 0xab, 0x94, 0x99,
  0xd7, 0xe0, 0xb3, 0xb2, 0xa8, 0x72, 0x90, 0x02,
])
  ## RFC 9496 SS4.1: `ONE_MINUS_D_SQ = 1 - d^2`, one of the two MAP-only
  ## denominator/numerator constants (the other is `DMinusOneSq` below).
  ## Same compile-time-`feFromBytes`-from-spec-bytes mechanism as
  ## `InvSqrtAMinusD` (see that constant's own doc comment for the full
  ## rationale) -- the little-endian encoding of the decimal value RFC 9496
  ## SS4.1 publishes for `ONE_MINUS_D_SQ`
  ## (1159843021668779879193775521855586647937357759715417654439879720876
  ## 111806838), the one transcribed artifact. Cross-checked against its
  ## defining equation in `tests/unit/test_ristretto.nim`:
  ## `OneMinusDSq == 1 - d^2` where `d = feFromLimbs(scalar.Ed25519D_Raw)`.
  ## Exported (module-level, `InvSqrtAMinusD`'s own precedent) so that
  ## cross-check can run from the test file -- like that constant, NOT
  ## re-exported from the `sello` facade (see slice 8d's enumerated facade
  ## list): the map is this constant's only real consumer, same as
  ## `DMinusOneSq`/`SqrtAdMinusOne` below.

const DMinusOneSq* = feFromBytes([
  0x20'u8, 0x4d, 0xed, 0x44, 0xaa, 0x5a, 0xad, 0x31,
  0x99, 0x19, 0x1e, 0xb0, 0x2c, 0x4a, 0x9e, 0xd2,
  0xeb, 0x4e, 0x9b, 0x52, 0x2f, 0xd3, 0xdc, 0x4c,
  0x41, 0x22, 0x6c, 0xf6, 0x7a, 0xb3, 0x68, 0x59,
])
  ## RFC 9496 SS4.1: `D_MINUS_ONE_SQ = (d - 1)^2`. Same mechanism, same
  ## register as `OneMinusDSq` above -- the little-endian encoding of
  ## (4044083434630853685810104246932319082624839914623870835224013322086
  ## 5137265952). Cross-checked in-test against `DMinusOneSq == (d - 1)^2`.

const SqrtAdMinusOne* = feFromBytes([
  0x1b'u8, 0x2e, 0x7b, 0x49, 0xa0, 0xf6, 0x97, 0x7e,
  0xbd, 0x54, 0x78, 0x1b, 0x0c, 0x8e, 0x9d, 0xaf,
  0xfd, 0xd1, 0xf5, 0x31, 0xc9, 0xfc, 0x3c, 0x0f,
  0xac, 0x48, 0x83, 0x2b, 0xbf, 0x31, 0x69, 0x37,
])
  ## RFC 9496 SS4.1: `SQRT_AD_MINUS_ONE = sqrt(a*d - 1)` where `a = -1` --
  ## the map's final numerator-rotation multiplier (`w1 = N *
  ## SQRT_AD_MINUS_ONE`). Same mechanism, same register as the two constants
  ## above -- the little-endian encoding of
  ## (2506306895338462347411141415870215270124453150249265646007921048261
  ## 0430750235). Cross-checked in-test against
  ## `SqrtAdMinusOne^2 == a*d - 1` where `a = -1`.

func ristrettoMap(bytes: array[32, byte]): GeP3 =
  ## RFC 9496 SS4.3.4's `MAP` function (Elligator 2 for ristretto255): takes
  ## one 32-byte half of `ristrettoFromUniformBytes`'s input and returns an
  ## extended-coordinate point that is ALWAYS well-formed and on-curve --
  ## `MAP` is a total function on the field, so there is no accept/reject
  ## verdict here at all (unlike `ristrettoDecode`), and consequently no CT
  ## carve-out to state: every step below is unconditional straight-line
  ## field arithmetic plus `feCMove` selects, start to finish.
  ##
  ## Private (module-internal, per the task's scope): `MAP` has no meaning
  ## as a standalone group element derivation -- only
  ## `ristrettoFromUniformBytes` (SS4.3.4 step 3, `P1 + P2`) produces an
  ## actual `RistrettoPoint`, so this helper is not itself wrapped through
  ## `ristrettoUnchecked` (the caller does that).
  ##
  ## `t = feFromBytes(bytes)`: the spec's step 1 ("mask the most significant
  ## bit ... reduce r modulo p") is exactly what `feFromBytes` already does
  ## unconditionally on every input -- it drops the top bit of byte 31
  ## before decoding into limbs (the same fact `x25519.nim`'s own u-coordinate
  ## decode comment records), and every subsequent `fe*` operation treats its
  ## operands as residues mod p regardless of literal integer magnitude, so
  ## no separate reduction step is needed. Unlike `ristrettoDecode`'s
  ## canonicity check, non-canonical (>= p) 32-byte inputs are EXPLICITLY
  ## accepted here (RFC 9496's own note on this step) -- consistent with
  ## `ristrettoFromUniformBytes` being total.
  let t = feFromBytes(bytes)

  var tSq, r: Fe
  feSq(tSq, t)
  feMul(r, FeSqrtM1, tSq)                       # r = SQRT_M1 * t^2

  let d = feFromLimbs(Ed25519D_Raw)

  var rPlus1, u: Fe
  feAdd(rPlus1, r, FeOne)
  feMul(u, rPlus1, OneMinusDSq)                 # u = (r + 1) * ONE_MINUS_D_SQ

  var negOne, rD, negOneMinusRD, rPlusD, v: Fe
  feNeg(negOne, FeOne)
  feMul(rD, r, d)
  feSub(negOneMinusRD, negOne, rD)              # -1 - r*D
  feAdd(rPlusD, r, d)                           # r + D
  feMul(v, negOneMinusRD, rPlusD)               # v = (-1 - r*D) * (r + D)

  let (wasSquare, sCandidate) = feSqrtRatioM1(u, v)

  var st, absSt, negAbsSt: Fe
  feMul(st, sCandidate, t)
  absSt = st
  feAbs(absSt)                                  # CT_ABS(s*t)
  feNeg(negAbsSt, absSt)                        # s_prime = -CT_ABS(s*t)

  var s = sCandidate
  feCMove(s, negAbsSt, not wasSquare)
    # s = CT_SELECT(s IF was_square ELSE s_prime)

  var c = negOne
  feCMove(c, r, not wasSquare)
    # c = CT_SELECT(-1 IF was_square ELSE r)

  var rMinus1, cRMinus1, cTerm, n: Fe
  feSub(rMinus1, r, FeOne)
  feMul(cRMinus1, c, rMinus1)
  feMul(cTerm, cRMinus1, DMinusOneSq)
  feSub(n, cTerm, v)                            # N = c*(r-1)*D_MINUS_ONE_SQ - v

  var twoS, w0, w1, sSq, w2, w3: Fe
  feAdd(twoS, s, s)
  feMul(w0, twoS, v)                            # w0 = 2*s*v
  feMul(w1, n, SqrtAdMinusOne)                  # w1 = N * SQRT_AD_MINUS_ONE
  feSq(sSq, s)
  feSub(w2, FeOne, sSq)                         # w2 = 1 - s^2
  feAdd(w3, FeOne, sSq)                         # w3 = 1 + s^2

  var x, y, z, tOut: Fe
  feMul(x, w0, w3)
  feMul(y, w2, w1)
  feMul(z, w1, w3)
  feMul(tOut, w0, w2)
  result = GeP3(x: x, y: y, z: z, t: tOut)

func ristrettoFromUniformBytes*(b: array[64, byte]): RistrettoPoint =
  ## RFC 9496 SS4.3.4 Element Derivation: splits `b` into two 32-byte
  ## halves, `MAP`s each independently, and adds the results
  ## (`ristrettoUnchecked` wraps each `MAP` output before this module's own
  ## `+` operator, which needs `RistrettoPoint`s, not raw `GeP3`s).
  ##
  ## A TOTAL function: `MAP` never rejects (see its own doc comment), so
  ## every one of the 2^512 possible 64-byte inputs -- including the two
  ## deterministic edge cases `tests/unit/test_ristretto.nim` pins by name,
  ## all-zero and all-0xFF -- yields a valid `RistrettoPoint`. No `Option`,
  ## unlike `ristrettoDecode`: hashing is the caller's job (RFC 9496 leaves
  ## the hash-to-64-bytes step out of scope, and this module stays
  ## nimcrypto-free by design -- see the module doc comment), but whatever
  ## 64 bytes arrive here always produce SOME group element.
  ##
  ## **The `array[64, byte]` parameter IS the length check**, at compile
  ## time, with no runtime failure path to design around -- deliberately no
  ## `openArray[byte]` overload (that would trade a compile-time guarantee
  ## for a runtime one on an otherwise-total function). A nimcrypto SHA-512
  ## digest already has exactly this type (see `challenge.nim`'s own
  ## `sha512.finish(var array[64, byte])` usage), but this module is
  ## deliberately nimcrypto-free, so the EXPECTED caller arrives from some
  ## other hash/XOF whose output is a `seq[byte]` or `string` -- for that
  ## caller, the one checked-copy idiom to reach for is:
  ##
  ## .. code-block:: nim
  ##   var buf: array[64, byte]
  ##   doAssert digest.len == 64
  ##   for i in 0 ..< 64: buf[i] = digest[i]
  ##   let element = ristrettoFromUniformBytes(buf)
  ##
  ## (the `doAssert` is the "checked" half -- it fails loudly on a
  ## mis-sized digest rather than silently truncating or index-erroring).
  var half1, half2: array[32, byte]
  for i in 0 ..< 32:
    half1[i] = b[i]
    half2[i] = b[32 + i]
  let p1 = ristrettoUnchecked(ristrettoMap(half1))
  let p2 = ristrettoUnchecked(ristrettoMap(half2))
  p1 + p2

{.pop.}
