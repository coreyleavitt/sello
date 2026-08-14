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
## **Slice 2 scope** (this file, so far): `RistrettoPoint`/
## `RistrettoEncoded` and their basic borrows, the `ristrettoUnchecked`
## construction door, quotient `==`, and `ristrettoDecode`. NOT yet
## present: `ristrettoEncode`, the group operators (`+`/`-`), scalar
## multiplication, the one-way map, the secret-scalar role types, or a
## facade export -- later slices. `RistrettoPoint` has deliberately no
## `wipe` overload even once those land: see its own doc comment below.
##
## **Hash-the-encoding, not the point:** there is deliberately no
## `hash(RistrettoPoint)`. A hash must agree with `==`, and hashing any
## particular internal `GeP3` representation would diverge from quotient
## equality (two different-looking representations of the SAME element
## must hash the same, which only the canonical encoding guarantees).
## Key/dedupe on `RistrettoEncoded` (encode first), never on the point.

import std/[hashes, options]
import sello/field
import sello/scalar

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

{.pop.}
