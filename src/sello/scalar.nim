## Curve25519 group operations and scalar multiplication
##
## Extended homogeneous coordinates (X:Y:Z:T) with T = X*Y/Z.
##
## Addition formulas from Hisil-Wong-Carter-Dawson "Twisted Edwards Curves
## Revisited" (2008), as implemented in ref10 / TweetNaCl (public domain).
##
## Pure field-plus-curve-math leaf as of RFC-002 slice 2: the one thing
## that used to pull nimcrypto's SHA-512 into this file, the shared
## `challenge` hash, moved out to `sello/challenge.nim` (which imports
## this module back for `scReduce`). No nimcrypto import here any more.

import sello/field
import sello/private/ct

## Compiler-enforced effect contract (janus consumer finding 3) -- see
## `signing.nim`'s module doc for the surface-wide policy.
{.push raises: [], gcsafe.}

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

type
  SecretScalar* = distinct array[32, byte]
    ## A scalar that must never reach `scalarmultVartime` (round-3 finding
    ## A3). Before this type existed, "never pass the signer's secret
    ## scalar to `scalarmultVartime`" was enforced by nothing but a naming
    ## convention (the `Vartime` suffix, RFC-001 finding 8) and a doc
    ## comment -- a plain `array[32, byte]` is structurally identical
    ## whether it holds a public nonce-derived digest or a secret signing
    ## key, so nothing stopped a future refactor from silently handing one
    ## to the other. `SecretScalar` closes that at the type level:
    ## `scalarmultVartime` (below) accepts only a bare `array[32, byte]`,
    ## with no converter to/from `SecretScalar`, so passing a
    ## `SecretScalar` where it expects a scalar is an ordinary Nim type
    ## mismatch -- a compile error, not a discipline that has to hold by
    ## habit. Pinned as a regression by
    ## `tests/unit/fixtures/reject_secretscalar_vartime.nim`.
    ##
    ## **Home, and why not elsewhere (recorded per this finding's own
    ## request for the reasoning):** lives here, in `scalar.nim`, rather
    ## than a shared leaf like `wire.nim`/`wipe.nim`. Those two leaves hold
    ## PUBLIC wire types and a generic wipe utility respectively -- neither
    ## is the right home for a type whose entire purpose is gating access
    ## to this file's OWN `geScalarmultBase`/`scMulAdd`. `field.nim` (below
    ## this file) was also considered, since `clampScalar` and
    ## `x25519.nim`'s ladder both handle secret scalars too -- but
    ## `x25519.nim` never calls `scalarmultVartime` or `geScalarmultBase`
    ## at all (its Montgomery ladder is a wholly separate RFC 7748
    ## algorithm on `field.nim` alone, with no vartime group-op path to
    ## accidentally reach), so it has no compile-time hazard this type
    ## needs to close, and `x25519.nim`'s own module doc/CLAUDE.md
    ## architecture note is explicit that it "must remain a
    ## `field.nim`-only consumer" -- adding a `scalar.nim` dependency there
    ## just to share this type would cost a real layering rule for zero
    ## benefit. `SecretScalar` stays scoped to exactly the two functions
    ## (`geScalarmultBase`, `scMulAdd`'s secret positions) and the one
    ## caller module (`private/backend.nim`) it actually protects.
    ##
    ## **`recodeScalarRadix16` and the Montgomery ladder deliberately stay
    ## byte-level**, below this type's boundary, not wrapped in
    ## `SecretScalar` themselves: `recodeScalarRadix16` is a pure
    ## bit-recoding leaf with no group-op call of its own (it cannot reach
    ## `scalarmultVartime` no matter what type its input has) and is
    ## exercised directly, over plain `array[32, byte]` scalars, by
    ## white-box tests (`test_scalar.nim`) and the Z3 harness
    ## (`tests/verify/symex_recode.nim`) that have no reason to know about
    ## a signing-specific secrecy type; threading `SecretScalar` through it
    ## would widen the type's footprint without tightening anything it
    ## actually guards. `geScalarmultBase` is where the boundary is drawn
    ## instead: it is the actual entry point `backend.nim` calls with a
    ## real secret, so that is where the type does its one job.
    ##
    ## **`private/`-extraction considered and declined (compromise-audit
    ## finding R2):** moving `geScalarmultBase`/`scMulAdd`/`SecretScalar`/
    ## `toSecretScalar`/`secretScalarBytes` to a new
    ## `private/secret_scalar.nim` (matching every other raw-secret handler
    ## in this codebase living under `private/`) was evaluated directly
    ## against this file. It does not extract cleanly: `geScalarmultBase`
    ## needs `geP3Double` (the 4x-doubling step between the odd/even digit
    ## passes), and `scMulAdd` needs `load3`/`load4` (its limb decoding) --
    ## all three are today unexported internals with exactly one other
    ## caller apiece that would stay behind in this file (`geP3Double` via
    ## `buildBaseTable`, `load3`/`load4` via `scReduce`). Extracting would
    ## force exporting all three purely to bridge the module split, trading
    ## "secret ops sit in the public tier" for "scalar.nim's private
    ## reduction/doubling helpers become public surface" -- not a net win.
    ## `geScalarmultBase`/`scMulAdd` stay here; RFC finding R1's `ct.wipe`
    ## coverage of every secret local both functions touch (`sBytes`/
    ## `digits`/`acc`/`u`/`step` in `geScalarmultBase`, `b`/`c`/`s0..s23` in
    ## `scMulAdd`, both under the same `try`/`finally` net
    ## `private/backend.nim` uses) is applied in place, on the strength of
    ## `private/ct.nim` already being a universal leaf any secret-holding
    ## module reaches into directly regardless of its position in the
    ## import graph (see this project's own architecture notes) -- the same
    ## justification `x25519.nim` (not under `private/` either) relies on
    ## for its own `ct.wipe` calls.

  GeP2* = object
    x*, y*, z*: Fe

  GeP3* = object
    x*, y*, z*, t*: Fe

  GeP1P1* = object
    x*, y*, z*, t*: Fe

  GeCached* = object
    yPlusX*, yMinusX*, z*, t2d*: Fe

func toSecretScalar*(bytes: array[32, byte]): SecretScalar {.inline.} =
  ## Explicit, grep-able construction -- the point where a byte array
  ## becomes type-tracked as a secret scalar, mirroring
  ## `wire.toPublicKey`/`signing.toSeed`'s naming convention.
  SecretScalar(bytes)

func secretScalarBytes*(s: SecretScalar): array[32, byte] {.inline.} =
  ## Explicit, grep-able unwrap. A named accessor rather than a bare
  ## `array[32, byte](s)` cast at each call site (round-3 finding A3(c)):
  ## every place that genuinely needs the raw bytes back (this file's own
  ## `geScalarmultBase`/`scMulAdd`, or a future caller with a real reason)
  ## greps for this one name instead of an invisible cast scattered through
  ## the codebase -- the same "one audited door" register as
  ## `field.feFromLimbs`/`wire.toBytes`.
  array[32, byte](s)

# ---------------------------------------------------------------------------
# Curve constants (ref10)
# ---------------------------------------------------------------------------

const
  Ed25519D_Raw*: array[10, int32] = [
    -10913610'i32, 13857413, -15372611, 6949391, 114729,
    -8787816, -6275908, -3247719, -18696448, -12055116
  ]

  Ed25519Gx_Raw*: array[10, int32] = [
    -14297830'i32, -7645148, 16144683, -16471763, 27570974,
    -2696100, -26142465, 8378389, 20764389, 8758491
  ]

  Ed25519Gy_Raw*: array[10, int32] = [
    -26843541'i32, -6710886, 13421773, -13421773, 26843546,
    6710886, -13421773, 13421773, -26843546, -6710886
  ]

# sqrt(-1) mod p (RFC-003 slice 1 item 3) moved to field.nim, not kept
# here: unlike Ed25519D_Raw/Gx_Raw/Gy_Raw above (which encode the curve
# equation and base point -- genuinely curve-specific), sqrt(-1) is a
# property of the field GF(p) alone, with no curve knowledge baked in. Its
# consumer, the ed25519 point-decode sqrt-ratio step, is now
# `field.feSqrtRatioM1` (RFC-004 slice 1c migrated `ed25519.pointDecode`
# off the original `field.feSqrtRatioVartime`, since deleted, onto this
# constant-time primitive -- a field.nim primitive either way, so a
# Ristretto decode can reuse it without importing this curve-ops module)
# -- see that function's doc comment for the constant itself.

# ---------------------------------------------------------------------------
# Conversions, group operations, and fixed-base scalarmult's table build +
# constant-time select (RFC-001 finding 1): this whole region, through
# cmovCached below, is the point-arithmetic core reachable from
# geScalarmultBase, which runs on secret scalars (the signer's `a` and
# nonce `r` -- see backend.nim). Pushed checks-off for the same CT reason
# as this file's other two regions: Nim's push/pop is lexical, so a caller
# elsewhere in the codebase disabling checks (x25519.nim, backend.nim) does
# NOT cover these callees, and left as `checks: on` every one of them would
# compile in a bounds/overflow branch on secret-derived limb values --
# exactly the branch-on-secret-data the CT discipline forbids. geAdd/the
# P1P1-to-P2/P3 conversions/geP2Dbl are also the verify-only
# `scalarmultVartime`'s callees (below); that function has no CT
# requirement of its own, but shares these functions with the
# secret-facing path, so it picks up checks-off too as an accepted side
# effect (same precedent as `verify`'s calls into the scReduce/pointEncode
# group further down this file).
# ---------------------------------------------------------------------------

{.push checks: off.}

func geP3ToCached*(r: var GeCached; p: GeP3) {.inline.} =
  feAdd(r.yPlusX, p.y, p.x)
  feSub(r.yMinusX, p.y, p.x)
  r.z = p.z
  let D = feFromLimbs(Ed25519D_Raw)
  var tD: Fe
  feMul(tD, p.t, D)
  feAdd(r.t2d, tD, tD)  # t2d = 2*d*T

func geP1P1ToP2*(r: var GeP2; p: GeP1P1) {.inline.} =
  feMul(r.x, p.x, p.t)
  feMul(r.y, p.y, p.z)
  feMul(r.z, p.z, p.t)

func geP1P1ToP3*(r: var GeP3; p: GeP1P1) {.inline.} =
  feMul(r.x, p.x, p.t)
  feMul(r.y, p.y, p.z)
  feMul(r.z, p.z, p.t)
  feMul(r.t, p.x, p.y)

func geP3ToP2*(r: var GeP2; p: GeP3) {.inline.} =
  r.x = p.x
  r.y = p.y
  r.z = p.z

# ---------------------------------------------------------------------------
# Group operations
# ---------------------------------------------------------------------------

func geP2Dbl*(r: var GeP1P1; p: GeP2) {.inline.} =
  ## Point doubling: 2*P  (input P2, output completed P1P1).
  ## Verbatim ref10 ge_p2_dbl (public domain). The P1P1 stores the four
  ## completed-point components; geP1P1ToP2/P3 forms the products. (a = -1.)
  var t0: Fe
  feSq(r.x, p.x)            # X^2
  feSq(r.z, p.y)            # Y^2
  feSq2(r.t, p.z)           # 2*Z^2
  feAdd(r.y, p.x, p.y)      # X+Y
  feSq(t0, r.y)             # (X+Y)^2
  feAdd(r.y, r.z, r.x)      # Y^2 + X^2
  feSub(r.z, r.z, r.x)      # Y^2 - X^2
  feSub(r.x, t0, r.y)       # (X+Y)^2 - (X^2+Y^2)
  feSub(r.t, r.t, r.z)      # 2*Z^2 - (Y^2-X^2)

func geAdd*(r: var GeP1P1; p: GeP3; q: GeCached) {.inline.} =
  ## Group addition: p + q  (p in P3, q in GeCached, result in completed P1P1).
  ## Verbatim ref10 ge_add (public domain).
  var A, B, C, D: Fe
  feAdd(A, p.y, p.x)        # Y+X
  feSub(B, p.y, p.x)        # Y-X
  feMul(A, A, q.yPlusX)     # (Y+X)(Yq+Xq)
  feMul(B, B, q.yMinusX)    # (Y-X)(Yq-Xq)
  feMul(C, q.t2d, p.t)      # 2d*Tq*T
  feMul(D, p.z, q.z)        # Z*Zq
  feAdd(D, D, D)            # 2*Z*Zq
  feSub(r.x, A, B)          # X = (Y+X)(Yq+Xq) - (Y-X)(Yq-Xq)
  feAdd(r.y, A, B)          # Y = (Y+X)(Yq+Xq) + (Y-X)(Yq-Xq)
  feAdd(r.z, D, C)          # Z = 2*Z*Zq + C
  feSub(r.t, D, C)          # T = 2*Z*Zq - C

func geP3Identity(): GeP3 {.inline.} =
  ## The extended-coordinate identity point (0, 1, 1, 0). RFC-004 slice 7a
  ## consolidation (optional per that RFC's own slice text, taken here
  ## since `geScalarmultCT` below makes this the THIRD inline construction
  ## of the identity in this file -- `scalarmultVartime`'s `pts[0]` and
  ## `geScalarmultBase`'s `acc` init, both refactored to call this instead,
  ## field-for-field identical to what they wrote before, a pure rename
  ## with no behavior change). Not exported: every caller lives in this
  ## file.
  result.x = FeZero
  result.y = FeOne
  result.z = FeOne
  result.t = FeZero

# ---------------------------------------------------------------------------
# Scalar multiplication: variable-base, unsigned 4-bit windows
# ---------------------------------------------------------------------------

func scalarmultVartime*(r: var GeP3; s: array[32, byte]; p: GeP3) =
  ## r = [s]p — variable-base scalar multiplication.
  ## Uses unsigned 4-bit windows (nibbles 0..15), high-first.
  ##
  ## RFC-001 finding 8: named `*Vartime` (not plain `scalarmult`) so every
  ## call site self-flags — this function has no constant-time requirement
  ## and never runs on a secret scalar (verify-only: `ed25519.verify`'s
  ## [S]B and [k]A, plus this file's own base-table-vs-runtime standing-
  ## guard test). Before this rename, it was distinguishable from the CT
  ## signer code sharing this file (`geScalarmultBase`/`cmovCached`) only
  ## by a doc comment — the same mistake class the project already
  ## eliminated at the ed25519.nim/private/backend.nim boundary (verify
  ## vs. sign, one import away from each other, no naming cue). Do NOT add
  ## the signer's secret scalar to this function.
  var pts: array[16, GeP3]
  var cch: array[16, GeCached]
  var tmp2: GeP2
  var dbl: GeP1P1

  # Build pts[0] = identity, pts[1] = P, pts[2] = 2P, ..., pts[15] = 15P
  # Then cch[k] = cached(pts[k]).
  pts[0] = geP3Identity()
  geP3ToCached(cch[0], pts[0])

  pts[1] = p
  geP3ToCached(cch[1], pts[1])

  for i in countup(2, 15):
    geAdd(dbl, pts[i-1], cch[1])   # pts[i] = pts[i-1] + P
    geP1P1ToP3(pts[i], dbl)
    geP3ToCached(cch[i], pts[i])

  # Process nibbles from high to low. `r` is seeded with the identity
  # up front (RFC-004 slice 7a finding, discovered while cross-checking
  # `geScalarmultCT` against this function at s=0 via `pointEncode`
  # rather than `RistrettoPoint`'s quotient `==`, which degenerately
  # accepts the all-zero (0:0:0:0) GeP3 Nim's implicit object
  # zero-initialization used to leave `r` as -- every cross-product in the
  # quotient-equality check collapses to 0 when x1=y1=0, so an all-zero
  # `r` passed as "equal to the identity" without actually holding it):
  # for an all-zero `s`, `started` never flips true and the loop below
  # never assigns to `r` at all, so without this line the caller's `var r:
  # GeP3` would be returned exactly as it arrived (implicit all-zero
  # fields for a freshly-declared local, not the mathematically correct
  # identity [0]p). Harmless for every `started = true` path: the first
  # nonzero digit's `r = pts[window]` (below) overwrites this
  # unconditionally, so this line changes output only for the all-zero-
  # scalar case.
  r = pts[0]
  var started = false

  for i in countdown(63, 0):
    let b = int(s[i shr 1])
    let window = (b shr (4 * (i and 1))) and 0xF

    if started:
      # Double r four times (16 = 2^4)
      geP3ToP2(tmp2, r)
      for j in 0..<4:
        geP2Dbl(dbl, tmp2)
        if j < 3:
          geP1P1ToP2(tmp2, dbl)
        else:
          geP1P1ToP3(r, dbl)

    if window != 0:
      if not started:
        r = pts[window]
        started = true
      else:
        geAdd(dbl, r, cch[window])
        geP1P1ToP3(r, dbl)

# ---------------------------------------------------------------------------
# Fixed-base scalar multiplication: compile-time table + constant-time select
#
# Table layout (ref10 ge_scalarmult_base structure; GeCached deviation is a
# round-1 RFC-001 decision — no ge_precomp/ge_madd port, since geAdd
# already handles a GeCached operand): GeBaseTable[i][j] caches the point
# (j+1) * 16^(2*i) * B for i in 0..31, j in 0..7 — row i holds the 8 nonzero
# multiples of B scaled by 256^i. geScalarmultBase (below) recodes a scalar
# into 64 signed radix-16 digits and consumes this same table twice: once
# for the odd digit positions summed directly, then the accumulator is
# scaled by 16 (four doublings), then the even digit positions, exactly as
# ref10 does.
# ---------------------------------------------------------------------------

func geBasePoint*(): GeP3 =
  ## The RFC 8032 base point B, in extended coordinates.
  result.x = feFromLimbs(Ed25519Gx_Raw)
  result.y = feFromLimbs(Ed25519Gy_Raw)
  result.z = FeOne
  feMul(result.t, result.x, result.y)

func geP3Double(p: GeP3): GeP3 =
  var p2: GeP2
  geP3ToP2(p2, p)
  var d: GeP1P1
  geP2Dbl(d, p2)
  geP1P1ToP3(result, d)

func geP3AddCached(p: GeP3; q: GeCached): GeP3 =
  var d: GeP1P1
  geAdd(d, p, q)
  geP1P1ToP3(result, d)

func buildBaseTable(): array[32, array[8, GeCached]] =
  ## Computes GeBaseTable at compile time: 31*8 = 248 doublings step each
  ## row's base point to the next (256 = 16^2 per row), plus 7 additions per
  ## row to build multiples 2..8 from 1 — verified in-container (~1s,
  ## byte-exact against runtime scalarmultVartime; see the standing-guard
  ## test in tests/unit/test_scalar.nim, which re-checks this every
  ## `scripts/test.sh` run since this repo has no CI to rely on instead).
  var rowBase = geBasePoint()
  for i in 0..<32:
    if i > 0:
      for _ in 0..<8:
        rowBase = geP3Double(rowBase)
    var rowBaseCached: GeCached
    geP3ToCached(rowBaseCached, rowBase)
    geP3ToCached(result[i][0], rowBase)
    var acc = rowBase
    for j in 1..<8:
      acc = geP3AddCached(acc, rowBaseCached)
      geP3ToCached(result[i][j], acc)

const GeBaseTable*: array[32, array[8, GeCached]] = buildBaseTable()

func cmovCached*(r: var GeCached; table: array[8, GeCached]; digit: int32) {.noinline.} =
  ## Constant-time select of the `digit`-th multiple of a base-table row
  ## (a row of GeBaseTable, or any array of 8 GeCached entries holding
  ## 1*P..8*P), with conditional negation for negative digits. `digit`
  ## ranges over [-8, 8] (see geScalarmultBase's recoding, slice 4).
  ##
  ## Full 8-entry scan on every call — fixed, secret-independent iteration
  ## count, no early exit — with `r` identity-initialized first, so digit 0
  ## selects the identity with no special case. Selection and negation
  ## masks are derived arithmetically from `digit` (the feCMove/feCSwap
  ## family); nothing here branches on `digit`'s value or sign. `{.noinline.}`
  ## (RFC-001 slice 8): this is itself a masking helper built on
  ## `feCMove`/`feCSwap`, same rationale as those two (see `field.nim`).
  r.yPlusX = FeOne
  r.yMinusX = FeOne
  r.z = FeOne
  r.t2d = FeZero

  let isNeg = digit < 0
  let signMask = valueBarrier32(-int32(isNeg))
    ## `valueBarrier32` (RFC-005 fix-slice 22a): same clang
    ## branch-synthesis finding and remedy as `field.feCMove`/`feCSwap`'s
    ## own masks (this function's `isNeg`-derived mask is the third and
    ## last of the codebase's three secret-derived mask construction
    ## sites) -- see `private/ct.nim`'s "The value barrier" doc section.
  let absDigit = (digit xor signMask) - signMask  # branchless abs

  for i in 1..8:
    let match = absDigit == int32(i)
    feCMove(r.yPlusX, table[i - 1].yPlusX, match)
    feCMove(r.yMinusX, table[i - 1].yMinusX, match)
    feCMove(r.z, table[i - 1].z, match)
    feCMove(r.t2d, table[i - 1].t2d, match)

  # Conditional negation of a GeCached entry (RFC-001): swap(yPlusX,
  # yMinusX); t2d = -t2d; z unchanged.
  feCSwap(r.yPlusX, r.yMinusX, isNeg)
  var negT2d: Fe
  feNeg(negT2d, r.t2d)
  feCMove(r.t2d, negT2d, isNeg)

{.pop.}

# ---------------------------------------------------------------------------
# Fixed-base scalar multiplication: signed radix-16 recoding + table consume
# (RFC-001 slice 4). Ports ref10 ge_scalarmult_base's digit/consumption
# structure (public domain).
#
# Precondition — the WHOLE precondition, stated here and repeated on
# geScalarmultBase's doc comment because it is easy to over-tighten: bit
# 255 of the scalar is 0. This function serves two scalar domains: clamped
# secret scalars (bit 255 clear, bit 254 set) and reduced nonces
# r = scReduce(...) < L (top three bits always clear, since L < 2^253). Do
# NOT assert clamped shape (bit 254 set) — that would reject every real
# r-shaped scalar `sign` computes R = [r]B with.
#
# Both functions are secret-facing (the scalar recoded here is `a` or `r`
# in the eventual sign path), so checks are pushed off as elsewhere in this
# file's sc* group.
# ---------------------------------------------------------------------------

{.push checks: off.}

func recodeScalarRadix16*(s: array[32, byte]): array[64, int32] =
  ## 64 nibbles of `s` -> 64 signed digits via carry propagation (ref10's
  ## e[] step, public domain). Range is asymmetric: digits[0..62] land in
  ## [-8, 7]; only digit[63] can reach +8 (bit 255 clear bounds its
  ## pre-carry nibble to at most 7, and only the incoming final carry can
  ## push it to 8 — a mid-position 8 would be a carry bug, not valid
  ## output). No data-dependent branches: every step runs on a fixed
  ## 64-iteration schedule regardless of the digit values produced.
  for i in 0 ..< 32:
    result[2 * i] = int32(s[i] and 0xF)
    result[2 * i + 1] = int32((s[i] shr 4) and 0xF)

  var carry: int32 = 0
  for i in 0 ..< 63:
    result[i] += carry
    carry = (result[i] + 8) shr 4
    result[i] -= carry shl 4
  result[63] += carry

func geScalarmultBase*(s: SecretScalar): GeP3 =
  ## r = [s]B — fixed-base scalar multiplication via the compile-time
  ## GeBaseTable and cmovCached's constant-time select. Ports ref10's
  ## ge_scalarmult_base structure (public domain): recode into signed
  ## radix-16 digits, consume the table for the 32 odd digit positions,
  ## scale the accumulator by 16 (four doublings), then consume it again
  ## for the 32 even positions. Uses plain geAdd throughout — no
  ## ge_madd/ge_msub port — because cmovCached's conditional negation
  ## already produces the correctly-signed cached point for negative
  ## digits (the GeCached-table deviation carried over from slice 3).
  ##
  ## Precondition: bit 255 of `s` is 0 — see recodeScalarRadix16's doc
  ## comment; do not additionally require clamped shape. Branchless on
  ## `s`: recoding is carry-propagation arithmetic and every table lookup
  ## goes through cmovCached's full 8-entry scan.
  ##
  ## `s: SecretScalar`, not a bare `array[32, byte]` (round-3 finding A3):
  ## this is the one entry point `private/backend.nim` hands a real secret
  ## scalar to, so this is where the type boundary belongs -- see
  ## `SecretScalar`'s own doc comment above for the full home/scope
  ## reasoning. `secretScalarBytes(s)` below is the explicit, grep-able
  ## unwrap for the two places genuinely below the type boundary
  ## (the bit-255 precondition check, `recodeScalarRadix16`'s byte-level
  ## input).
  ##
  ## RFC finding R1: every secret local this function touches --
  ## `sBytes` (a fresh copy of the raw secret scalar), `digits` (its
  ## directly-invertible radix-16 decomposition), and the secret-dependent
  ## point accumulators `acc`/`u`/`step` -- is wiped via `ct.wipe` under
  ## the same `try`/`finally` net `private/backend.nim` uses (RFC-001
  ## ledger finding 18): `sBytes` is wiped early, the moment `digits`
  ## supersedes it (a genuine lifetime reduction), and everything --
  ## `sBytes` included -- is wiped once in `finally`, which runs on every
  ## exit path (nothing in this body raises, so the non-happy path is a
  ## defensive, currently-unreachable net). The wipes live in `finally`
  ## ONLY, not duplicated at the end of `try` -- the stage-4 review
  ## (finding 6) retired the earlier end-of-try copies as zero-benefit
  ## redundancy (`finally` runs immediately after; no lifetime was
  ## shortened), converging on the register `x25519`'s overloads and
  ## `ristretto.ristrettoEncode` already use. `result = acc` copies `acc`'s
  ## value out before `acc` itself is wiped, so the wipe cannot affect the
  ## returned point.
  # Debug-only precondition check (RFC-002 slice 2 item 3a): plain
  # `assert`, meant to be absent from the dudect-measured `-d:release`
  # build (and every downstream consumer's release build) entirely, so it
  # never touches this function's constant-time shape there.
  #
  # Deviation from the RFC's literal mechanism, forced by empirical Nim
  # 2.2.10 behavior (verified with isolated scratch probes, not assumed):
  # the RFC's stated rationale, "plain assert -- stripped by -d:release",
  # does NOT hold in this toolchain -- `-d:release` alone leaves
  # `assertions` on; only `-d:danger` disables them by default. Worse,
  # this whole function already sits under the file's `checks: off`
  # region, and Nim's `checks` umbrella bundles `assertions` together with
  # bounds/overflow/nil checks, so a bare `assert` written directly here
  # would be silently compiled out UNCONDITIONALLY (debug and release
  # alike) rather than tracking any release/debug split at all. `when not
  # defined(release)` sidesteps both problems at once: under `-d:release`
  # the whole block is omitted from compilation, full stop, matching the
  # RFC's actual intent more literally than its stated mechanism did;
  # under a plain debug build, `{.push assertions: on.}` locally overrides
  # the surrounding `checks: off` region just for this statement, so the
  # assert can actually fire. (Same empirical-deviation register as
  # `signing.Seed`'s `distinct array` fallback -- see that module's doc
  # comment.)
  var sBytes = secretScalarBytes(s)
  when not defined(release):
    {.push assertions: on.}
    assert (sBytes[31] and 0x80'u8) == 0, "geScalarmultBase: bit 255 of s must be 0"
    {.pop.}
  var digits = recodeScalarRadix16(sBytes)

  var acc: GeP3 = geP3Identity()

  var u: GeCached
  var step: GeP1P1

  try:
    ct.wipe(sBytes)

    for i in countup(1, 63, 2):
      cmovCached(u, GeBaseTable[i div 2], digits[i])
      geAdd(step, acc, u)
      geP1P1ToP3(acc, step)

    for _ in 0 ..< 4:
      acc = geP3Double(acc)

    for i in countup(0, 62, 2):
      cmovCached(u, GeBaseTable[i div 2], digits[i])
      geAdd(step, acc, u)
      geP1P1ToP3(acc, step)

    result = acc
  finally:
    ct.wipe(sBytes)
    ct.wipe(digits)
    ct.wipe(acc)
    ct.wipe(u)
    ct.wipe(step)

{.pop.}

# ---------------------------------------------------------------------------
# Variable-base CONSTANT-TIME scalar multiplication (RFC-004 slice 7a).
#
# This is Ristretto255's headline new secret-scalar operation: `[s]P` for a
# secret `s` and an ARBITRARY (not fixed) point `P` -- the operation OPRF
# evaluation, Pedersen commitments, and ElGamal-style DH shares over the
# group all need, and the one operation the fixed-base-only pair
# (`geScalarmultBase`/`scalarmultVartime`) cannot provide safely (the
# former is fixed-base only; the latter is variable-base but vartime).
#
# **UNIFORM interleaved ladder, NOT geScalarmultBase's odds/x16/evens
# shape** (RFC-004 Design, rounds 1-2): `geScalarmultBase`'s table is built
# at COMPILE TIME with every row `i` pre-scaled by 16^(2*i) -- that
# factoring is exactly what lets it split 64 digits into two half-passes
# with one 4-doubling scale-by-16 between them, touching the table twice.
# A single RUNTIME table built from an arbitrary `p` (below) has no such
# pre-scaling available, so cloning that shape here would compute the
# WRONG multiple. Instead, the standard interleaved high-to-low form: the
# accumulator starts at the identity, and for each of the 64 signed
# radix-16 digits of `s`, high to low, four doublings of the accumulator
# are followed by one constant-time table select + add -- a UNIFORM 256
# doublings + 64 adds, every iteration identical in shape. The first
# iteration's four doublings act on the identity and are deliberately NOT
# special-cased away: an initial-load idiom (skip the first four doublings,
# reconstruct the accumulator from the selected `GeCached` directly) would
# save about 1.5% of the doublings at the cost of a second, non-uniform
# loop shape for the exact-string mutation catalog and cost model to track
# separately -- not worth it for a ~1.5% constant.
#
# **Table build is PUBLIC, not CT.** `p` is a public group element in every
# protocol this operation serves -- a Pedersen commitment before
# publication, an OPRF blinded element -- the SECRET is the scalar `s`,
# never the point being multiplied (see `ristretto.nim`'s module-doc
# headline for the full posture this rests on). Building the 8-entry table
# `[1*P .. 8*P]` at runtime therefore carries no CT obligation, and reuses
# `scalarmultVartime`'s own table-build pattern (above in this file): plain
# `geAdd` -> `geP1P1ToP3` -> `geP3ToCached`, sized to 8 rather than that
# function's 16 since `cmovCached`'s built-in conditional negation already
# covers the negative half of the signed [-8, 8] digit domain
# `recodeScalarRadix16` produces -- confirmed against `cmovCached`'s own
# source (round 3): no new CT negate helper is needed. Only the per-digit
# LOOKUP into this table must be constant-time, and it is the exact same
# `cmovCached` select `geScalarmultBase` already uses against its own
# (compile-time, pre-scaled) table -- one audited select, two callers.
#
# **Written loop-composition argument** (RFC-004's symex decline register:
# a whole-loop Z3 query was considered and declined up front, per the
# `symex_reduce.nim` resource-wall precedent, in favor of this written
# argument over already-individually-proven components -- see the RFC's
# Validation battery "symex (Z3)" bullet): the loop below is constant-time
# on `s` because every one of its three moving parts is:
#   1. SHAPE. The loop runs exactly 64 iterations; each does exactly 4
#      doublings (`geP3Double`, itself unconditional field arithmetic --
#      `geP3ToP2`/`geP2Dbl`/`geP1P1ToP3` contain no data-dependent branch)
#      plus exactly one `cmovCached` select and one `geAdd`/`geP1P1ToP3`.
#      The iteration COUNT and the operation SEQUENCE within an iteration
#      never depend on `digits[i]`'s VALUE -- only on the loop index `i`,
#      which is a compile-time-fixed schedule, not data derived from `s`.
#   2. SELECTION. The one data-dependent step -- choosing which table
#      entry (and its sign) feeds the add -- routes entirely through
#      `cmovCached`, whose masked-select/masked-negate arithmetic is
#      machine-checked full-domain in `tests/verify/symex_mask.nim`
#      (`cmoveSelectStep`/`cswapSelectStep`), and whose own 8-entry scan is
#      itself a fixed, secret-independent iteration count with no early
#      exit.
#   3. RECODING. `digits` comes from `recodeScalarRadix16`, whose
#      digit-range invariant is machine-checked in
#      `tests/verify/symex_recode.nim` (the per-iteration lemma plus the
#      63-step composition, both `sxUnsat`) and whose own body is
#      unconditional carry-propagation arithmetic with no branch on `s`'s
#      byte values. Its one precondition (bit 255 of `s` clear) is
#      discharged below, the same debug-only assert `geScalarmultBase`
#      carries.
# Composing (1)-(3): the loop's total instruction sequence and iteration
# count are fixed at compile time, and the only quantities that vary with
# `s` are field-arithmetic operand VALUES flowing through already-CT
# primitives -- exactly the composition argument `geScalarmultBase` above
# already rests on for its own two half-passes, extended here to one
# uniform pass over a runtime table. No new solver query is introduced
# because no new primitive is: `geAdd`, `geP3Double`, `cmovCached`, and
# `recodeScalarRadix16` are all pure reuse, individually already proven.
# ---------------------------------------------------------------------------

{.push checks: off.}

func geScalarmultCT*(s: SecretScalar; p: GeP3): GeP3 =
  ## r = [s]p — variable-base scalar multiplication, CONSTANT-TIME on `s`.
  ## The CT sibling of `geScalarmultBase` (CT fixed-base) and
  ## `scalarmultVartime` (vartime variable-base) -- see the region doc
  ## comment immediately above for the full ladder-shape/table-build/
  ## loop-composition writeup; not repeated per-line here.
  ##
  ## Precondition: bit 255 of `s` is 0 -- identical to `geScalarmultBase`'s
  ## own precondition (see `recodeScalarRadix16`'s doc comment), discharged
  ## by construction for every real caller: the secret role types
  ## consuming this (`ristretto.RistrettoStaticSecret`/
  ## `RistrettoEphemeralSecret`) hold only canonical residues mod L
  ## (< L < 2^253).
  ##
  ## `s: SecretScalar`, not a bare `array[32, byte]` (matching
  ## `geScalarmultBase`'s own type boundary, round-3 finding A3): this is
  ## an entry point a real caller (`ristretto.ristrettoScalarmult`) hands a
  ## real secret scalar to.
  ##
  ## Wipe discipline (RFC finding R1, extended to this function by RFC-004
  ## slice 7a): every secret local this function touches -- `sBytes` (a
  ## fresh copy of the raw secret scalar), `digits` (its directly-
  ## invertible radix-16 decomposition), the secret-dependent accumulator
  ## `acc`, and the two per-iteration temporaries `u` (the
  ## `cmovCached`-selected `GeCached`) and `step` (the completed-point
  ## temp) -- is wiped via `ct.wipe` under the same `try`/`finally` net
  ## `geScalarmultBase` uses (early `sBytes` wipe + finally-only full
  ## wipe; see that function's doc comment for the stage-4 finding-6
  ## rationale retiring the old end-of-try duplicate wipes). `u`/`step`
  ## are declared
  ## ONCE outside the loop and reused every iteration (`geScalarmultBase`'s
  ## own pattern): only their FINAL leftover values persist on the stack
  ## once the loop ends, so one wipe after the loop covers every
  ## iteration's stale value, not just the last -- each earlier iteration's
  ## value was already overwritten by the next iteration's `cmovCached`/
  ## `geAdd` call before this function returns. The runtime table
  ## (`table`/`pts` below) is PUBLIC (see the region doc comment) and is
  ## NOT wiped -- same register as `GeBaseTable` (unwiped, compile-time,
  ## public) and `scalarmultVartime`'s own `pts`/`cch` tables.
  ## `result = acc` copies `acc`'s value out before `acc` itself is wiped,
  ## so the wipe cannot affect the returned point.
  var sBytes = secretScalarBytes(s)
  when not defined(release):
    {.push assertions: on.}
    assert (sBytes[31] and 0x80'u8) == 0, "geScalarmultCT: bit 255 of s must be 0"
    {.pop.}
  var digits = recodeScalarRadix16(sBytes)

  # Runtime table build: [1*P .. 8*P], PUBLIC (see region doc comment) --
  # scalarmultVartime's own geAdd -> geP1P1ToP3 -> geP3ToCached pattern,
  # sized to 8 (not that function's 16) since cmovCached's built-in
  # negation already covers digits -1..-8.
  var pts: array[8, GeP3]
  var table: array[8, GeCached]
  pts[0] = p
  geP3ToCached(table[0], pts[0])
  for i in 1 ..< 8:
    var step0: GeP1P1
    geAdd(step0, pts[i - 1], table[0])
    geP1P1ToP3(pts[i], step0)
    geP3ToCached(table[i], pts[i])

  var acc: GeP3 = geP3Identity()
  var u: GeCached
  var step: GeP1P1

  try:
    ct.wipe(sBytes)

    for i in countdown(63, 0):
      for _ in 0 ..< 4:
        acc = geP3Double(acc)
      cmovCached(u, table, digits[i])
      geAdd(step, acc, u)
      geP1P1ToP3(acc, step)

    result = acc
  finally:
    ct.wipe(sBytes)
    ct.wipe(digits)
    ct.wipe(acc)
    ct.wipe(u)
    ct.wipe(step)

{.pop.}

# ---------------------------------------------------------------------------
# Point encoding and scalar reduction/canonicity (RFC 8032 §5.1) —
# relocated from ed25519.nim / extracted from its verify. (The shared
# `challenge` hash that used to live at the end of this group moved out to
# `sello/challenge.nim` in RFC-002 slice 2, taking this file's only
# nimcrypto import with it.)
#
# RFC 8032 signing must run scReduce over secret-derived values (the nonce
# hash) and needs pointEncode for R and A, but ed25519.nim's whole identity
# is "verify-only, never touches a secret" — so this group lives here
# instead (ref10 keeps the sc25519_*/ge_* families together for the same
# reason), and ed25519.nim imports it back. Pushed checks-off: these
# functions index fixed-size arrays at compile-time-constant offsets (not a
# CT requirement by itself), and will see secret-derived input once signing
# lands. verify's calls into this group now also run checks-off as an
# accepted side effect, not because verify needs it.
# ---------------------------------------------------------------------------

{.push checks: off.}

func pointEncode*(p: GeP3): array[32, byte] =
  var zInv, x, y: Fe
  feInvert(zInv, p.z)
  feMul(x, p.x, zInv)
  feMul(y, p.y, zInv)
  var enc = feToBytes(y)
  if feIsNegative(x):
    enc[31] = enc[31] or 0x80'u8
  return enc

# Subgroup order L (RFC 8032 §5.1).
const
  L*: array[32, byte] = [
    0xED'u8, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58,
    0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
  ]

func load3(s: openArray[byte]; off: int): int64 {.inline.} =
  int64(s[off]) or (int64(s[off + 1]) shl 8) or (int64(s[off + 2]) shl 16)

func load4(s: openArray[byte]; off: int): int64 {.inline.} =
  int64(s[off]) or (int64(s[off + 1]) shl 8) or
    (int64(s[off + 2]) shl 16) or (int64(s[off + 3]) shl 24)

func scReduce*(o: var array[32, byte]; s: array[64, byte]) =
  ## Reduce 512-bit scalar modulo L. Ported from libsodium ref10 sc25519_reduce.
  const M = 0x1FFFFF'i64
  var s0  = M and load3(s, 0)
  var s1  = M and (load4(s, 2) shr 5)
  var s2  = M and (load3(s, 5) shr 2)
  var s3  = M and (load4(s, 7) shr 7)
  var s4  = M and (load4(s, 10) shr 4)
  var s5  = M and (load3(s, 13) shr 1)
  var s6  = M and (load4(s, 15) shr 6)
  var s7  = M and (load3(s, 18) shr 3)
  var s8  = M and load3(s, 21)
  var s9  = M and (load4(s, 23) shr 5)
  var s10 = M and (load3(s, 26) shr 2)
  var s11 = M and (load4(s, 28) shr 7)
  var s12 = M and (load4(s, 31) shr 4)
  var s13 = M and (load3(s, 34) shr 1)
  var s14 = M and (load4(s, 36) shr 6)
  var s15 = M and (load3(s, 39) shr 3)
  var s16 = M and load3(s, 42)
  var s17 = M and (load4(s, 44) shr 5)
  var s18 = M and (load3(s, 47) shr 2)
  var s19 = M and (load4(s, 49) shr 7)
  var s20 = M and (load4(s, 52) shr 4)
  var s21 = M and (load3(s, 55) shr 1)
  var s22 = M and (load4(s, 57) shr 6)
  var s23 = load4(s, 60) shr 3

  s11 += s23 * 666643
  s12 += s23 * 470296
  s13 += s23 * 654183
  s14 -= s23 * 997805
  s15 += s23 * 136657
  s16 -= s23 * 683901

  s10 += s22 * 666643
  s11 += s22 * 470296
  s12 += s22 * 654183
  s13 -= s22 * 997805
  s14 += s22 * 136657
  s15 -= s22 * 683901

  s9 += s21 * 666643
  s10 += s21 * 470296
  s11 += s21 * 654183
  s12 -= s21 * 997805
  s13 += s21 * 136657
  s14 -= s21 * 683901

  s8 += s20 * 666643
  s9 += s20 * 470296
  s10 += s20 * 654183
  s11 -= s20 * 997805
  s12 += s20 * 136657
  s13 -= s20 * 683901

  s7 += s19 * 666643
  s8 += s19 * 470296
  s9 += s19 * 654183
  s10 -= s19 * 997805
  s11 += s19 * 136657
  s12 -= s19 * 683901

  s6 += s18 * 666643
  s7 += s18 * 470296
  s8 += s18 * 654183
  s9 -= s18 * 997805
  s10 += s18 * 136657
  s11 -= s18 * 683901

  var carry6  = (s6  + (1'i64 shl 20)) shr 21; s7  += carry6;  s6  -= carry6 shl 21
  var carry8  = (s8  + (1'i64 shl 20)) shr 21; s9  += carry8;  s8  -= carry8 shl 21
  var carry10 = (s10 + (1'i64 shl 20)) shr 21; s11 += carry10; s10 -= carry10 shl 21
  var carry12 = (s12 + (1'i64 shl 20)) shr 21; s13 += carry12; s12 -= carry12 shl 21
  var carry14 = (s14 + (1'i64 shl 20)) shr 21; s15 += carry14; s14 -= carry14 shl 21
  var carry16 = (s16 + (1'i64 shl 20)) shr 21; s17 += carry16; s16 -= carry16 shl 21

  var carry7  = (s7  + (1'i64 shl 20)) shr 21; s8  += carry7;  s7  -= carry7 shl 21
  var carry9  = (s9  + (1'i64 shl 20)) shr 21; s10 += carry9;  s9  -= carry9 shl 21
  var carry11 = (s11 + (1'i64 shl 20)) shr 21; s12 += carry11; s11 -= carry11 shl 21
  var carry13 = (s13 + (1'i64 shl 20)) shr 21; s14 += carry13; s13 -= carry13 shl 21
  var carry15 = (s15 + (1'i64 shl 20)) shr 21; s16 += carry15; s15 -= carry15 shl 21

  s5 += s17 * 666643
  s6 += s17 * 470296
  s7 += s17 * 654183
  s8 -= s17 * 997805
  s9 += s17 * 136657
  s10 -= s17 * 683901

  s4 += s16 * 666643
  s5 += s16 * 470296
  s6 += s16 * 654183
  s7 -= s16 * 997805
  s8 += s16 * 136657
  s9 -= s16 * 683901

  s3 += s15 * 666643
  s4 += s15 * 470296
  s5 += s15 * 654183
  s6 -= s15 * 997805
  s7 += s15 * 136657
  s8 -= s15 * 683901

  s2 += s14 * 666643
  s3 += s14 * 470296
  s4 += s14 * 654183
  s5 -= s14 * 997805
  s6 += s14 * 136657
  s7 -= s14 * 683901

  s1 += s13 * 666643
  s2 += s13 * 470296
  s3 += s13 * 654183
  s4 -= s13 * 997805
  s5 += s13 * 136657
  s6 -= s13 * 683901

  s0 += s12 * 666643
  s1 += s12 * 470296
  s2 += s12 * 654183
  s3 -= s12 * 997805
  s4 += s12 * 136657
  s5 -= s12 * 683901
  s12 = 0

  var carry0 = (s0 + (1'i64 shl 20)) shr 21; s1 += carry0; s0 -= carry0 shl 21
  var carry2 = (s2 + (1'i64 shl 20)) shr 21; s3 += carry2; s2 -= carry2 shl 21
  var carry4 = (s4 + (1'i64 shl 20)) shr 21; s5 += carry4; s4 -= carry4 shl 21
  carry6 = (s6 + (1'i64 shl 20)) shr 21; s7 += carry6; s6 -= carry6 shl 21
  carry8 = (s8 + (1'i64 shl 20)) shr 21; s9 += carry8; s8 -= carry8 shl 21
  carry10 = (s10 + (1'i64 shl 20)) shr 21; s11 += carry10; s10 -= carry10 shl 21

  var carry1 = (s1 + (1'i64 shl 20)) shr 21; s2 += carry1; s1 -= carry1 shl 21
  var carry3 = (s3 + (1'i64 shl 20)) shr 21; s4 += carry3; s3 -= carry3 shl 21
  var carry5 = (s5 + (1'i64 shl 20)) shr 21; s6 += carry5; s5 -= carry5 shl 21
  carry7 = (s7 + (1'i64 shl 20)) shr 21; s8 += carry7; s7 -= carry7 shl 21
  carry9 = (s9 + (1'i64 shl 20)) shr 21; s10 += carry9; s9 -= carry9 shl 21
  carry11 = (s11 + (1'i64 shl 20)) shr 21; s12 += carry11; s11 -= carry11 shl 21

  s0 += s12 * 666643
  s1 += s12 * 470296
  s2 += s12 * 654183
  s3 -= s12 * 997805
  s4 += s12 * 136657
  s5 -= s12 * 683901
  s12 = 0

  carry0 = s0 shr 21; s1 += carry0; s0 -= carry0 shl 21
  carry1 = s1 shr 21; s2 += carry1; s1 -= carry1 shl 21
  carry2 = s2 shr 21; s3 += carry2; s2 -= carry2 shl 21
  carry3 = s3 shr 21; s4 += carry3; s3 -= carry3 shl 21
  carry4 = s4 shr 21; s5 += carry4; s4 -= carry4 shl 21
  carry5 = s5 shr 21; s6 += carry5; s5 -= carry5 shl 21
  carry6 = s6 shr 21; s7 += carry6; s6 -= carry6 shl 21
  carry7 = s7 shr 21; s8 += carry7; s7 -= carry7 shl 21
  carry8 = s8 shr 21; s9 += carry8; s8 -= carry8 shl 21
  carry9 = s9 shr 21; s10 += carry9; s9 -= carry9 shl 21
  carry10 = s10 shr 21; s11 += carry10; s10 -= carry10 shl 21
  carry11 = s11 shr 21; s12 += carry11; s11 -= carry11 shl 21

  s0 += s12 * 666643
  s1 += s12 * 470296
  s2 += s12 * 654183
  s3 -= s12 * 997805
  s4 += s12 * 136657
  s5 -= s12 * 683901

  carry0 = s0 shr 21; s1 += carry0; s0 -= carry0 shl 21
  carry1 = s1 shr 21; s2 += carry1; s1 -= carry1 shl 21
  carry2 = s2 shr 21; s3 += carry2; s2 -= carry2 shl 21
  carry3 = s3 shr 21; s4 += carry3; s3 -= carry3 shl 21
  carry4 = s4 shr 21; s5 += carry4; s4 -= carry4 shl 21
  carry5 = s5 shr 21; s6 += carry5; s5 -= carry5 shl 21
  carry6 = s6 shr 21; s7 += carry6; s6 -= carry6 shl 21
  carry7 = s7 shr 21; s8 += carry7; s7 -= carry7 shl 21
  carry8 = s8 shr 21; s9 += carry8; s8 -= carry8 shl 21
  carry9 = s9 shr 21; s10 += carry9; s9 -= carry9 shl 21
  carry10 = s10 shr 21; s11 += carry10; s10 -= carry10 shl 21

  o[ 0] = byte(s0 shr 0)
  o[ 1] = byte(s0 shr 8)
  o[ 2] = byte((s0 shr 16) or (s1 shl 5))
  o[ 3] = byte(s1 shr 3)
  o[ 4] = byte(s1 shr 11)
  o[ 5] = byte((s1 shr 19) or (s2 shl 2))
  o[ 6] = byte(s2 shr 6)
  o[ 7] = byte((s2 shr 14) or (s3 shl 7))
  o[ 8] = byte(s3 shr 1)
  o[ 9] = byte(s3 shr 9)
  o[10] = byte((s3 shr 17) or (s4 shl 4))
  o[11] = byte(s4 shr 4)
  o[12] = byte(s4 shr 12)
  o[13] = byte((s4 shr 20) or (s5 shl 1))
  o[14] = byte(s5 shr 7)
  o[15] = byte((s5 shr 15) or (s6 shl 6))
  o[16] = byte(s6 shr 2)
  o[17] = byte(s6 shr 10)
  o[18] = byte((s6 shr 18) or (s7 shl 3))
  o[19] = byte(s7 shr 5)
  o[20] = byte(s7 shr 13)
  o[21] = byte(s8 shr 0)
  o[22] = byte(s8 shr 8)
  o[23] = byte((s8 shr 16) or (s9 shl 5))
  o[24] = byte(s9 shr 3)
  o[25] = byte(s9 shr 11)
  o[26] = byte((s9 shr 19) or (s10 shl 2))
  o[27] = byte(s10 shr 6)
  o[28] = byte((s10 shr 14) or (s11 shl 7))
  o[29] = byte(s11 shr 1)
  o[30] = byte(s11 shr 9)
  o[31] = byte(s11 shr 17)

func scIsCanonical*(s: array[32, byte]): bool =
  ## Returns true iff s < L. RFC 8032 §5.1.3 step 12.
  ##
  ## Not constant-time; verify-path only, never on secret-derived data --
  ## this is a vartime, early-exit, MSB-first byte-comparison loop against
  ## L, and its iteration count leaks (via timing) how many leading bytes
  ## of the input agree with L. Correct for `ed25519.verify`'s use (the
  ## signature's `s` scalar is public wire data); wrong for a caller
  ## importing SECRET scalar bytes (e.g. `ristretto.toRistrettoStaticSecret`)
  ## -- use `scIsCanonicalCT` below for that.
  for i in countdown(31, 0):
    if s[i] < L[i]: return true
    if s[i] > L[i]: return false
  return false

func scIsCanonicalCT*(s: array[32, byte]): bool =
  ## Constant-time counterpart to `scIsCanonical` above: identical verdict
  ## (true iff s < L) for every input, computed with no secret-dependent
  ## branch and no early exit -- the `field.feBytesCanonicalCT` register
  ## (that function's doc comment is this one's template) applied to the
  ## scalar side instead of the field side.
  ##
  ## Exists because `ristretto.toRistrettoStaticSecret` (key IMPORT of a
  ## caller-supplied SECRET scalar, dalek's `from_canonical_bytes`
  ## register) was calling the vartime `scIsCanonical` above on secret
  ## data: that loop's iteration count leaks, via timing, how many
  ## leading bytes of the imported secret match L -- the same hazard
  ## class `feBytesCanonicalCT` exists to close on the field side, and
  ## the reason curve25519-dalek's own `Scalar::from_canonical_bytes` is
  ## CT. `ed25519.nim`'s call to `scIsCanonical` (the signature's `s`
  ## scalar, public wire data) is correct as-is and stays vartime -- this
  ## function is for the secret-import path only.
  ##
  ## Computed as a full 32-byte little-endian subtract-with-borrow of
  ## s - L (L's own encoding, like every scalar in this codebase, is
  ## little-endian, so the chain runs LSB-to-MSB): `s < L` iff the final
  ## borrow out of the most significant byte is 1, i.e. the subtraction
  ## would have gone negative. Every byte position is visited
  ## unconditionally regardless of `s`; the loop body never branches on
  ## `s`, `L`, or any intermediate -- only the final `bool` conversion
  ## (an ordinary, non-secret-timed return) reads the accumulated borrow.
  ##
  ## **Machine-checked proof: considered and declined (round-2 review
  ## finding R2-2).** This 32-step subtract-with-borrow chain is the same
  ## shape as `scReduce`/`scMulAdd`'s carry-propagation macro -- a
  ## tractable per-step lemma (one byte position's borrow-in/borrow-out
  ## relation) composed 32 times. `tests/verify/symex_reduce.nim`'s own
  ## whole-chain composition attempt (`scReduceCarryChainFreeVars`, a
  ## 24-limb chain of the same general shape) hit a genuine Z3 resource
  ## wall -- no verdict within ~515-550s across two runs -- and this
  ## borrow chain's own composition offers no reason to expect a cheaper
  ## outcome. Rather than chase that wall a third time for a property
  ## this codebase already covers empirically, a symex proof here was
  ## considered and declined; the boundary set (0, 1, L-1, L, L+1, 2^252,
  ## all-0xFF, and two more L near-misses) plus a 500-input random sweep
  ## against the vartime `scIsCanonical` oracle
  ## (`tests/unit/test_scalar.nim`'s "scIsCanonicalCT (finding 2)" suite)
  ## carry the correctness weight in the meantime.
  var borrow: uint32 = 0
  for i in 0..<32:
    let diff = uint32(s[i]) - uint32(L[i]) - borrow
    borrow = (diff shr 31) and 1'u32
  borrow == 1

func scMulAdd*(a: array[32, byte]; bSecret, cSecret: SecretScalar): array[32, byte] =
  ## s = (a*b + c) mod L. Ported from ref10 sc_muladd (public domain;
  ## also shipped as libsodium's sc25519_muladd). Same radix-2^21,
  ## 12-limb decomposition as scReduce, but here the limbs come straight
  ## from 32-byte inputs (not a 64-byte hash) and are combined via a full
  ## schoolbook multiply before the same carry-propagation/reduction tail.
  ## `b`/`c` are secret in the real sign path (`private/backend.nim` calls
  ## this as `scMulAdd(k, a, r)`: `a` here is the PUBLIC challenge scalar
  ## `k`; `b`/`c` bind to the clamped secret key scalar `a` and the secret
  ## nonce `r` respectively) -- typed `SecretScalar` accordingly (round-3
  ## finding A3), while the public multiplier stays a bare
  ## `array[32, byte]`. `bSecret`/`cSecret` are unwrapped once, right below,
  ## into plain-byte `b`/`c` shadows (`var`, not `let` -- RFC finding R1
  ## wipes them once their limb decompositions are complete): the rest of
  ## this function's body
  ## is otherwise the untouched ref10 port (the same `a0..a11`/`b0..b11`/
  ## `c0..c11` limb extraction every other consumer of this arithmetic
  ## already relies on byte-for-byte), so the `SecretScalar` boundary costs
  ## nothing but these two lines. This function indexes fixed-size arrays
  ## at compile-time-constant offsets only, so checks-off carries no
  ## additional CT burden here.
  ##
  ## RFC finding R1 (extended by round-2 finding R15): `b`/`c` (fresh
  ## copies of the secret key scalar and nonce), their `b0..b11`/`c0..c11`
  ## radix-2^21 limb decompositions (themselves a full, directly-invertible
  ## re-encoding of the same secret bytes -- R15 found these surviving
  ## un-wiped on the stack after R1's `b`/`c` wipe, defeating that wipe's
  ## own purpose), and the `s0..s23` limb accumulators built from them are
  ## all secret working state, wiped via `ct.wipe` once no longer needed,
  ## under the same `try`/`finally` net `private/backend.nim` uses
  ## (RFC-001 ledger finding 18) -- `b`/`c` as soon as the `b0..b11`/
  ## `c0..c11` limb decompositions below are complete (their only
  ## consumers), `b0..b11`/`c0..c11` themselves immediately after the
  ## `s0..s23` schoolbook-multiply accumulation that is THEIR only
  ## consumer completes (before carry propagation begins), and `s0..s23`
  ## once `result` is fully assigned. The `carry0..carry22` intermediates
  ## (also secret-derived, though lossier/lower-value than the limbs
  ## above) are wiped defensively in `finally` only, since they are still
  ## live and being read/written throughout the carry-propagation tail.
  ## `finally` re-wipes everything regardless of exit path (defensive,
  ## currently unreachable: this whole function is fixed-size-array/int64
  ## arithmetic under `checks: off`, with no raising op reachable).
  var b = secretScalarBytes(bSecret)
  var c = secretScalarBytes(cSecret)
  var b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11: int64
  var c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11: int64
  var carry0, carry1, carry2, carry3, carry4, carry5: int64
  var carry6, carry7, carry8, carry9, carry10, carry11: int64
  var carry12, carry13, carry14, carry15, carry16, carry17: int64
  var carry18, carry19, carry20, carry21, carry22: int64
  let a0  = 0x1FFFFF'i64 and load3(a, 0)
  let a1  = 0x1FFFFF'i64 and (load4(a, 2) shr 5)
  let a2  = 0x1FFFFF'i64 and (load3(a, 5) shr 2)
  let a3  = 0x1FFFFF'i64 and (load4(a, 7) shr 7)
  let a4  = 0x1FFFFF'i64 and (load4(a, 10) shr 4)
  let a5  = 0x1FFFFF'i64 and (load3(a, 13) shr 1)
  let a6  = 0x1FFFFF'i64 and (load4(a, 15) shr 6)
  let a7  = 0x1FFFFF'i64 and (load3(a, 18) shr 3)
  let a8  = 0x1FFFFF'i64 and load3(a, 21)
  let a9  = 0x1FFFFF'i64 and (load4(a, 23) shr 5)
  let a10 = 0x1FFFFF'i64 and (load3(a, 26) shr 2)
  let a11 = load4(a, 28) shr 7

  b0  = 0x1FFFFF'i64 and load3(b, 0)
  b1  = 0x1FFFFF'i64 and (load4(b, 2) shr 5)
  b2  = 0x1FFFFF'i64 and (load3(b, 5) shr 2)
  b3  = 0x1FFFFF'i64 and (load4(b, 7) shr 7)
  b4  = 0x1FFFFF'i64 and (load4(b, 10) shr 4)
  b5  = 0x1FFFFF'i64 and (load3(b, 13) shr 1)
  b6  = 0x1FFFFF'i64 and (load4(b, 15) shr 6)
  b7  = 0x1FFFFF'i64 and (load3(b, 18) shr 3)
  b8  = 0x1FFFFF'i64 and load3(b, 21)
  b9  = 0x1FFFFF'i64 and (load4(b, 23) shr 5)
  b10 = 0x1FFFFF'i64 and (load3(b, 26) shr 2)
  b11 = load4(b, 28) shr 7

  c0  = 0x1FFFFF'i64 and load3(c, 0)
  c1  = 0x1FFFFF'i64 and (load4(c, 2) shr 5)
  c2  = 0x1FFFFF'i64 and (load3(c, 5) shr 2)
  c3  = 0x1FFFFF'i64 and (load4(c, 7) shr 7)
  c4  = 0x1FFFFF'i64 and (load4(c, 10) shr 4)
  c5  = 0x1FFFFF'i64 and (load3(c, 13) shr 1)
  c6  = 0x1FFFFF'i64 and (load4(c, 15) shr 6)
  c7  = 0x1FFFFF'i64 and (load3(c, 18) shr 3)
  c8  = 0x1FFFFF'i64 and load3(c, 21)
  c9  = 0x1FFFFF'i64 and (load4(c, 23) shr 5)
  c10 = 0x1FFFFF'i64 and (load3(c, 26) shr 2)
  c11 = load4(c, 28) shr 7

  ct.wipe(b)
  ct.wipe(c)

  var s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11: int64
  var s12, s13, s14, s15, s16, s17, s18, s19, s20, s21, s22, s23: int64

  try:
    s0  = c0 + a0*b0
    s1  = c1 + a0*b1 + a1*b0
    s2  = c2 + a0*b2 + a1*b1 + a2*b0
    s3  = c3 + a0*b3 + a1*b2 + a2*b1 + a3*b0
    s4  = c4 + a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0
    s5  = c5 + a0*b5 + a1*b4 + a2*b3 + a3*b2 + a4*b1 + a5*b0
    s6  = c6 + a0*b6 + a1*b5 + a2*b4 + a3*b3 + a4*b2 + a5*b1 + a6*b0
    s7  = c7 + a0*b7 + a1*b6 + a2*b5 + a3*b4 + a4*b3 + a5*b2 + a6*b1 + a7*b0
    s8  = c8 + a0*b8 + a1*b7 + a2*b6 + a3*b5 + a4*b4 + a5*b3 + a6*b2 +
              a7*b1 + a8*b0
    s9  = c9 + a0*b9 + a1*b8 + a2*b7 + a3*b6 + a4*b5 + a5*b4 + a6*b3 +
              a7*b2 + a8*b1 + a9*b0
    s10 = c10 + a0*b10 + a1*b9 + a2*b8 + a3*b7 + a4*b6 + a5*b5 + a6*b4 +
              a7*b3 + a8*b2 + a9*b1 + a10*b0
    s11 = c11 + a0*b11 + a1*b10 + a2*b9 + a3*b8 + a4*b7 + a5*b6 + a6*b5 +
              a7*b4 + a8*b3 + a9*b2 + a10*b1 + a11*b0
    s12 = a1*b11 + a2*b10 + a3*b9 + a4*b8 + a5*b7 + a6*b6 + a7*b5 +
              a8*b4 + a9*b3 + a10*b2 + a11*b1
    s13 = a2*b11 + a3*b10 + a4*b9 + a5*b8 + a6*b7 + a7*b6 + a8*b5 +
              a9*b4 + a10*b3 + a11*b2
    s14 = a3*b11 + a4*b10 + a5*b9 + a6*b8 + a7*b7 + a8*b6 + a9*b5 +
              a10*b4 + a11*b3
    s15 = a4*b11 + a5*b10 + a6*b9 + a7*b8 + a8*b7 + a9*b6 + a10*b5 + a11*b4
    s16 = a5*b11 + a6*b10 + a7*b9 + a8*b8 + a9*b7 + a10*b6 + a11*b5
    s17 = a6*b11 + a7*b10 + a8*b9 + a9*b8 + a10*b7 + a11*b6
    s18 = a7*b11 + a8*b10 + a9*b9 + a10*b8 + a11*b7
    s19 = a8*b11 + a9*b10 + a10*b9 + a11*b8
    s20 = a9*b11 + a10*b10 + a11*b9
    s21 = a10*b11 + a11*b10
    s22 = a11*b11
    s23 = 0'i64

    # b0..b11/c0..c11's only consumers are the s0..s23 products above --
    # wipe them here, right after last use, same placement rule as b/c
    # and s0..s23 elsewhere in this function (RFC finding R15).
    ct.wipe(b0);  ct.wipe(b1);  ct.wipe(b2);  ct.wipe(b3)
    ct.wipe(b4);  ct.wipe(b5);  ct.wipe(b6);  ct.wipe(b7)
    ct.wipe(b8);  ct.wipe(b9);  ct.wipe(b10); ct.wipe(b11)
    ct.wipe(c0);  ct.wipe(c1);  ct.wipe(c2);  ct.wipe(c3)
    ct.wipe(c4);  ct.wipe(c5);  ct.wipe(c6);  ct.wipe(c7)
    ct.wipe(c8);  ct.wipe(c9);  ct.wipe(c10); ct.wipe(c11)

    carry0  = (s0  + (1'i64 shl 20)) shr 21; s1  += carry0;  s0  -= carry0 shl 21
    carry2  = (s2  + (1'i64 shl 20)) shr 21; s3  += carry2;  s2  -= carry2 shl 21
    carry4  = (s4  + (1'i64 shl 20)) shr 21; s5  += carry4;  s4  -= carry4 shl 21
    carry6  = (s6  + (1'i64 shl 20)) shr 21; s7  += carry6;  s6  -= carry6 shl 21
    carry8  = (s8  + (1'i64 shl 20)) shr 21; s9  += carry8;  s8  -= carry8 shl 21
    carry10 = (s10 + (1'i64 shl 20)) shr 21; s11 += carry10; s10 -= carry10 shl 21
    carry12 = (s12 + (1'i64 shl 20)) shr 21; s13 += carry12; s12 -= carry12 shl 21
    carry14 = (s14 + (1'i64 shl 20)) shr 21; s15 += carry14; s14 -= carry14 shl 21
    carry16 = (s16 + (1'i64 shl 20)) shr 21; s17 += carry16; s16 -= carry16 shl 21
    carry18 = (s18 + (1'i64 shl 20)) shr 21; s19 += carry18; s18 -= carry18 shl 21
    carry20 = (s20 + (1'i64 shl 20)) shr 21; s21 += carry20; s20 -= carry20 shl 21
    carry22 = (s22 + (1'i64 shl 20)) shr 21; s23 += carry22; s22 -= carry22 shl 21

    carry1  = (s1  + (1'i64 shl 20)) shr 21; s2  += carry1;  s1  -= carry1 shl 21
    carry3  = (s3  + (1'i64 shl 20)) shr 21; s4  += carry3;  s3  -= carry3 shl 21
    carry5  = (s5  + (1'i64 shl 20)) shr 21; s6  += carry5;  s5  -= carry5 shl 21
    carry7  = (s7  + (1'i64 shl 20)) shr 21; s8  += carry7;  s7  -= carry7 shl 21
    carry9  = (s9  + (1'i64 shl 20)) shr 21; s10 += carry9;  s9  -= carry9 shl 21
    carry11 = (s11 + (1'i64 shl 20)) shr 21; s12 += carry11; s11 -= carry11 shl 21
    carry13 = (s13 + (1'i64 shl 20)) shr 21; s14 += carry13; s13 -= carry13 shl 21
    carry15 = (s15 + (1'i64 shl 20)) shr 21; s16 += carry15; s15 -= carry15 shl 21
    carry17 = (s17 + (1'i64 shl 20)) shr 21; s18 += carry17; s17 -= carry17 shl 21
    carry19 = (s19 + (1'i64 shl 20)) shr 21; s20 += carry19; s19 -= carry19 shl 21
    carry21 = (s21 + (1'i64 shl 20)) shr 21; s22 += carry21; s21 -= carry21 shl 21

    s11 += s23 * 666643
    s12 += s23 * 470296
    s13 += s23 * 654183
    s14 -= s23 * 997805
    s15 += s23 * 136657
    s16 -= s23 * 683901
    s23 = 0

    s10 += s22 * 666643
    s11 += s22 * 470296
    s12 += s22 * 654183
    s13 -= s22 * 997805
    s14 += s22 * 136657
    s15 -= s22 * 683901
    s22 = 0

    s9 += s21 * 666643
    s10 += s21 * 470296
    s11 += s21 * 654183
    s12 -= s21 * 997805
    s13 += s21 * 136657
    s14 -= s21 * 683901
    s21 = 0

    s8 += s20 * 666643
    s9 += s20 * 470296
    s10 += s20 * 654183
    s11 -= s20 * 997805
    s12 += s20 * 136657
    s13 -= s20 * 683901
    s20 = 0

    s7 += s19 * 666643
    s8 += s19 * 470296
    s9 += s19 * 654183
    s10 -= s19 * 997805
    s11 += s19 * 136657
    s12 -= s19 * 683901
    s19 = 0

    s6 += s18 * 666643
    s7 += s18 * 470296
    s8 += s18 * 654183
    s9 -= s18 * 997805
    s10 += s18 * 136657
    s11 -= s18 * 683901
    s18 = 0

    carry6  = (s6  + (1'i64 shl 20)) shr 21; s7  += carry6;  s6  -= carry6 shl 21
    carry8  = (s8  + (1'i64 shl 20)) shr 21; s9  += carry8;  s8  -= carry8 shl 21
    carry10 = (s10 + (1'i64 shl 20)) shr 21; s11 += carry10; s10 -= carry10 shl 21
    carry12 = (s12 + (1'i64 shl 20)) shr 21; s13 += carry12; s12 -= carry12 shl 21
    carry14 = (s14 + (1'i64 shl 20)) shr 21; s15 += carry14; s14 -= carry14 shl 21
    carry16 = (s16 + (1'i64 shl 20)) shr 21; s17 += carry16; s16 -= carry16 shl 21

    carry7  = (s7  + (1'i64 shl 20)) shr 21; s8  += carry7;  s7  -= carry7 shl 21
    carry9  = (s9  + (1'i64 shl 20)) shr 21; s10 += carry9;  s9  -= carry9 shl 21
    carry11 = (s11 + (1'i64 shl 20)) shr 21; s12 += carry11; s11 -= carry11 shl 21
    carry13 = (s13 + (1'i64 shl 20)) shr 21; s14 += carry13; s13 -= carry13 shl 21
    carry15 = (s15 + (1'i64 shl 20)) shr 21; s16 += carry15; s15 -= carry15 shl 21

    s5 += s17 * 666643
    s6 += s17 * 470296
    s7 += s17 * 654183
    s8 -= s17 * 997805
    s9 += s17 * 136657
    s10 -= s17 * 683901
    s17 = 0

    s4 += s16 * 666643
    s5 += s16 * 470296
    s6 += s16 * 654183
    s7 -= s16 * 997805
    s8 += s16 * 136657
    s9 -= s16 * 683901
    s16 = 0

    s3 += s15 * 666643
    s4 += s15 * 470296
    s5 += s15 * 654183
    s6 -= s15 * 997805
    s7 += s15 * 136657
    s8 -= s15 * 683901
    s15 = 0

    s2 += s14 * 666643
    s3 += s14 * 470296
    s4 += s14 * 654183
    s5 -= s14 * 997805
    s6 += s14 * 136657
    s7 -= s14 * 683901
    s14 = 0

    s1 += s13 * 666643
    s2 += s13 * 470296
    s3 += s13 * 654183
    s4 -= s13 * 997805
    s5 += s13 * 136657
    s6 -= s13 * 683901
    s13 = 0

    s0 += s12 * 666643
    s1 += s12 * 470296
    s2 += s12 * 654183
    s3 -= s12 * 997805
    s4 += s12 * 136657
    s5 -= s12 * 683901
    s12 = 0

    carry0 = s0 shr 21; s1 += carry0; s0 -= carry0 shl 21
    carry1 = s1 shr 21; s2 += carry1; s1 -= carry1 shl 21
    carry2 = s2 shr 21; s3 += carry2; s2 -= carry2 shl 21
    carry3 = s3 shr 21; s4 += carry3; s3 -= carry3 shl 21
    carry4 = s4 shr 21; s5 += carry4; s4 -= carry4 shl 21
    carry5 = s5 shr 21; s6 += carry5; s5 -= carry5 shl 21
    carry6 = s6 shr 21; s7 += carry6; s6 -= carry6 shl 21
    carry7 = s7 shr 21; s8 += carry7; s7 -= carry7 shl 21
    carry8 = s8 shr 21; s9 += carry8; s8 -= carry8 shl 21
    carry9 = s9 shr 21; s10 += carry9; s9 -= carry9 shl 21
    carry10 = s10 shr 21; s11 += carry10; s10 -= carry10 shl 21
    carry11 = s11 shr 21; s12 += carry11; s11 -= carry11 shl 21

    s0 += s12 * 666643
    s1 += s12 * 470296
    s2 += s12 * 654183
    s3 -= s12 * 997805
    s4 += s12 * 136657
    s5 -= s12 * 683901
    s12 = 0

    carry0 = s0 shr 21; s1 += carry0; s0 -= carry0 shl 21
    carry1 = s1 shr 21; s2 += carry1; s1 -= carry1 shl 21
    carry2 = s2 shr 21; s3 += carry2; s2 -= carry2 shl 21
    carry3 = s3 shr 21; s4 += carry3; s3 -= carry3 shl 21
    carry4 = s4 shr 21; s5 += carry4; s4 -= carry4 shl 21
    carry5 = s5 shr 21; s6 += carry5; s5 -= carry5 shl 21
    carry6 = s6 shr 21; s7 += carry6; s6 -= carry6 shl 21
    carry7 = s7 shr 21; s8 += carry7; s7 -= carry7 shl 21
    carry8 = s8 shr 21; s9 += carry8; s8 -= carry8 shl 21
    carry9 = s9 shr 21; s10 += carry9; s9 -= carry9 shl 21
    carry10 = s10 shr 21; s11 += carry10; s10 -= carry10 shl 21

    result[ 0] = byte(s0 shr 0)
    result[ 1] = byte(s0 shr 8)
    result[ 2] = byte((s0 shr 16) or (s1 shl 5))
    result[ 3] = byte(s1 shr 3)
    result[ 4] = byte(s1 shr 11)
    result[ 5] = byte((s1 shr 19) or (s2 shl 2))
    result[ 6] = byte(s2 shr 6)
    result[ 7] = byte((s2 shr 14) or (s3 shl 7))
    result[ 8] = byte(s3 shr 1)
    result[ 9] = byte(s3 shr 9)
    result[10] = byte((s3 shr 17) or (s4 shl 4))
    result[11] = byte(s4 shr 4)
    result[12] = byte(s4 shr 12)
    result[13] = byte((s4 shr 20) or (s5 shl 1))
    result[14] = byte(s5 shr 7)
    result[15] = byte((s5 shr 15) or (s6 shl 6))
    result[16] = byte(s6 shr 2)
    result[17] = byte(s6 shr 10)
    result[18] = byte((s6 shr 18) or (s7 shl 3))
    result[19] = byte(s7 shr 5)
    result[20] = byte(s7 shr 13)
    result[21] = byte(s8 shr 0)
    result[22] = byte(s8 shr 8)
    result[23] = byte((s8 shr 16) or (s9 shl 5))
    result[24] = byte(s9 shr 3)
    result[25] = byte(s9 shr 11)
    result[26] = byte((s9 shr 19) or (s10 shl 2))
    result[27] = byte(s10 shr 6)
    result[28] = byte((s10 shr 14) or (s11 shl 7))
    result[29] = byte(s11 shr 1)
    result[30] = byte(s11 shr 9)
    result[31] = byte(s11 shr 17)

    ct.wipe(s0);  ct.wipe(s1);  ct.wipe(s2);  ct.wipe(s3)
    ct.wipe(s4);  ct.wipe(s5);  ct.wipe(s6);  ct.wipe(s7)
    ct.wipe(s8);  ct.wipe(s9);  ct.wipe(s10); ct.wipe(s11)
    ct.wipe(s12); ct.wipe(s13); ct.wipe(s14); ct.wipe(s15)
    ct.wipe(s16); ct.wipe(s17); ct.wipe(s18); ct.wipe(s19)
    ct.wipe(s20); ct.wipe(s21); ct.wipe(s22); ct.wipe(s23)
  finally:
    ct.wipe(b)
    ct.wipe(c)
    ct.wipe(b0);  ct.wipe(b1);  ct.wipe(b2);  ct.wipe(b3)
    ct.wipe(b4);  ct.wipe(b5);  ct.wipe(b6);  ct.wipe(b7)
    ct.wipe(b8);  ct.wipe(b9);  ct.wipe(b10); ct.wipe(b11)
    ct.wipe(c0);  ct.wipe(c1);  ct.wipe(c2);  ct.wipe(c3)
    ct.wipe(c4);  ct.wipe(c5);  ct.wipe(c6);  ct.wipe(c7)
    ct.wipe(c8);  ct.wipe(c9);  ct.wipe(c10); ct.wipe(c11)
    ct.wipe(s0);  ct.wipe(s1);  ct.wipe(s2);  ct.wipe(s3)
    ct.wipe(s4);  ct.wipe(s5);  ct.wipe(s6);  ct.wipe(s7)
    ct.wipe(s8);  ct.wipe(s9);  ct.wipe(s10); ct.wipe(s11)
    ct.wipe(s12); ct.wipe(s13); ct.wipe(s14); ct.wipe(s15)
    ct.wipe(s16); ct.wipe(s17); ct.wipe(s18); ct.wipe(s19)
    ct.wipe(s20); ct.wipe(s21); ct.wipe(s22); ct.wipe(s23)
    ct.wipe(carry0);  ct.wipe(carry1);  ct.wipe(carry2);  ct.wipe(carry3)
    ct.wipe(carry4);  ct.wipe(carry5);  ct.wipe(carry6);  ct.wipe(carry7)
    ct.wipe(carry8);  ct.wipe(carry9);  ct.wipe(carry10); ct.wipe(carry11)
    ct.wipe(carry12); ct.wipe(carry13); ct.wipe(carry14); ct.wipe(carry15)
    ct.wipe(carry16); ct.wipe(carry17); ct.wipe(carry18); ct.wipe(carry19)
    ct.wipe(carry20); ct.wipe(carry21); ct.wipe(carry22)

{.pop.}
{.pop.}