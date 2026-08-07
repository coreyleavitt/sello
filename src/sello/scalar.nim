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

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

type
  GeP2* = object
    x*, y*, z*: Fe

  GeP3* = object
    x*, y*, z*, t*: Fe

  GeP1P1* = object
    x*, y*, z*, t*: Fe

  GeCached* = object
    yPlusX*, yMinusX*, z*, t2d*: Fe

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
# one consumer, the ed25519 point-decode sqrt-ratio retry step, is now
# `field.feSqrtRatioVartime` (a field.nim primitive so a future Ristretto
# decode can reuse it without importing this curve-ops module) -- see that
# function's doc comment for the constant itself.

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
  pts[0].x = FeZero; pts[0].y = FeOne; pts[0].z = FeOne; pts[0].t = FeZero
  geP3ToCached(cch[0], pts[0])

  pts[1] = p
  geP3ToCached(cch[1], pts[1])

  for i in countup(2, 15):
    geAdd(dbl, pts[i-1], cch[1])   # pts[i] = pts[i-1] + P
    geP1P1ToP3(pts[i], dbl)
    geP3ToCached(cch[i], pts[i])

  # Process nibbles from high to low
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
  let signMask = -int32(isNeg)
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

func geScalarmultBase*(s: array[32, byte]): GeP3 =
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
  when not defined(release):
    {.push assertions: on.}
    assert (s[31] and 0x80'u8) == 0, "geScalarmultBase: bit 255 of s must be 0"
    {.pop.}
  let digits = recodeScalarRadix16(s)

  var acc: GeP3
  acc.x = FeZero; acc.y = FeOne; acc.z = FeOne; acc.t = FeZero

  var u: GeCached
  var step: GeP1P1

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
  for i in countdown(31, 0):
    if s[i] < L[i]: return true
    if s[i] > L[i]: return false
  return false

func scMulAdd*(a, b, c: array[32, byte]): array[32, byte] =
  ## s = (a*b + c) mod L. Ported from ref10 sc_muladd (public domain;
  ## also shipped as libsodium's sc25519_muladd). Same radix-2^21,
  ## 12-limb decomposition as scReduce, but here the limbs come straight
  ## from 32-byte inputs (not a 64-byte hash) and are combined via a full
  ## schoolbook multiply before the same carry-propagation/reduction tail.
  ## a, b are secret in the sign path (the nonce r and clamped scalar a);
  ## this function indexes fixed-size arrays at compile-time-constant
  ## offsets only, so checks-off carries no additional CT burden here.
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

  let b0  = 0x1FFFFF'i64 and load3(b, 0)
  let b1  = 0x1FFFFF'i64 and (load4(b, 2) shr 5)
  let b2  = 0x1FFFFF'i64 and (load3(b, 5) shr 2)
  let b3  = 0x1FFFFF'i64 and (load4(b, 7) shr 7)
  let b4  = 0x1FFFFF'i64 and (load4(b, 10) shr 4)
  let b5  = 0x1FFFFF'i64 and (load3(b, 13) shr 1)
  let b6  = 0x1FFFFF'i64 and (load4(b, 15) shr 6)
  let b7  = 0x1FFFFF'i64 and (load3(b, 18) shr 3)
  let b8  = 0x1FFFFF'i64 and load3(b, 21)
  let b9  = 0x1FFFFF'i64 and (load4(b, 23) shr 5)
  let b10 = 0x1FFFFF'i64 and (load3(b, 26) shr 2)
  let b11 = load4(b, 28) shr 7

  let c0  = 0x1FFFFF'i64 and load3(c, 0)
  let c1  = 0x1FFFFF'i64 and (load4(c, 2) shr 5)
  let c2  = 0x1FFFFF'i64 and (load3(c, 5) shr 2)
  let c3  = 0x1FFFFF'i64 and (load4(c, 7) shr 7)
  let c4  = 0x1FFFFF'i64 and (load4(c, 10) shr 4)
  let c5  = 0x1FFFFF'i64 and (load3(c, 13) shr 1)
  let c6  = 0x1FFFFF'i64 and (load4(c, 15) shr 6)
  let c7  = 0x1FFFFF'i64 and (load3(c, 18) shr 3)
  let c8  = 0x1FFFFF'i64 and load3(c, 21)
  let c9  = 0x1FFFFF'i64 and (load4(c, 23) shr 5)
  let c10 = 0x1FFFFF'i64 and (load3(c, 26) shr 2)
  let c11 = load4(c, 28) shr 7

  var s0  = c0 + a0*b0
  var s1  = c1 + a0*b1 + a1*b0
  var s2  = c2 + a0*b2 + a1*b1 + a2*b0
  var s3  = c3 + a0*b3 + a1*b2 + a2*b1 + a3*b0
  var s4  = c4 + a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0
  var s5  = c5 + a0*b5 + a1*b4 + a2*b3 + a3*b2 + a4*b1 + a5*b0
  var s6  = c6 + a0*b6 + a1*b5 + a2*b4 + a3*b3 + a4*b2 + a5*b1 + a6*b0
  var s7  = c7 + a0*b7 + a1*b6 + a2*b5 + a3*b4 + a4*b3 + a5*b2 + a6*b1 + a7*b0
  var s8  = c8 + a0*b8 + a1*b7 + a2*b6 + a3*b5 + a4*b4 + a5*b3 + a6*b2 +
            a7*b1 + a8*b0
  var s9  = c9 + a0*b9 + a1*b8 + a2*b7 + a3*b6 + a4*b5 + a5*b4 + a6*b3 +
            a7*b2 + a8*b1 + a9*b0
  var s10 = c10 + a0*b10 + a1*b9 + a2*b8 + a3*b7 + a4*b6 + a5*b5 + a6*b4 +
            a7*b3 + a8*b2 + a9*b1 + a10*b0
  var s11 = c11 + a0*b11 + a1*b10 + a2*b9 + a3*b8 + a4*b7 + a5*b6 + a6*b5 +
            a7*b4 + a8*b3 + a9*b2 + a10*b1 + a11*b0
  var s12 = a1*b11 + a2*b10 + a3*b9 + a4*b8 + a5*b7 + a6*b6 + a7*b5 +
            a8*b4 + a9*b3 + a10*b2 + a11*b1
  var s13 = a2*b11 + a3*b10 + a4*b9 + a5*b8 + a6*b7 + a7*b6 + a8*b5 +
            a9*b4 + a10*b3 + a11*b2
  var s14 = a3*b11 + a4*b10 + a5*b9 + a6*b8 + a7*b7 + a8*b6 + a9*b5 +
            a10*b4 + a11*b3
  var s15 = a4*b11 + a5*b10 + a6*b9 + a7*b8 + a8*b7 + a9*b6 + a10*b5 + a11*b4
  var s16 = a5*b11 + a6*b10 + a7*b9 + a8*b8 + a9*b7 + a10*b6 + a11*b5
  var s17 = a6*b11 + a7*b10 + a8*b9 + a9*b8 + a10*b7 + a11*b6
  var s18 = a7*b11 + a8*b10 + a9*b9 + a10*b8 + a11*b7
  var s19 = a8*b11 + a9*b10 + a10*b9 + a11*b8
  var s20 = a9*b11 + a10*b10 + a11*b9
  var s21 = a10*b11 + a11*b10
  var s22 = a11*b11
  var s23 = 0'i64

  var carry0  = (s0  + (1'i64 shl 20)) shr 21; s1  += carry0;  s0  -= carry0 shl 21
  var carry2  = (s2  + (1'i64 shl 20)) shr 21; s3  += carry2;  s2  -= carry2 shl 21
  var carry4  = (s4  + (1'i64 shl 20)) shr 21; s5  += carry4;  s4  -= carry4 shl 21
  var carry6  = (s6  + (1'i64 shl 20)) shr 21; s7  += carry6;  s6  -= carry6 shl 21
  var carry8  = (s8  + (1'i64 shl 20)) shr 21; s9  += carry8;  s8  -= carry8 shl 21
  var carry10 = (s10 + (1'i64 shl 20)) shr 21; s11 += carry10; s10 -= carry10 shl 21
  var carry12 = (s12 + (1'i64 shl 20)) shr 21; s13 += carry12; s12 -= carry12 shl 21
  var carry14 = (s14 + (1'i64 shl 20)) shr 21; s15 += carry14; s14 -= carry14 shl 21
  var carry16 = (s16 + (1'i64 shl 20)) shr 21; s17 += carry16; s16 -= carry16 shl 21
  var carry18 = (s18 + (1'i64 shl 20)) shr 21; s19 += carry18; s18 -= carry18 shl 21
  var carry20 = (s20 + (1'i64 shl 20)) shr 21; s21 += carry20; s20 -= carry20 shl 21
  var carry22 = (s22 + (1'i64 shl 20)) shr 21; s23 += carry22; s22 -= carry22 shl 21

  var carry1  = (s1  + (1'i64 shl 20)) shr 21; s2  += carry1;  s1  -= carry1 shl 21
  var carry3  = (s3  + (1'i64 shl 20)) shr 21; s4  += carry3;  s3  -= carry3 shl 21
  var carry5  = (s5  + (1'i64 shl 20)) shr 21; s6  += carry5;  s5  -= carry5 shl 21
  var carry7  = (s7  + (1'i64 shl 20)) shr 21; s8  += carry7;  s7  -= carry7 shl 21
  var carry9  = (s9  + (1'i64 shl 20)) shr 21; s10 += carry9;  s9  -= carry9 shl 21
  var carry11 = (s11 + (1'i64 shl 20)) shr 21; s12 += carry11; s11 -= carry11 shl 21
  var carry13 = (s13 + (1'i64 shl 20)) shr 21; s14 += carry13; s13 -= carry13 shl 21
  var carry15 = (s15 + (1'i64 shl 20)) shr 21; s16 += carry15; s15 -= carry15 shl 21
  var carry17 = (s17 + (1'i64 shl 20)) shr 21; s18 += carry17; s17 -= carry17 shl 21
  var carry19 = (s19 + (1'i64 shl 20)) shr 21; s20 += carry19; s19 -= carry19 shl 21
  var carry21 = (s21 + (1'i64 shl 20)) shr 21; s22 += carry21; s21 -= carry21 shl 21

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

{.pop.}