## Curve25519 group operations and scalar multiplication
##
## Extended homogeneous coordinates (X:Y:Z:T) with T = X*Y/Z.
##
## Addition formulas from Hisil-Wong-Carter-Dawson "Twisted Edwards Curves
## Revisited" (2008), as implemented in ref10 / TweetNaCl (public domain).

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

  GePrecomp* = object
    yPlusX*, yMinusX*, xy2d*: Fe

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

  SqrtM1_Raw*: array[10, int32] = [
    -32595792'i32, -7943725, 9377950, 3500415, 12389472,
    -272473, -25146209, -2005654, 326686, 11406482
  ]

# ---------------------------------------------------------------------------
# Conversions
# ---------------------------------------------------------------------------

func geP3ToCached*(r: var GeCached; p: GeP3) {.inline.} =
  feAdd(r.yPlusX, p.y, p.x)
  feSub(r.yMinusX, p.y, p.x)
  r.z = p.z
  var D: Fe
  D.limbs = Ed25519D_Raw
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

func geSub*(r: var GeP1P1; p: GeP3; q: GeCached) {.inline.} =
  ## Group subtraction: p - q  (swaps Yq+Xq and Yq-Xq, and the Z/T signs).
  ## Verbatim ref10 ge_sub (public domain).
  var A, B, C, D: Fe
  feAdd(A, p.y, p.x)        # Y+X
  feSub(B, p.y, p.x)        # Y-X
  feMul(A, A, q.yMinusX)    # (Y+X)(Yq-Xq)
  feMul(B, B, q.yPlusX)     # (Y-X)(Yq+Xq)
  feMul(C, q.t2d, p.t)      # 2d*Tq*T
  feMul(D, p.z, q.z)        # Z*Zq
  feAdd(D, D, D)            # 2*Z*Zq
  feSub(r.x, A, B)          # X = (Y+X)(Yq-Xq) - (Y-X)(Yq+Xq)
  feAdd(r.y, A, B)          # Y = (Y+X)(Yq-Xq) + (Y-X)(Yq+Xq)
  feSub(r.z, D, C)          # Z = 2*Z*Zq - C
  feAdd(r.t, D, C)          # T = 2*Z*Zq + C

# ---------------------------------------------------------------------------
# Scalar multiplication: variable-base, unsigned 4-bit windows
# ---------------------------------------------------------------------------

func scalarmult*(r: var GeP3; s: array[32, byte]; p: GeP3) =
  ## r = [s]p — variable-base scalar multiplication.
  ## Uses unsigned 4-bit windows (nibbles 0..15), high-first.
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