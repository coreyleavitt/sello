## GF(2^255 - 19) field arithmetic
##
## Ported from ref10 / orlp ed25519 (public domain).
## Radix 2^25.5: 10 limbs, each in int32 range.
## Coeffs: [0..2^26), [0..2^25), [0..2^26), [0..2^25), [0..2^26),
##          [0..2^25), [0..2^26), [0..2^25), [0..2^26), [0..2^25).

type
  Fe* = object
    limbs*: array[10, int32]

const
  FeZero* = Fe(limbs: [0'i32, 0, 0, 0, 0, 0, 0, 0, 0, 0])
  FeOne*  = Fe(limbs: [1'i32, 0, 0, 0, 0, 0, 0, 0, 0, 0])

# ---------------------------------------------------------------------------
# Decode / Encode
# ---------------------------------------------------------------------------

func feFromBytes*(b: array[32, byte]): Fe {.inline.} =
  var h0 = int64(b[ 0]) or (int64(b[ 1]) shl 8) or (int64(b[ 2]) shl 16) or (int64(b[ 3]) shl 24)
  var h1 = int64(b[ 4]) or (int64(b[ 5]) shl 8) or (int64(b[ 6]) shl 16)
  var h2 = int64(b[ 7]) or (int64(b[ 8]) shl 8) or (int64(b[ 9]) shl 16)
  var h3 = int64(b[10]) or (int64(b[11]) shl 8) or (int64(b[12]) shl 16)
  var h4 = int64(b[13]) or (int64(b[14]) shl 8) or (int64(b[15]) shl 16)
  var h5 = int64(b[16]) or (int64(b[17]) shl 8) or (int64(b[18]) shl 16) or (int64(b[19]) shl 24)
  var h6 = int64(b[20]) or (int64(b[21]) shl 8) or (int64(b[22]) shl 16)
  var h7 = int64(b[23]) or (int64(b[24]) shl 8) or (int64(b[25]) shl 16)
  var h8 = int64(b[26]) or (int64(b[27]) shl 8) or (int64(b[28]) shl 16)
  var h9 = int64(b[29]) or (int64(b[30]) shl 8) or (int64(b[31]) shl 16)
  h1 = h1 shl 6
  h2 = h2 shl 5
  h3 = h3 shl 3
  h4 = h4 shl 2
  h6 = h6 shl 7
  h7 = h7 shl 5
  h8 = h8 shl 4
  h9 = (h9 and 8388607) shl 2

  var carry9 = (h9 + (1'i64 shl 24)) shr 25
  h0 += carry9 * 19
  h9 -= carry9 shl 25
  var carry1 = (h1 + (1'i64 shl 24)) shr 25
  h2 += carry1
  h1 -= carry1 shl 25
  var carry3 = (h3 + (1'i64 shl 24)) shr 25
  h4 += carry3
  h3 -= carry3 shl 25
  var carry5 = (h5 + (1'i64 shl 24)) shr 25
  h6 += carry5
  h5 -= carry5 shl 25
  var carry7 = (h7 + (1'i64 shl 24)) shr 25
  h8 += carry7
  h7 -= carry7 shl 25

  var carry0 = (h0 + (1'i64 shl 25)) shr 26
  h1 += carry0
  h0 -= carry0 shl 26
  var carry2 = (h2 + (1'i64 shl 25)) shr 26
  h3 += carry2
  h2 -= carry2 shl 26
  var carry4 = (h4 + (1'i64 shl 25)) shr 26
  h5 += carry4
  h4 -= carry4 shl 26
  var carry6 = (h6 + (1'i64 shl 25)) shr 26
  h7 += carry6
  h6 -= carry6 shl 26
  var carry8 = (h8 + (1'i64 shl 25)) shr 26
  h9 += carry8
  h8 -= carry8 shl 26

  result.limbs[0] = int32(h0)
  result.limbs[1] = int32(h1)
  result.limbs[2] = int32(h2)
  result.limbs[3] = int32(h3)
  result.limbs[4] = int32(h4)
  result.limbs[5] = int32(h5)
  result.limbs[6] = int32(h6)
  result.limbs[7] = int32(h7)
  result.limbs[8] = int32(h8)
  result.limbs[9] = int32(h9)

func feToBytes*(f: Fe): array[32, byte] {.inline.} =
  var h0 = f.limbs[0].int32
  var h1 = f.limbs[1].int32
  var h2 = f.limbs[2].int32
  var h3 = f.limbs[3].int32
  var h4 = f.limbs[4].int32
  var h5 = f.limbs[5].int32
  var h6 = f.limbs[6].int32
  var h7 = f.limbs[7].int32
  var h8 = f.limbs[8].int32
  var h9 = f.limbs[9].int32

  var q = cast[int32]((19 * cast[int64](h9) + (1'i64 shl 24)) shr 25)
  q = (h0 + q) shr 26
  q = (h1 + q) shr 25
  q = (h2 + q) shr 26
  q = (h3 + q) shr 25
  q = (h4 + q) shr 26
  q = (h5 + q) shr 25
  q = (h6 + q) shr 26
  q = (h7 + q) shr 25
  q = (h8 + q) shr 26
  q = (h9 + q) shr 25

  h0 += 19 * q

  var carry0 = h0 shr 26
  h1 += carry0
  h0 -= carry0 shl 26
  var carry1 = h1 shr 25
  h2 += carry1
  h1 -= carry1 shl 25
  var carry2 = h2 shr 26
  h3 += carry2
  h2 -= carry2 shl 26
  var carry3 = h3 shr 25
  h4 += carry3
  h3 -= carry3 shl 25
  var carry4 = h4 shr 26
  h5 += carry4
  h4 -= carry4 shl 26
  var carry5 = h5 shr 25
  h6 += carry5
  h5 -= carry5 shl 25
  var carry6 = h6 shr 26
  h7 += carry6
  h6 -= carry6 shl 26
  var carry7 = h7 shr 25
  h8 += carry7
  h7 -= carry7 shl 25
  var carry8 = h8 shr 26
  h9 += carry8
  h8 -= carry8 shl 26
  var carry9 = h9 shr 25
  h9 -= carry9 shl 25

  result[ 0] = byte(h0 shr  0)
  result[ 1] = byte(h0 shr  8)
  result[ 2] = byte(h0 shr 16)
  result[ 3] = byte(cast[uint32](h0 shr 24) or (cast[uint32](h1) shl 2))
  result[ 4] = byte(h1 shr  6)
  result[ 5] = byte(h1 shr 14)
  result[ 6] = byte(cast[uint32](h1 shr 22) or (cast[uint32](h2) shl 3))
  result[ 7] = byte(h2 shr  5)
  result[ 8] = byte(h2 shr 13)
  result[ 9] = byte(cast[uint32](h2 shr 21) or (cast[uint32](h3) shl 5))
  result[10] = byte(h3 shr  3)
  result[11] = byte(h3 shr 11)
  result[12] = byte(cast[uint32](h3 shr 19) or (cast[uint32](h4) shl 6))
  result[13] = byte(h4 shr  2)
  result[14] = byte(h4 shr 10)
  result[15] = byte(h4 shr 18)
  result[16] = byte(h5 shr  0)
  result[17] = byte(h5 shr  8)
  result[18] = byte(h5 shr 16)
  result[19] = byte(cast[uint32](h5 shr 24) or (cast[uint32](h6) shl 1))
  result[20] = byte(h6 shr  7)
  result[21] = byte(h6 shr 15)
  result[22] = byte(cast[uint32](h6 shr 23) or (cast[uint32](h7) shl 3))
  result[23] = byte(h7 shr  5)
  result[24] = byte(h7 shr 13)
  result[25] = byte(cast[uint32](h7 shr 21) or (cast[uint32](h8) shl 4))
  result[26] = byte(h8 shr  4)
  result[27] = byte(h8 shr 12)
  result[28] = byte(cast[uint32](h8 shr 20) or (cast[uint32](h9) shl 6))
  result[29] = byte(h9 shr  2)
  result[30] = byte(h9 shr 10)
  result[31] = byte(h9 shr 18)

# ---------------------------------------------------------------------------
# Predicates
# ---------------------------------------------------------------------------

func feBytesCanonical*(b: array[32, byte]): bool =
  ## True iff the low 255 bits of `b` (little-endian; bit 255 ignored)
  ## encode a value < p = 2^255 - 19, i.e. the unique canonical encoding
  ## of a field element. Not constant-time; verify-path only.
  for i in countdown(31, 0):
    let v = if i == 31: b[31] and 0x7F'u8 else: b[i]
    let p = if i == 31: 0x7F'u8 elif i == 0: 0xED'u8 else: 0xFF'u8
    if v < p: return true
    if v > p: return false
  false  # equal to p: non-canonical

func feIsNegative*(f: Fe): bool {.inline.} =
  let b = feToBytes(f)
  (b[0] and 1) != 0

func feIsNonZero*(f: Fe): bool {.inline.} =
  let b = feToBytes(f)
  for i in 0..<32:
    if b[i] != 0: return true
  false

# ---------------------------------------------------------------------------
# Field arithmetic
# ---------------------------------------------------------------------------

func feAdd*(r: var Fe; a, b: Fe) {.inline.} =
  for i in 0..<10:
    r.limbs[i] = a.limbs[i] + b.limbs[i]

func feSub*(r: var Fe; a, b: Fe) {.inline.} =
  for i in 0..<10:
    r.limbs[i] = a.limbs[i] - b.limbs[i]

func feMul*(r: var Fe; a, b: Fe) {.inline.} =
  template A(i: int): int64 = cast[int64](a.limbs[i])
  template B(i: int): int64 = cast[int64](b.limbs[i])

  let a0 = A(0); let a1 = A(1); let a2 = A(2); let a3 = A(3); let a4 = A(4)
  let a5 = A(5); let a6 = A(6); let a7 = A(7); let a8 = A(8); let a9 = A(9)
  let b0 = B(0); let b1 = B(1); let b2 = B(2); let b3 = B(3); let b4 = B(4)
  let b5 = B(5); let b6 = B(6); let b7 = B(7); let b8 = B(8); let b9 = B(9)

  let b1_19 = 19 * b1; let b2_19 = 19 * b2; let b3_19 = 19 * b3
  let b4_19 = 19 * b4; let b5_19 = 19 * b5; let b6_19 = 19 * b6
  let b7_19 = 19 * b7; let b8_19 = 19 * b8; let b9_19 = 19 * b9

  let a1_2 = 2 * a1; let a3_2 = 2 * a3; let a5_2 = 2 * a5
  let a7_2 = 2 * a7; let a9_2 = 2 * a9

  var h0 = a0*b0 + a1_2*b9_19 + a2*b8_19 + a3_2*b7_19 + a4*b6_19 +
           a5_2*b5_19 + a6*b4_19 + a7_2*b3_19 + a8*b2_19 + a9_2*b1_19
  var h1 = a0*b1 + a1*b0    + a2*b9_19 + a3*b8_19 + a4*b7_19 +
           a5*b6_19 + a6*b5_19 + a7*b4_19 + a8*b3_19 + a9*b2_19
  var h2 = a0*b2 + a1_2*b1  + a2*b0    + a3_2*b9_19 + a4*b8_19 +
           a5_2*b7_19 + a6*b6_19 + a7_2*b5_19 + a8*b4_19 + a9_2*b3_19
  var h3 = a0*b3 + a1*b2    + a2*b1    + a3*b0    + a4*b9_19 +
           a5*b8_19 + a6*b7_19 + a7*b6_19 + a8*b5_19 + a9*b4_19
  var h4 = a0*b4 + a1_2*b3  + a2*b2    + a3_2*b1  + a4*b0 +
           a5_2*b9_19 + a6*b8_19 + a7_2*b7_19 + a8*b6_19 + a9_2*b5_19
  var h5 = a0*b5 + a1*b4    + a2*b3    + a3*b2    + a4*b1 +
           a5*b0    + a6*b9_19 + a7*b8_19 + a8*b7_19 + a9*b6_19
  var h6 = a0*b6 + a1_2*b5  + a2*b4    + a3_2*b3  + a4*b2 +
           a5_2*b1  + a6*b0    + a7_2*b9_19 + a8*b8_19 + a9_2*b7_19
  var h7 = a0*b7 + a1*b6    + a2*b5    + a3*b4    + a4*b3 +
           a5*b2    + a6*b1    + a7*b0    + a8*b9_19 + a9*b8_19
  var h8 = a0*b8 + a1_2*b7  + a2*b6    + a3_2*b5  + a4*b4 +
           a5_2*b3  + a6*b2    + a7_2*b1  + a8*b0    + a9_2*b9_19
  var h9 = a0*b9 + a1*b8    + a2*b7    + a3*b6    + a4*b5 +
           a5*b4    + a6*b3    + a7*b2    + a8*b1    + a9*b0

  var carry0 = (h0 + (1'i64 shl 25)) shr 26
  h1 += carry0; h0 -= carry0 shl 26
  var carry4 = (h4 + (1'i64 shl 25)) shr 26
  h5 += carry4; h4 -= carry4 shl 26

  var carry1 = (h1 + (1'i64 shl 24)) shr 25
  h2 += carry1; h1 -= carry1 shl 25
  var carry5 = (h5 + (1'i64 shl 24)) shr 25
  h6 += carry5; h5 -= carry5 shl 25

  var carry2 = (h2 + (1'i64 shl 25)) shr 26
  h3 += carry2; h2 -= carry2 shl 26
  var carry6 = (h6 + (1'i64 shl 25)) shr 26
  h7 += carry6; h6 -= carry6 shl 26

  var carry3 = (h3 + (1'i64 shl 24)) shr 25
  h4 += carry3; h3 -= carry3 shl 25
  var carry7 = (h7 + (1'i64 shl 24)) shr 25
  h8 += carry7; h7 -= carry7 shl 25

  var carry4b = (h4 + (1'i64 shl 25)) shr 26
  h5 += carry4b; h4 -= carry4b shl 26
  var carry8 = (h8 + (1'i64 shl 25)) shr 26
  h9 += carry8; h8 -= carry8 shl 26

  var carry9 = (h9 + (1'i64 shl 24)) shr 25
  h0 += carry9 * 19; h9 -= carry9 shl 25

  var carry0b = (h0 + (1'i64 shl 25)) shr 26
  h1 += carry0b; h0 -= carry0b shl 26

  r.limbs[0] = int32(h0)
  r.limbs[1] = int32(h1)
  r.limbs[2] = int32(h2)
  r.limbs[3] = int32(h3)
  r.limbs[4] = int32(h4)
  r.limbs[5] = int32(h5)
  r.limbs[6] = int32(h6)
  r.limbs[7] = int32(h7)
  r.limbs[8] = int32(h8)
  r.limbs[9] = int32(h9)

func feSq*(r: var Fe; a: Fe) {.inline.} =
  template A(i: int): int64 = cast[int64](a.limbs[i])

  let a0 = A(0); let a1 = A(1); let a2 = A(2); let a3 = A(3); let a4 = A(4)
  let a5 = A(5); let a6 = A(6); let a7 = A(7); let a8 = A(8); let a9 = A(9)

  let a0_2 = 2 * a0; let a1_2 = 2 * a1; let a2_2 = 2 * a2
  let a3_2 = 2 * a3; let a4_2 = 2 * a4; let a5_2 = 2 * a5
  let a6_2 = 2 * a6; let a7_2 = 2 * a7
  let a5_38 = 38 * a5; let a6_19 = 19 * a6; let a7_38 = 38 * a7
  let a8_19 = 19 * a8; let a9_38 = 38 * a9

  let f0f0    = a0   * a0
  let f0f1_2  = a0_2 * a1
  let f0f2_2  = a0_2 * a2
  let f0f3_2  = a0_2 * a3
  let f0f4_2  = a0_2 * a4
  let f0f5_2  = a0_2 * a5
  let f0f6_2  = a0_2 * a6
  let f0f7_2  = a0_2 * a7
  let f0f8_2  = a0_2 * a8
  let f0f9_2  = a0_2 * a9
  let f1f1_2  = a1_2 * a1
  let f1f2_2  = a1_2 * a2
  let f1f3_4  = a1_2 * a3_2
  let f1f4_2  = a1_2 * a4
  let f1f5_4  = a1_2 * a5_2
  let f1f6_2  = a1_2 * a6
  let f1f7_4  = a1_2 * a7_2
  let f1f8_2  = a1_2 * a8
  let f1f9_76 = a1_2 * a9_38
  let f2f2    = a2   * a2
  let f2f3_2  = a2_2 * a3
  let f2f4_2  = a2_2 * a4
  let f2f5_2  = a2_2 * a5
  let f2f6_2  = a2_2 * a6
  let f2f7_2  = a2_2 * a7
  let f2f8_38 = a2_2 * a8_19
  let f2f9_38 = a2   * a9_38
  let f3f3_2  = a3_2 * a3
  let f3f4_2  = a3_2 * a4
  let f3f5_4  = a3_2 * a5_2
  let f3f6_2  = a3_2 * a6
  let f3f7_76 = a3_2 * a7_38
  let f3f8_38 = a3_2 * a8_19
  let f3f9_76 = a3_2 * a9_38
  let f4f4    = a4   * a4
  let f4f5_2  = a4_2 * a5
  let f4f6_38 = a4_2 * a6_19
  let f4f7_38 = a4   * a7_38
  let f4f8_38 = a4_2 * a8_19
  let f4f9_38 = a4   * a9_38
  let f5f5_38 = a5   * a5_38
  let f5f6_38 = a5_2 * a6_19
  let f5f7_76 = a5_2 * a7_38
  let f5f8_38 = a5_2 * a8_19
  let f5f9_76 = a5_2 * a9_38
  let f6f6_19 = a6   * a6_19
  let f6f7_38 = a6   * a7_38
  let f6f8_38 = a6_2 * a8_19
  let f6f9_38 = a6   * a9_38
  let f7f7_38 = a7   * a7_38
  let f7f8_38 = a7_2 * a8_19
  let f7f9_76 = a7_2 * a9_38
  let f8f8_19 = a8   * a8_19
  let f8f9_38 = a8   * a9_38
  let f9f9_38 = a9   * a9_38

  var h0 = f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38
  var h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38
  var h2 = f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19
  var h3 = f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38
  var h4 = f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38
  var h5 = f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38
  var h6 = f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19
  var h7 = f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38
  var h8 = f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38
  var h9 = f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2

  var carry0 = (h0 + (1'i64 shl 25)) shr 26
  h1 += carry0; h0 -= carry0 shl 26
  var carry4 = (h4 + (1'i64 shl 25)) shr 26
  h5 += carry4; h4 -= carry4 shl 26

  var carry1 = (h1 + (1'i64 shl 24)) shr 25
  h2 += carry1; h1 -= carry1 shl 25
  var carry5 = (h5 + (1'i64 shl 24)) shr 25
  h6 += carry5; h5 -= carry5 shl 25

  var carry2 = (h2 + (1'i64 shl 25)) shr 26
  h3 += carry2; h2 -= carry2 shl 26
  var carry6 = (h6 + (1'i64 shl 25)) shr 26
  h7 += carry6; h6 -= carry6 shl 26

  var carry3 = (h3 + (1'i64 shl 24)) shr 25
  h4 += carry3; h3 -= carry3 shl 25
  var carry7 = (h7 + (1'i64 shl 24)) shr 25
  h8 += carry7; h7 -= carry7 shl 25

  var carry4b = (h4 + (1'i64 shl 25)) shr 26
  h5 += carry4b; h4 -= carry4b shl 26
  var carry8 = (h8 + (1'i64 shl 25)) shr 26
  h9 += carry8; h8 -= carry8 shl 26

  var carry9 = (h9 + (1'i64 shl 24)) shr 25
  h0 += carry9 * 19; h9 -= carry9 shl 25

  var carry0b = (h0 + (1'i64 shl 25)) shr 26
  h1 += carry0b; h0 -= carry0b shl 26

  r.limbs[0] = int32(h0)
  r.limbs[1] = int32(h1)
  r.limbs[2] = int32(h2)
  r.limbs[3] = int32(h3)
  r.limbs[4] = int32(h4)
  r.limbs[5] = int32(h5)
  r.limbs[6] = int32(h6)
  r.limbs[7] = int32(h7)
  r.limbs[8] = int32(h8)
  r.limbs[9] = int32(h9)

func feSq2*(r: var Fe; a: Fe) {.inline.} =
  feSq(r, a)
  for i in 0..<10:
    r.limbs[i] = r.limbs[i] + r.limbs[i]

func feNeg*(r: var Fe; a: Fe) {.inline.} =
  for i in 0..<10:
    r.limbs[i] = -a.limbs[i]

func feMul121666*(r: var Fe; a: Fe) {.inline.} =
  var t: array[10, int64]
  for i in 0..<10:
    t[i] = cast[int64](a.limbs[i]) * 121666'i64

  var carry0 = (t[0] + (1'i64 shl 25)) shr 26
  t[1] += carry0; t[0] -= carry0 shl 26
  var carry4 = (t[4] + (1'i64 shl 25)) shr 26
  t[5] += carry4; t[4] -= carry4 shl 26

  var carry1 = (t[1] + (1'i64 shl 24)) shr 25
  t[2] += carry1; t[1] -= carry1 shl 25
  var carry5 = (t[5] + (1'i64 shl 24)) shr 25
  t[6] += carry5; t[5] -= carry5 shl 25

  var carry2 = (t[2] + (1'i64 shl 25)) shr 26
  t[3] += carry2; t[2] -= carry2 shl 26
  var carry6 = (t[6] + (1'i64 shl 25)) shr 26
  t[7] += carry6; t[6] -= carry6 shl 26

  var carry3 = (t[3] + (1'i64 shl 24)) shr 25
  t[4] += carry3; t[3] -= carry3 shl 25
  var carry7 = (t[7] + (1'i64 shl 24)) shr 25
  t[8] += carry7; t[7] -= carry7 shl 25

  var carry4b = (t[4] + (1'i64 shl 25)) shr 26
  t[5] += carry4b; t[4] -= carry4b shl 26
  var carry8 = (t[8] + (1'i64 shl 25)) shr 26
  t[9] += carry8; t[8] -= carry8 shl 26

  var carry9 = (t[9] + (1'i64 shl 24)) shr 25
  t[0] += carry9 * 19; t[9] -= carry9 shl 25

  var carry0b = (t[0] + (1'i64 shl 25)) shr 26
  t[1] += carry0b; t[0] -= carry0b shl 26

  for i in 0..<10:
    r.limbs[i] = int32(t[i])

func feInvert*(r: var Fe; a: Fe) =
  var t0, t1, t2, t3: Fe

  feSq(t0, a)
  feSq(t1, t0)
  feSq(t1, t1)
  feMul(t1, a, t1)
  feMul(t0, t0, t1)
  feSq(t2, t0)
  feMul(t1, t1, t2)
  feSq(t2, t1)
  for i in 1..<5:
    feSq(t2, t2)
  feMul(t1, t2, t1)
  feSq(t2, t1)
  for i in 1..<10:
    feSq(t2, t2)
  feMul(t2, t2, t1)
  feSq(t3, t2)
  for i in 1..<20:
    feSq(t3, t3)
  feMul(t2, t3, t2)
  feSq(t2, t2)
  for i in 1..<10:
    feSq(t2, t2)
  feMul(t1, t2, t1)
  feSq(t2, t1)
  for i in 1..<50:
    feSq(t2, t2)
  feMul(t2, t2, t1)
  feSq(t3, t2)
  for i in 1..<100:
    feSq(t3, t3)
  feMul(t2, t3, t2)
  feSq(t2, t2)
  for i in 1..<50:
    feSq(t2, t2)
  feMul(t1, t2, t1)
  feSq(t1, t1)
  for i in 1..<5:
    feSq(t1, t1)
  feMul(r, t1, t0)

func fePow22523*(r: var Fe; a: Fe) {.inline.} =
  var t0, t1, t2: Fe

  feSq(t0, a)
  feSq(t1, t0)
  feSq(t1, t1)
  feMul(t1, a, t1)
  feMul(t0, t0, t1)
  feSq(t0, t0)
  feMul(t0, t1, t0)
  feSq(t1, t0)
  for i in 1..<5:
    feSq(t1, t1)
  feMul(t0, t1, t0)
  feSq(t1, t0)
  for i in 1..<10:
    feSq(t1, t1)
  feMul(t1, t1, t0)
  feSq(t2, t1)
  for i in 1..<20:
    feSq(t2, t2)
  feMul(t1, t2, t1)
  feSq(t1, t1)
  for i in 1..<10:
    feSq(t1, t1)
  feMul(t0, t1, t0)
  feSq(t1, t0)
  for i in 1..<50:
    feSq(t1, t1)
  feMul(t1, t1, t0)
  feSq(t2, t1)
  for i in 1..<100:
    feSq(t2, t2)
  feMul(t1, t2, t1)
  feSq(t1, t1)
  for i in 1..<50:
    feSq(t1, t1)
  feMul(t0, t1, t0)
  feSq(t0, t0)
  feSq(t0, t0)
  feMul(r, t0, a)

func feCMove*(r: var Fe; a: Fe; b: bool) {.inline.} =
  let mask = -int32(b)
  for i in 0..<10:
    r.limbs[i] = r.limbs[i] xor ((r.limbs[i] xor a.limbs[i]) and mask)

func feCopy*(r: var Fe; a: Fe) {.inline.} =
  r = a