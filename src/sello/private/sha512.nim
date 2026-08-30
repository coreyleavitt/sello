## sello/private/sha512.nim — in-house SHA-512 (FIPS 180-4), RFC-006.
##
## Implemented directly from FIPS 180-4 ("Secure Hash Standard (SHS)",
## NIST, 2015), Section 5 (preprocessing/padding) and Section 6.4
## (SHA-512 message schedule and compression function) -- the spec is
## short and complete, and the algorithm is straight-line ARX
## (add/rotate/xor) with no lookup tables and no branch or index that
## depends on message *content*, so a direct port carries no CT surprises
## of its own (see CT posture below). The eighty `K` round constants and
## the eight `Sha512IV` words are transcribed verbatim from the spec's own
## hex tables (FIPS 180-4 §4.2.3 / §5.3.5); their number-theoretic
## derivation (fractional parts of cube/square roots of the first primes)
## gets NO in-repo re-derivation test -- the NIST CAVP corpus (driven
## through this module in `tests/unit/test_sha512.nim`) is the right
## instrument for a wrong constant, since any single transcription error
## fails it immediately on the very first vector. Same recorded-decline
## register as `field.feSqrtRatioM1`'s A.4-vectors-not-symex choice.
##
## A leaf module, `private/ct.nim`'s sibling in the layering: imports
## NOTHING but `sello/private/ct` for its own secret wipes, unconditionally
## -- there is no wipe-free build of this module. Under `private/` because
## it is not public API (see RFC-006's Non-goals: sello is a 25519
## library, not a hash toolkit); consumed by `challenge.nim` and
## `private/backend.nim` (slice 3 swaps those over from nimcrypto).
##
## ## Types/API
##
## The production face is three fixed-arity one-shot `func`s --
## `sha512(a)`, `sha512(a, b)`, `sha512(a, b, c)`, all `openArray[byte] ->
## array[64, byte]` -- because every real call site hashes a fixed, known
## set of 1-3 buffers and immediately finishes (the seed hash, the nonce
## hash, and the three-part `challenge` hash, respectively; the CAVP
## Monte Carlo chain step is also exactly the three-part shape). Each
## one-shot runs `init`/`update`(xN)/`finish` on a context confined to its
## own stack frame, then `ct.wipe`s that whole context before returning --
## the module's `raises: []` push means no exception path can skip that
## wipe. Nim cannot express `varargs[openArray[byte]]` (`openArray` does
## not nest), which is what makes this fixed-arity family the deep design
## rather than a stopgap; no fourth production call site exists, and a
## future one escalates rather than growing the family or hand-concatenating
## parts into a caller-side scratch buffer (which would reopen the exact
## residue question the one-shots exist to close).
##
## A streaming register -- `Sha512Context` (all fields private) plus
## `init`/`update`/`finish` -- is exported for the test estate only: CAVP
## ShortMsg/LongMsg and the Monte Carlo chain step all route through the
## one-shots above (the heaviest corpora thereby validate the exact
## functions production calls); the genuine streaming consumers are the
## incremental/split-point boundary suite (which places `update`
## boundaries deliberately at the padding thresholds) and, in a later
## slice, `test_ct.nim`'s whole-object wipe scan (which needs a live
## context to inspect).
##
## Contract, stated rather than left to guess: `init` unconditionally
## resets every field (state to the IV, buffer/fill/length to zero) and is
## supported on a fresh, mid-stream, or already-finished context -- the
## reuse-across-a-vector-loop path a test consumer needs is ruled IN.
## `update`/`finish` called on a context that was never `init`ed is
## undefined: the failure mode is a plausible-looking wrong digest, not a
## crash (a zero-initialized `Sha512Context`'s all-zero state is not the
## IV). `finish` is terminal -- a further `update`/`finish` without an
## intervening `init` is caller error, deliberately not type-gated (this
## register's only consumers are test suites hashing public vectors;
## production goes through the one-shots, which never expose a context to
## misuse in the first place). No `=destroy`/`secretHooks` on the type:
## production contexts are module-confined and deterministically wiped by
## the one-shot that owns them before it returns, and the streaming
## register only ever touches public test data -- a destructor would
## duplicate the first case and serve nothing in the second.
##
## ## Context layout
##
## Flat and fixed-size only (`array[8, uint64]` state, `array[128, byte]`
## block buffer, an `int` fill counter, and the FIPS 180-4 128-bit message
## bit-length as two `uint64`s) -- no `seq`/`ref`/`string` anywhere, so a
## future generic `ct.wipe(ctx)` covers the whole object by raw
## reinterpretation, the same property `ct.nim`'s own doc comment requires
## of every type it wipes. Padding is constructed in place in this same
## persistent `buffer` field; when finalization needs a second block
## (original fill >= 112, i.e. no room left for the length field after
## the mandatory `0x80` pad byte), `finish` reuses that identical buffer
## rather than a fresh scratch array, so a context wipe stays a complete
## residue guarantee with nothing separate to miss.
##
## The 128-bit length is tracked as the spec's own bit-length (not a byte
## count promoted at the end): `lengthLo`/`lengthHi` accumulate `nBytes *
## 8` on every `update` call, with an explicit carry from `lengthLo` into
## `lengthHi` on overflow. That carry path triggers only once the
## cumulative message length exceeds 2^64 bits -- i.e. 2^61 bytes (2
## exabytes) -- which is unreachable by any physical input to this
## library (every production call site hashes at most a handful of
## 32-64-byte buffers). It is verified correct by code inspection against
## FIPS 180-4 Sec 5.1.2 only, not by a running test -- the same
## recorded-decline register as the K/IV constants above (see the
## `addLength` doc comment at the carry site itself).
##
## Three named sites use explicit per-byte shift/or big-endian assembly,
## in the `field.feFromBytes`/`feToBytes` register -- never a pointer cast
## or `copyMem` onto the `uint64` words, since every validation instrument
## in this repo runs on a little-endian host and a cast-based shortcut
## would pass the entire estate while being silently wrong on a
## big-endian target: (1) `compress`'s block -> message-schedule decode
## (`blk` bytes into `W[0..15]`), (2) `finish`'s state -> digest encode,
## and (3) `finish`'s 128-bit length-field write into the final padded
## block.
##
## ## Hygiene
##
## `compress` wipes its own message schedule `W` and its eight working
## variables (kept in one `array[8, uint64]`, precisely so one `ct.wipe`
## call covers all eight at once, the same "secrets live in a fixed-size
## stack array" discipline this whole codebase holds) via `private/
## ct.wipe` before returning, on EVERY call -- uniform, no skip-wipe fast
## path for the public-data (verify-adjacent) case, because a hash
## context carries no type-level notion of "this input is secret" the way
## `SecretScalar` does elsewhere in this codebase; an unflaggable hygiene
## fork is the risk here, not output drift (wiping cannot change the
## digest). **RFC-006 slice-1b amendment:** `W` is a rolling 16-word
## circular buffer (`array[16, uint64]`), not a fully materialized
## 80-word one -- W[t] depends only on W[t-2]/W[t-7]/W[t-15]/W[t-16], so
## the full 80-word history need never exist (see `compress`'s own doc
## comment for the indexing argument). The first implementation's fully
## materialized `array[80, uint64]` (640 bytes) plus the working
## variables (64 bytes), wiped one BYTE at a time, measured ~50% overhead
## -- far past this section's single-digit-percent expectation (see
## `docs/rfc-006-sha512.handoff.md`'s slice-1b finding for the
## measurement). The redesign attacks both cost factors: secret-bearing
## scratch shrinks from 704 to 192 bytes, and both `W` and the working
## variables now wipe through `private/ct.nim`'s word-granular
## `wipe[N](var array[N, uint64])` sibling overload (24 volatile
## per-`uint64` stores total, instead of 704 volatile per-byte stores) --
## overload resolution routes `array[N, uint64]` there automatically, so
## neither `ct.wipe(w)` nor `ct.wipe(v)` below chooses a register by
## name. The one-shot `sha512` funcs additionally `ct.wipe` the
## whole context object after `finish` returns, before they themselves
## return -- covering the context's own persistent fields (`buffer` may
## still hold raw tail bytes of a secret message after the final
## `compress`, since `finish` does not itself wipe those fields; the
## per-call `compress` wipe above covers only its own transient `W`/working
## variables). `finish`'s own postcondition is therefore left unspecified
## beyond "terminal, and consistent with `init`'s unconditional reset" --
## real hygiene for production callers is the one-shot's job, matching the
## "production contexts are module-confined and deterministically wiped"
## claim in Types/API above.
##
## ## CT posture
##
## Constant-time by construction and by nature: no branch, index, or
## table anywhere in `compress` depends on message *content* -- block and
## round counts are a function of message *length* only, and every
## current call site's length is public or fixed (a 32-byte seed). A
## future caller with a secret-*length* input would need a fresh CT review
## of the padding path specifically (this module makes no claim about
## that case). `Ch`/`Maj` are the standard bitwise forms; `compress` is
## straight-line with no early exit.
##
## ## Symex
##
## Recorded decline (RFC-006 slice 4): ARX correctness is the KAT
## corpus's instrument here, not a solver's, and there is no novel mask
## algebra or carry bound in this module that is not already covered by
## the existing `tests/verify/` proofs' register (`symex_mask.nim`'s mask
## algebra, `symex_reduce.nim`'s carry-propagation bound) -- `compress`'s
## additions are plain unsigned 64-bit wraparound arithmetic with no
## masking step of the kind those proofs exist to check.

import sello/private/ct

## Compiler-enforced effect contract (janus consumer finding 3) -- see
## `signing.nim`'s module doc for the surface-wide policy.
{.push raises: [], gcsafe.}

type
  Sha512Context* = object
    ## Streaming register, exported for the test estate only -- see the
    ## module doc's Types/API section for the full contract. All fields
    ## are private: no `sello/private/sha512` consumer outside this
    ## module reaches into them directly, only through `init`/`update`/
    ## `finish`.
    state: array[8, uint64]
    buffer: array[128, byte]
    fill: int
      ## Number of valid bytes currently sitting in `buffer`, always in
      ## 0..127 on entry to any proc in this module (a full 128-byte
      ## block is compressed and `fill` reset to 0 the moment it fills,
      ## inside `update`).
    lengthLo: uint64
    lengthHi: uint64
      ## Message length in BITS, as a 128-bit counter split across these
      ## two words (FIPS 180-4 Sec 5.1.2) -- see the module doc's Context
      ## layout section and `addLength`'s own doc comment for the carry
      ## path.

const
  Sha512IV: array[8, uint64] = [
    0x6a09e667f3bcc908'u64, 0xbb67ae8584caa73b'u64,
    0x3c6ef372fe94f82b'u64, 0xa54ff53a5f1d36f1'u64,
    0x510e527fade682d1'u64, 0x9b05688c2b3e6c1f'u64,
    0x1f83d9abfb41bd6b'u64, 0x5be0cd19137e2179'u64,
  ]
    ## FIPS 180-4 Sec 5.3.5 -- the first 64 bits of the fractional parts
    ## of the square roots of the first 8 primes. Transcribed verbatim
    ## from the spec's own hex; see the module doc's Source & attribution
    ## paragraph for why this gets no re-derivation test.

  K: array[80, uint64] = [
    0x428a2f98d728ae22'u64, 0x7137449123ef65cd'u64,
    0xb5c0fbcfec4d3b2f'u64, 0xe9b5dba58189dbbc'u64,
    0x3956c25bf348b538'u64, 0x59f111f1b605d019'u64,
    0x923f82a4af194f9b'u64, 0xab1c5ed5da6d8118'u64,
    0xd807aa98a3030242'u64, 0x12835b0145706fbe'u64,
    0x243185be4ee4b28c'u64, 0x550c7dc3d5ffb4e2'u64,
    0x72be5d74f27b896f'u64, 0x80deb1fe3b1696b1'u64,
    0x9bdc06a725c71235'u64, 0xc19bf174cf692694'u64,
    0xe49b69c19ef14ad2'u64, 0xefbe4786384f25e3'u64,
    0x0fc19dc68b8cd5b5'u64, 0x240ca1cc77ac9c65'u64,
    0x2de92c6f592b0275'u64, 0x4a7484aa6ea6e483'u64,
    0x5cb0a9dcbd41fbd4'u64, 0x76f988da831153b5'u64,
    0x983e5152ee66dfab'u64, 0xa831c66d2db43210'u64,
    0xb00327c898fb213f'u64, 0xbf597fc7beef0ee4'u64,
    0xc6e00bf33da88fc2'u64, 0xd5a79147930aa725'u64,
    0x06ca6351e003826f'u64, 0x142929670a0e6e70'u64,
    0x27b70a8546d22ffc'u64, 0x2e1b21385c26c926'u64,
    0x4d2c6dfc5ac42aed'u64, 0x53380d139d95b3df'u64,
    0x650a73548baf63de'u64, 0x766a0abb3c77b2a8'u64,
    0x81c2c92e47edaee6'u64, 0x92722c851482353b'u64,
    0xa2bfe8a14cf10364'u64, 0xa81a664bbc423001'u64,
    0xc24b8b70d0f89791'u64, 0xc76c51a30654be30'u64,
    0xd192e819d6ef5218'u64, 0xd69906245565a910'u64,
    0xf40e35855771202a'u64, 0x106aa07032bbd1b8'u64,
    0x19a4c116b8d2d0c8'u64, 0x1e376c085141ab53'u64,
    0x2748774cdf8eeb99'u64, 0x34b0bcb5e19b48a8'u64,
    0x391c0cb3c5c95a63'u64, 0x4ed8aa4ae3418acb'u64,
    0x5b9cca4f7763e373'u64, 0x682e6ff3d6b2b8a3'u64,
    0x748f82ee5defb2fc'u64, 0x78a5636f43172f60'u64,
    0x84c87814a1f0ab72'u64, 0x8cc702081a6439ec'u64,
    0x90befffa23631e28'u64, 0xa4506cebde82bde9'u64,
    0xbef9a3f7b2c67915'u64, 0xc67178f2e372532b'u64,
    0xca273eceea26619c'u64, 0xd186b8c721c0c207'u64,
    0xeada7dd6cde0eb1e'u64, 0xf57d4f7fee6ed178'u64,
    0x06f067aa72176fba'u64, 0x0a637dc5a2c898a6'u64,
    0x113f9804bef90dae'u64, 0x1b710b35131c471b'u64,
    0x28db77f523047d84'u64, 0x32caab7b40c72493'u64,
    0x3c9ebe0a15c9bebc'u64, 0x431d67c49c100d4c'u64,
    0x4cc5d4becb3e42b6'u64, 0x597f299cfc657e2a'u64,
    0x5fcb6fab3ad6faec'u64, 0x6c44198c4a475817'u64,
  ]
    ## FIPS 180-4 Sec 4.2.3 -- the first 64 bits of the fractional parts
    ## of the cube roots of the first 80 primes. Transcribed verbatim from
    ## the spec's own hex; same recorded decline as `Sha512IV` above.

# ---------------------------------------------------------------------------
# Compression core (straight-line ARX; checks off per convention -- this
# region never runs a bounds/overflow check on secret-derived data).
# ---------------------------------------------------------------------------

{.push checks: off.}

func rotr64(x: uint64; n: int): uint64 {.inline.} =
  ## Right-rotate a 64-bit word by `n` bits (0 < n < 64), the one ARX
  ## primitive both the message schedule's sigma functions and the round
  ## function's Sigma functions are built from.
  (x shr n) or (x shl (64 - n))

func compress(state: var array[8, uint64]; blk: array[128, byte]) {.noinline.} =
  ## FIPS 180-4 Sec 6.4.2 -- processes exactly one 128-byte message block,
  ## updating `state` in place. Wipes its own message schedule `W` and
  ## working variables before returning, on every call (module doc's
  ## Hygiene section).
  ##
  ## RFC-006 slice-1b amendment: `W` is a ROLLING 16-word circular buffer,
  ## not a fully materialized 80-word array -- W[t] depends only on
  ## W[t-2]/W[t-7]/W[t-15]/W[t-16], all reachable mod 16 (in particular
  ## `(t - 16) and 15 == t and 15`, so the slot about to be overwritten
  ## always holds exactly W[t-16] going in). The 80-round loop below folds
  ## the message-schedule recurrence and the round function into one pass;
  ## every index is loop-counter-derived (`t`, `t and 15`, `(t-2) and 15`,
  ## etc.), never data-dependent, so the CT posture is unchanged from the
  ## original fully-materialized version. See `docs/rfc-006-sha512.md`'s
  ## Hygiene section and `docs/rfc-006-sha512.handoff.md`'s slice-1b
  ## finding for why: the fully-materialized 640-byte `W` plus the 64-byte
  ## working-variable set, wiped one byte at a time, cost ~50% overhead in
  ## the first implementation -- far past the RFC's single-digit-percent
  ## expectation. Shrinking the schedule to 16 words (128 bytes) and
  ## wiping both `W` and the working variables through `ct.nim`'s new
  ## word-granular `wipe[N](var array[N, uint64])` overload (24 volatile
  ## word stores total, instead of 704 volatile byte stores) closes the
  ## gap: less secret-bearing scratch to begin with, and each remaining
  ## byte wiped 8x more cheaply.
  var w: array[16, uint64]

  # -- site 1: explicit big-endian block -> message-schedule decode --
  for i in 0 ..< 16:
    let o = i * 8
    w[i] = (uint64(blk[o + 0]) shl 56) or
           (uint64(blk[o + 1]) shl 48) or
           (uint64(blk[o + 2]) shl 40) or
           (uint64(blk[o + 3]) shl 32) or
           (uint64(blk[o + 4]) shl 24) or
           (uint64(blk[o + 5]) shl 16) or
           (uint64(blk[o + 6]) shl 8) or
            uint64(blk[o + 7])

  # Eight working variables (a..h == v[0..7]) in one fixed-size array, so
  # the whole set wipes in a single ct.wipe call below.
  var v: array[8, uint64] = state

  for t in 0 ..< 80:
    let idx = t and 15
    if t >= 16:
      # W[t] = W[t-16] + sigma0(W[t-15]) + W[t-7] + sigma1(W[t-2]).
      # `w[idx]` on the right-hand side below is still the OLD value
      # (W[t-16]) at this point -- it is overwritten by this same
      # statement, exactly the "oldest slot about to roll over" shape a
      # 16-deep circular buffer requires.
      let s0 = rotr64(w[(t - 15) and 15], 1) xor
               rotr64(w[(t - 15) and 15], 8) xor
               (w[(t - 15) and 15] shr 7)
      let s1 = rotr64(w[(t - 2) and 15], 19) xor
               rotr64(w[(t - 2) and 15], 61) xor
               (w[(t - 2) and 15] shr 6)
      w[idx] = w[idx] + s0 + w[(t - 7) and 15] + s1
    # For t < 16, `w[idx] == w[t]` already holds the decoded block word
    # from site 1 -- no separate read path needed.

    let bigS1 = rotr64(v[4], 14) xor rotr64(v[4], 18) xor rotr64(v[4], 41)
    let ch = (v[4] and v[5]) xor ((not v[4]) and v[6])
    let temp1 = v[7] + bigS1 + ch + K[t] + w[idx]
    let bigS0 = rotr64(v[0], 28) xor rotr64(v[0], 34) xor rotr64(v[0], 39)
    let maj = (v[0] and v[1]) xor (v[0] and v[2]) xor (v[1] and v[2])
    let temp2 = bigS0 + maj

    v[7] = v[6]
    v[6] = v[5]
    v[5] = v[4]
    v[4] = v[3] + temp1
    v[3] = v[2]
    v[2] = v[1]
    v[1] = v[0]
    v[0] = temp1 + temp2

  state[0] += v[0]
  state[1] += v[1]
  state[2] += v[2]
  state[3] += v[3]
  state[4] += v[4]
  state[5] += v[5]
  state[6] += v[6]
  state[7] += v[7]

  ct.wipe(w)
  ct.wipe(v)

{.pop.}

# ---------------------------------------------------------------------------
# Streaming register (init/update/finish) -- exported for the test estate
# only, see module doc's Types/API section.
# ---------------------------------------------------------------------------

func addLength(ctx: var Sha512Context; nBytes: int) {.inline.} =
  ## Adds `nBytes * 8` bits to the context's 128-bit message-bit-length
  ## counter. The low-word-to-high-word carry below is exercised only
  ## once the CUMULATIVE message length (across every `update` call on
  ## this context) exceeds 2^64 bits, i.e. 2^61 bytes (2 exabytes) --
  ## unreachable by any physical input to this library (every production
  ## call site hashes at most a handful of 32-64-byte buffers). Verified
  ## correct by code inspection against FIPS 180-4 Sec 5.1.2 only, not by
  ## a running test -- the module doc's recorded-decline register.
  let added = uint64(nBytes) * 8'u64
  let newLo = ctx.lengthLo + added
  if newLo < ctx.lengthLo:
    inc ctx.lengthHi
  ctx.lengthLo = newLo

func init*(ctx: var Sha512Context) =
  ## Unconditionally resets every field: state to the IV, buffer/fill/
  ## length to zero. Supported on a fresh, mid-stream, or already-finished
  ## context -- see the module doc's Types/API contract paragraph.
  ctx = Sha512Context(state: Sha512IV)

func update*(ctx: var Sha512Context; data: openArray[byte]) =
  ## Feeds `data` into the running hash: buffers up to 127 bytes
  ## internally and compresses each full 128-byte block as it fills. A
  ## final partial block is completed and compressed only by `finish`.
  ## Calling `update` before `init` is undefined (see the type's own doc
  ## comment).
  addLength(ctx, data.len)
  var offset = 0
  let n = data.len
  while offset < n:
    let space = 128 - ctx.fill
    let take = min(space, n - offset)
    for i in 0 ..< take:
      ctx.buffer[ctx.fill + i] = data[offset + i]
    ctx.fill += take
    offset += take
    if ctx.fill == 128:
      compress(ctx.state, ctx.buffer)
      ctx.fill = 0

func finish*(ctx: var Sha512Context; digest: var array[64, byte]) =
  ## Pads the final block(s) in place in the context's own persistent
  ## `buffer` field (never a fresh scratch array -- module doc's Context
  ## layout section) and writes the digest into `digest`. Terminal: a
  ## further `update`/`finish` without an intervening `init` is caller
  ## error (undefined, not type-gated -- see the type's own doc comment).
  let bitsHi = ctx.lengthHi
  let bitsLo = ctx.lengthLo

  ctx.buffer[ctx.fill] = 0x80
  inc ctx.fill

  if ctx.fill > 112:
    # No room left for the 128-bit length field in this block -- zero the
    # remainder, compress it, and start a fresh (reused) block for the
    # length-only final block.
    for i in ctx.fill ..< 128:
      ctx.buffer[i] = 0
    compress(ctx.state, ctx.buffer)
    ctx.fill = 0

  for i in ctx.fill ..< 112:
    ctx.buffer[i] = 0

  # -- site 3: explicit big-endian 128-bit length-field assembly --
  for i in 0 ..< 8:
    ctx.buffer[112 + i] = byte((bitsHi shr (56 - i * 8)) and 0xFF'u64)
  for i in 0 ..< 8:
    ctx.buffer[120 + i] = byte((bitsLo shr (56 - i * 8)) and 0xFF'u64)

  compress(ctx.state, ctx.buffer)

  # -- site 2: explicit big-endian state -> digest assembly --
  for i in 0 ..< 8:
    let word = ctx.state[i]
    let o = i * 8
    for j in 0 ..< 8:
      digest[o + j] = byte((word shr (56 - j * 8)) and 0xFF'u64)

# ---------------------------------------------------------------------------
# One-shot production face.
# ---------------------------------------------------------------------------

func sha512*(a: openArray[byte]): array[64, byte] =
  ## **Taint posture (RFC-005 slice 21, A1's taint CT harness) --
  ## deliberately NO interior `declassify` call**, the same reasoning as
  ## `ristretto.ristrettoEncode`'s own documented posture (see that
  ## function's doc comment for the full writeup this one cross-
  ## references rather than re-derives). `sha512` is a shared low-level
  ## primitive, reused both for hashing a message a caller intends to
  ## inspect the digest of (this slice's own `diSha512DigestKat` target)
  ## AND for genuinely secret-derivation hashing internal to this
  ## codebase's signing path -- `private/backend.derivePublic`'s very
  ## first line, `h = sha512(seed)`, is exactly this: `h` is not a value
  ## `derivePublic` intends to publish, it is the raw material the
  ## secret scalar `a` and the nonce-generation prefix are carved from,
  ## and `backend.signDetached`'s own nonce hash (`sha512(prefix, msg)`)
  ## is the identical shape. Declassifying unconditionally at THIS
  ## function's own return would silently un-taint every one of those
  ## secret intermediates the moment `sha512` produces them -- masking
  ## real leaks in `derivePublic`/`signDetached`'s OWN downstream
  ## clamp/scalarmult logic from this harness, the exact "taint washout"
  ## failure mode A1's own text names, self-inflicted by this function
  ## rather than caught by it. `compress` (below) is pure ARX (add-
  ## rotate-xor) with no data-dependent branch of its own either, so
  ## there is no interior-branch-timing reason to declassify here at
  ## all -- unlike `diX25519ZeroVerdict`'s "too late" argument against a
  ## harness-side declassify, nothing inside `sha512`/`compress` ever
  ## branches on the digest, so a CALLER declassifying its own copy of
  ## the digest, after this call returns, loses nothing. This slice's
  ## own `tests/ct_taint/target_sha512.nim` target does exactly that --
  ## see its own header comment.
  ##
  ## Single-buffer one-shot: `init`/`update`/`finish` on a module-confined
  ## context, wiped before returning.
  var ctx: Sha512Context
  ctx.init()
  ctx.update(a)
  ctx.finish(result)
  ct.wipe(ctx)

func sha512*(a, b: openArray[byte]): array[64, byte] =
  ## Two-buffer one-shot (the nonce hash's shape: `sha512(prefix, msg)`).
  ## Taint posture: see the single-buffer overload's doc comment above --
  ## identical reasoning, no interior declassify here either.
  var ctx: Sha512Context
  ctx.init()
  ctx.update(a)
  ctx.update(b)
  ctx.finish(result)
  ct.wipe(ctx)

func sha512*(a, b, c: openArray[byte]): array[64, byte] =
  ## Three-buffer one-shot (`challenge`'s shape, and the CAVP Monte Carlo
  ## chain step's `sha512(md3, md2, md1)`). Taint posture: see the
  ## single-buffer overload's doc comment above -- identical reasoning,
  ## no interior declassify here either.
  var ctx: Sha512Context
  ctx.init()
  ctx.update(a)
  ctx.update(b)
  ctx.update(c)
  ctx.finish(result)
  ct.wipe(ctx)

{.pop.}
