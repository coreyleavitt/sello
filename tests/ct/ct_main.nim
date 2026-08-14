## tests/ct/ct_main.nim — dudect harness driver (RFC-001 slice 9).
##
## Run via `scripts/ct.sh`, never as part of `scripts/test.sh` -- this is a
## statistical, environment-sensitive measurement, not a pass/fail
## correctness check on the usual bar.
##
## Targets, chosen to cover every secret-touching entry point named in
## RFC-001's constant-time discipline section:
##   - `positiveControl` -- NOT a sello function. A deliberately
##     variable-time comparison that branches on the secret. This is the
##     harness's own self-test (this slice's RED equivalent): if the
##     detector cannot trip on a function built to leak, it cannot be
##     trusted on functions that are supposed to be flat. Expected
##     verdict: FAIL (t > 10), and a FAIL here is the *correct*, passing
##     outcome for the harness sanity check.
##   - `signDetached` -- the full RFC 8032 §5.1.6 signing operation, via
##     `sello/private/backend.derivePublic` followed by
##     `sello/private/backend.signDetached` (RFC-001 ledger finding 13
##     changed `signDetached`'s contract to take the public key as a
##     parameter rather than re-deriving it, so timing this target
##     end-to-end from a fresh seed now means calling both functions in
##     sequence -- exactly mirroring the real `keypair(seed)` then
##     `kp.sign(msg)` call sequence in `signing.nim`, just without
##     `Keypair`'s wrapping): seed expansion, clamping, both fixed-base
##     scalarmults, and `scMulAdd`. The highest-value target -- it is what
##     ships.
##   - `geScalarmultBase` -- the fixed-base scalarmult in isolation
##     (`sello/scalar.geScalarmultBase`), since it is this RFC's new
##     secret-facing arithmetic (radix-16 recoding + `cmovCached` select)
##     and is worth evidence on its own, not just folded into the
##     end-to-end sign timing.
##   - `x25519Base` -- the RFC 7748 Montgomery ladder over a secret
##     scalar (`sello/x25519.x25519Base`), covering the one secret-
##     holding code path outside the ed25519 signing stack. Constructs a
##     fresh `X25519StaticSecret` per sample via `toX25519StaticSecret` (RFC-001
##     ledger #29 revisited: `X25519Key` replaced by role-typed
##     `X25519StaticSecret`/`X25519Public`/`X25519Shared`) -- identical
##     construction cost for both classes, so it does not perturb the
##     measurement.
##   - `x25519(sink X25519EphemeralSecret, peer)` -- the ephemeral
##     construct-and-consume path (RFC-002 slice 4 item 2), covering the
##     one secret-holding entry point the first four targets above do not
##     reach: `X25519EphemeralSecret`'s move-only, single-use API.
##   - `x25519(X25519StaticSecret, peer)` -- RFC-003 slice 5 item 1: a
##     REAL fixed-vs-random-secret leak test of the arbitrary-peer DH path
##     (ladder + zero-check + `Option` wrap + `=destroy` wipe), which the
##     fifth target above cannot be, because `X25519StaticSecret` (unlike
##     `X25519EphemeralSecret`) HAS a from-bytes constructor
##     (`toX25519StaticSecret`) -- so this target pins a genuine fixed
##     secret across the whole fixed class, the same recipe as the first
##     four targets, just run through the two-party `x25519(secret, peer)`
##     overload instead of `x25519Base`'s single-party derivation. Static
##     and ephemeral secrets share the identical `ladder()`
##     (`sello/x25519.nim`), so this also stands in as evidence for the
##     ladder call as exercised through the DH (not just base-point)
##     entry point.
##
## For every one of the first FOUR targets, and the SIXTH, only the
## SECRET varies between classes (fixed vs. per-sample random); any public
## input (message, peer point) is held identically fixed in both classes,
## so a detected timing difference can only be attributed to the secret.
##
## The FIFTH target (`x25519` over `X25519EphemeralSecret`) cannot follow
## that same recipe, and says so plainly rather than quietly reusing the
## same class-construction idiom for a type it does not fit:
## `X25519EphemeralSecret` has, by design, no from-bytes constructor
## (`sello/x25519`'s module doc: freshness-by-construction is the whole
## point of the type) and does not even expose its scalar bytes outside
## `x25519.nim` -- there is no way for this file to build a "fixed" class
## whose secret is actually held fixed across samples the way the other
## targets' `fixedSeed`/`fixedScalar`/`fixedSecret` do. Both classes
## therefore do the IDENTICAL thing every sample: draw a fresh ephemeral
## secret from the OS CSPRNG via `x25519EphemeralSecret()` and consume it
## (`x25519(secret, peer)`, the sink overload) against the same fixed
## public peer point. The `bool` class label `runDudect` threads through
## carries no information at all about what `operate` does for this
## target -- there is no secret value left to classify by, so the honest
## design is to not pretend one exists.
##
## What this still checks, and what it does not: a clean (low-|t|) result
## here is EXPECTED by construction (both classes are literally drawn
## from the same generative process), so it is not evidence that "this
## secret's value doesn't leak" the way the other targets' results are --
## there is no fixed secret value to ask that question about. What it
## does check is that the sink-consuming call chain itself (fresh
## construction, the Montgomery ladder, the all-zero/small-order check,
## the `Option` wrap, and the `=destroy` wipe that fires when `secret`
## goes out of scope) introduces no timing artifact statistically
## correlated with an arbitrary bisection of otherwise-identical samples
## -- a calibration/self-consistency check on the wrapper's own
## machinery, not a leak test on a value that cannot be pinned. **The
## fixed-vs-random-secret leak question this target structurally cannot
## answer -- does the arbitrary-peer DH path's timing depend on the
## SECRET's actual value, not just on the shape of the call -- IS answered
## by the sixth target above,** which runs the identical `ladder()` +
## zero-check + `Option` wrap + wipe machinery through `X25519StaticSecret`,
## a type that does have a from-bytes constructor and therefore can be
## held genuinely fixed. See `docs/ct-results.md` for the same caveat
## recorded next to this target's numbers.
##
## RFC-004 slice 7b adds FOUR more targets over `sello/ristretto` (RFC 9496),
## restating each target's own dudect-bullet rationale briefly here rather
## than only in `docs/ct-results.md`:
##   - `ristretto.ristrettoScalarmult` -- CT variable-base scalarmult over
##     `RistrettoStaticSecret` (the ristretto255 role WITH a from-bytes
##     route, `toRistrettoStaticSecretWide`, the direct analog of the
##     sixth target's `toX25519StaticSecret` above): fixed-vs-random
##     SECRET, fixed public point (`ristretto.RistrettoBasePoint`) -- a
##     genuine leak-value test, following the sixth target's design exactly
##     as the task instructs. `RistrettoEphemeralSecret` gets no separate
##     target, per the RFC's own dudect bullet: its one consuming call runs
##     the identical `scalar.geScalarmultCT` this target already measures
##     with full fixed-vs-random power, so a construct+consume calibration
##     target (the fifth target's own shape, above) would add runtime
##     without adding information.
##   - `ristretto.ristrettoEncode` -- fixed-vs-random INPUT POINT (not
##     secret, a POINT): encode is the operation the RFC's own motivating
##     protocols run on secret-DERIVED points (a Pedersen commitment before
##     publication, an OPRF blinded element), so its CT-by-construction
##     claim gets a leak-value measurement here rather than only an
##     argument. `ristretto.ristrettoDecode` gets no target, deliberately:
##     its input is attacker-supplied wire data, public by definition --
##     there is no secret class to measure.
##   - ``ristretto.`==` `` -- classes are (round-2 redesign, restated):
##     class A is `(P, P)` for one FIXED `P` (both `feEqualCT` OR-terms
##     inside `==` hit their TRUE branch -- the match path); class B is
##     `(P, Q)` for a fresh random `Q` each sample (FALSE throughout). A
##     naive fixed-vs-random-OPERAND framing could pass while never timing
##     the match path at all; this class design forces it, and is the one
##     place a short-circuit boolean (rather than the bitwise-or `==`
##     actually uses) could silently reintroduce a branch that no mutation
##     or property test can see. **Measured status: FAIL, extensively
##     investigated, attributed to a harness resolution-floor limitation
##     for very fast primitives rather than a genuine leak** -- this
##     target (~800-900 cycles raw) is 30-600x smaller than every other
##     target in this battery. Several batched-measurement designs were
##     tried (see the target's own code comment below and
##     docs/ct-results.md for the full investigation, including two rounds
##     of non-shipped diagnostics) and every one that showed the effect
##     shared one property: the "fixed" class always touches the same
##     small, constant memory addresses every sample while the "random"
##     class's addresses vary sample-to-sample -- present in every target
##     in this file but negligible against their much larger per-sample
##     cost. A fixed-but-ALWAYS-FALSE control target showed an equally
##     large or larger spurious |t| than the real (sometimes-true) design,
##     ruling out the actual TRUE/FALSE verdict as the driver. No batching
##     design achieved a clean result at full-battery scale, so the
##     shipped target reverts to the simplest single-call design; its
##     numbers are recorded honestly rather than suppressed.
##   - `ristretto.ristrettoFromUniformBytes` -- fixed-vs-random 64-byte
##     INPUT: OPRF blinding maps a client's PRIVATE input to the group, so
##     the map's input is secret in exactly the deployments this RFC
##     headlines, even though the map itself is a total function with no
##     accept/reject verdict.
##
## Random ristretto255 elements for the encode and `==` targets come from
## `randomRistrettoPoint` below -- a THIRD, independent copy of the same
## rejection-sampling loop shape `dudect.runDudect`'s own Phase 1 (fresh
## random scalars, above) and `test_ristretto.nim`'s property-test
## generator already have, per the RFC's own explicit sanction for this
## file: `ct_main.nim` imports library modules only, never test files, so
## neither existing copy is reachable from here. Every call site is via
## `makeRandomInput`, which `dudect.runDudect` only ever invokes during its
## pre-measurement Phase 1 (see `dudect.nim`'s own doc comment) -- this
## generator's inherently variable iteration count (RFC 9496's ~1/16
## acceptance rate per candidate) therefore never lands inside a timed
## region and carries no timing-measurement risk of its own.

import std/[os, parseutils, strutils, random, options]
import sello/private/backend
import sello/field
import sello/scalar
import sello/x25519
import sello/ristretto
import ./dudect

# ---------------------------------------------------------------------------
# Fixed public inputs, shared across classes for a given target
# ---------------------------------------------------------------------------

const fixedMsg = "the quick brown fox jumps over the lazy dog, 32x"
  ## Arbitrary fixed public message for the signDetached target -- long
  ## enough to cross SHA-512's single-block boundary (55-byte cutoff),
  ## exercising the same multi-block path production messages will.

proc randomBytes32(): array[32, byte] =
  for i in 0 ..< 32: result[i] = byte(rand(255))

proc randomBytes64(): array[64, byte] =
  for i in 0 ..< 64: result[i] = byte(rand(255))

proc foldBytes32(b: array[32, byte]): uint64 =
  ## Shared checksum fold for the four RFC-004 slice 7b targets below --
  ## the same shift-and-or-low-bit accumulate every existing `opXxx` in
  ## this file hand-rolls inline; consolidated here since four new call
  ## sites need it (see the module doc comment's anti-DCE note and
  ## `dudect.nim`'s own "use-the-result" discussion for why this fold
  ## exists at all -- it must run INSIDE the measured region, which every
  ## call site below still does).
  for x in b: result = (result shl 1) or uint64(x and 1'u8)

proc randomRistrettoPoint(): RistrettoPoint =
  ## Inline rejection-sampling ristretto255 element generator -- the
  ## sanctioned third copy of this loop shape (RFC-004's dudect bullet):
  ## `dudect.runDudect`'s own Phase 1 (fresh random scalars, above) and
  ## `tests/unit/test_ristretto.nim`'s property-test generator are the
  ## other two, neither reachable from here since this file imports
  ## library modules only, never test files. Draws a uniformly random
  ## 32-byte candidate and re-attempts `ristretto.ristrettoDecode` until
  ## one is accepted -- RFC 9496's own ~1/16 acceptance rate per
  ## candidate. Every call site is via `makeRandomInput`, which
  ## `dudect.runDudect` only ever invokes during its pre-measurement
  ## Phase 1 (see `dudect.nim`'s own doc comment) -- this loop's variable
  ## iteration count therefore never lands inside a timed region and
  ## carries no timing-measurement risk of its own, despite being
  ## visibly variable-time itself.
  while true:
    let candidate = toRistrettoEncoded(randomBytes32())
    let decoded = ristrettoDecode(candidate)
    if decoded.isSome:
      return decoded.get()

# ---------------------------------------------------------------------------
# Target 0: positive control -- deliberately variable-time, must trip the
# detector. Not part of sello; exists to validate the harness itself.
# ---------------------------------------------------------------------------

proc leakyOp(secret: array[32, byte]): uint64 =
  ## Branches directly on secret data: takes a visibly slower path
  ## whenever `secret[0]` is even. The fixed-class secret below is
  ## chosen even, so every fixed-class sample takes the slow path while
  ## roughly half of random-class samples do -- a large, easy-to-detect
  ## mean timing difference between the two classes.
  var acc: uint64 = 0
  if (secret[0] and 1'u8) == 0'u8:
    for i in 0 ..< 4000:
      acc += uint64(i) xor uint64(secret[i mod 32])
  else:
    acc = uint64(secret[0])
  result = acc

# ---------------------------------------------------------------------------
# Target 1: backend.signDetached -- full sign operation
# ---------------------------------------------------------------------------

proc opSignDetached(seed: array[32, byte]): uint64 =
  ## `derivePublic` then `signDetached` in sequence -- see the module doc
  ## comment (RFC-001 ledger finding 13): this is what a fresh
  ## `keypair(seed)` + `kp.sign(msg)` call pair does under the hood, now
  ## that `signDetached` takes the public key as a parameter instead of
  ## re-deriving it.
  let pub = backend.derivePublic(seed)
  let sig = backend.signDetached(seed, pub, fixedMsg.toOpenArrayByte(0, fixedMsg.len - 1))
  var acc: uint64 = 0
  for b in sig: acc = (acc shl 1) or uint64(b and 1'u8)
  acc

# ---------------------------------------------------------------------------
# Target 2: scalar.geScalarmultBase -- fixed-base scalarmult in isolation
# ---------------------------------------------------------------------------

proc clampedRandomScalar(): array[32, byte] =
  result = randomBytes32()
  clampScalar(result)  # bit 255 clear, bit 254 set -- valid domain

proc opGeScalarmultBase(s: array[32, byte]): uint64 =
  ## `geScalarmultBase` takes `SecretScalar`, not a bare
  ## `array[32, byte]`, since batch A's `SecretScalar` distinct type
  ## (round-3 fix batch A, finding A3) -- wrapped here via
  ## `toSecretScalar` at the one call site this target needs it.
  let enc = pointEncode(geScalarmultBase(toSecretScalar(s)))
  var acc: uint64 = 0
  for b in enc: acc = (acc shl 1) or uint64(b and 1'u8)
  acc

# ---------------------------------------------------------------------------
# Target 3: x25519.x25519Base -- RFC 7748 Montgomery ladder
# ---------------------------------------------------------------------------

proc opX25519Base(secret: array[32, byte]): uint64 =
  let pk = x25519Base(toX25519StaticSecret(secret))
  var acc: uint64 = 0
  for b in toBytes(pk): acc = (acc shl 1) or uint64(b and 1'u8)
  acc

# ---------------------------------------------------------------------------
# Target 4: x25519(sink X25519EphemeralSecret, peer) -- ephemeral construct
# + consume path. See the module doc comment above for why this target's
# two "classes" do identical work rather than differing by secret value.
# ---------------------------------------------------------------------------

## An arbitrary fixed public peer u-coordinate (RFC 7748 accepts any
## 32-byte value here, no on-curve check). Held identical across every
## sample of both classes, same as the other targets' fixed public
## inputs -- it is not part of what this target is classifying by (see
## module doc comment), just the peer the ephemeral exchange completes
## against.
const fixedPeerBytes: array[32, byte] = block:
  var b: array[32, byte]
  for i in 0 ..< 32: b[i] = byte(i * 7 + 1)
  b

let fixedPeer = toX25519Public(fixedPeerBytes)

proc opX25519EphemeralConsume(unusedClassLabel: bool): uint64 =
  ## `unusedClassLabel` is exactly that -- unused. Both classes draw a
  ## fresh ephemeral secret and consume it against `fixedPeer`; see the
  ## module doc comment for why no class-distinguishing secret value
  ## exists for this type. Sole reference to `secret` before its one
  ## consuming call, so ordinary last-use inference lets this compile
  ## without `move()` (see `x25519.nim`'s doc comment on the sink
  ## overload).
  let secret = x25519EphemeralSecret()
  let shared = x25519(secret, fixedPeer)
  var acc: uint64 = 0
  if shared.isSome:
    for b in toBytes(shared.get()): acc = (acc shl 1) or uint64(b and 1'u8)
  acc

# ---------------------------------------------------------------------------
# Target 5: x25519(X25519StaticSecret, peer) -- arbitrary-peer DH path,
# fixed-vs-random SECRET (RFC-003 slice 5 item 1). Mirrors target 3's
# (`x25519Base`) fixed-vs-random structure exactly, just through the
# two-party DH overload against the same fixed peer the ephemeral target
# above uses -- this is the real leak test the ephemeral target's own doc
# comment says it cannot be, since `X25519StaticSecret` has a from-bytes
# constructor and so CAN be held genuinely fixed across the whole class.
# ---------------------------------------------------------------------------

proc opX25519StaticDH(secret: array[32, byte]): uint64 =
  let shared = x25519(toX25519StaticSecret(secret), fixedPeer)
  var acc: uint64 = 0
  if shared.isSome:
    for b in toBytes(shared.get()): acc = (acc shl 1) or uint64(b and 1'u8)
  acc

# ---------------------------------------------------------------------------
# Target 6: ristretto.ristrettoScalarmult -- CT variable-base scalarmult,
# fixed-vs-random SECRET (RistrettoStaticSecret), fixed public point.
# RFC-004 slice 7b.
# ---------------------------------------------------------------------------

## Arbitrary fixed 64-byte input for the `ristrettoScalarmult` fixed
## class. Wide-reduced by `toRistrettoStaticSecretWide` (TOTAL -- no
## `Option` unwrap, so no reject-vs-accept branching to confound the
## measurement) inside `opRistrettoScalarmult` below, into a canonical
## residue mod L, then held fixed across every fixed-class sample.
const fixedRistrettoStaticBytes64: array[64, byte] = block:
  var b: array[64, byte]
  for i in 0 ..< 64: b[i] = byte(i * 3 + 5)
  b

proc opRistrettoScalarmult(bytes: array[64, byte]): uint64 =
  ## Builds the `RistrettoStaticSecret` INSIDE the measured region from
  ## its wide from-bytes constructor, once per sample -- mirroring
  ## `opX25519StaticDH` above exactly (secret constructed from raw bytes
  ## inside `operate`, not pre-built in Phase 1), the design the RFC-004
  ## slice 7b task names as "the ristretto static target follows the
  ## [sixth target's] design." The multiplied point is held fixed
  ## (`RistrettoBasePoint`) across both classes, so only the secret
  ## varies -- a genuine fixed-vs-random-secret leak test of
  ## `scalar.geScalarmultCT` via its `ristretto.ristrettoScalarmult`
  ## wrapper.
  let secret = toRistrettoStaticSecretWide(bytes)
  let r = ristrettoScalarmult(secret, RistrettoBasePoint)
  foldBytes32(toBytes(ristrettoEncode(r)))

# ---------------------------------------------------------------------------
# Target 7: ristretto.ristrettoEncode -- fixed-vs-random INPUT POINT.
# RFC-004 slice 7b.
# ---------------------------------------------------------------------------

let fixedRistrettoPoint = randomRistrettoPoint()
  ## One fixed ristretto255 element, sampled once via the rejection
  ## generator above before any timing starts (module-init time, the same
  ## register as `fixedPeer` above for the X25519 targets) -- reused as
  ## the "fixed" class input for both the encode target below and the
  ## `==` target's fixed operand `P`.

proc opRistrettoEncode(p: RistrettoPoint): uint64 =
  foldBytes32(toBytes(ristrettoEncode(p)))

# ---------------------------------------------------------------------------
# Target 8: ristretto.`==` -- (P, P) fixed vs (P, Q) random, so the
# match path itself is what gets timed. RFC-004 slice 7b (round-2 class
# redesign, restated in this file's module doc comment above).
#
# **Measured status: FAIL, investigated at length, attributed to this
# harness's resolution floor for very fast primitives -- NOT to a
# secret-dependent branch or index in `ristretto.\`==\``.** See
# docs/ct-results.md for the full writeup; summarized here so the code and
# the record stay in sync:
#
# `ristretto.\`==\`` is straight-line CT code -- two unconditional
# `feEqualCT` calls plus a bitwise-or combine, no branch or array index
# that depends on any comparison outcome, built on the already
# machine-checked `feCMove`/`feCSwap` mask algebra (`tests/verify/
# symex_mask.nim`). Despite this, a naive single-call-per-sample
# measurement of this exact (P,P)-vs-(P,Q) class design FAILS: worst-case
# |t| in the 20-40 range across three independent full-battery runs, and
# 100+ in later isolated diagnostics with less surrounding measurement
# noise. Two rounds of dedicated, non-shipped diagnostics (built, run, and
# deleted per CLAUDE.md's "scratch files do not get committed" rule; the
# investigation is preserved here and in docs/ct-results.md rather than in
# the deleted files) ruled out every constant-time-relevant explanation
# tried:
#   1. A fixed-but-ALWAYS-UNEQUAL comparison target (never evaluating
#      true) shows an EQUALLY LARGE OR LARGER spurious |t| against a
#      random target as the real (sometimes-true) design does -- proof
#      the signal does NOT track the TRUE/FALSE verdict `==`'s CT design
#      protects.
#   2. Batching K=64 independent (P,P)/(P,Q) sub-comparisons per timed
#      sample (diluting per-call rdtsc/pipeline overhead, the standard
#      dudect remedy for very fast primitives) reduced an isolated
#      single-target measurement from FAIL to WARN, but made the SAME
#      design WORSE inside the full ten-target battery (a 10GB
#      `randomInputs` pre-allocation this design required -- `dudect.
#      runDudect`'s Phase 1 always pre-builds the entire random-class
#      input array up front -- introduced memory pressure invisible in
#      isolation but real at full-battery scale).
#   3. A revised batched design using a cheap `int32` pool-offset as T
#      (avoiding the large pre-allocation entirely, ~4MB regardless of K)
#      made the full-battery result WORSE STILL (worst-case |t| in the
#      100-200+ range) despite every OTHER target in that same run
#      measuring cleanly (|t| < 2.5) -- ruling out general host noise as
#      the explanation.
#   4. A further-refined design using GENUINELY DISTINCT memory addresses
#      for the equal-vs-unequal comparison targets (rather than literally
#      re-reading one address twice, which (3)'s offset=0 case did) still
#      showed the same large, consistently-signed effect -- ruling out
#      same-address-reload/store-forwarding as the sole explanation too.
# The common thread across every design that DID show the effect: the
# "fixed" class always touches the same small, constant set of memory
# addresses every sample, while the "random" class's addresses vary
# sample-to-sample -- a property of ANY fixed-vs-random dudect class
# design, not of this operation's arithmetic. This asymmetry is present in
# every dudect target in this codebase, including the six pre-existing
# ones, but is negligible against their far larger per-sample cost
# (26,000-500,000+ cycles); `ristretto.\`==\`` (~800-900 cycles raw) is by
# 30-600x the smallest operation ever measured by this harness, and is
# apparently the first target small enough to expose it. This reads as a
# genuine measurement-methodology resolution floor for very fast
# primitives -- a documented dudect limitation in the wider literature --
# rather than a software constant-time defect, but the exact hardware
# mechanism (prefetcher behavior on varying vs. repeated access patterns
# is the leading hypothesis) was not conclusively pinned down: this
# sandboxed environment has no `perf`/cachegrind/PMU access to confirm it
# directly. Reverted to the simplest, most RFC-literal single-call design
# below (batching was explored at length and did not achieve a clean
# result at full-battery scale, while adding real complexity and memory
# cost) so the shipped code stays minimal; the measured numbers are
# recorded honestly in docs/ct-results.md rather than suppressed or
# forced to a false PASS.
# ---------------------------------------------------------------------------

proc opRistrettoEqual(q: RistrettoPoint): uint64 =
  ## Class A (fixed): `q` IS `fixedRistrettoPoint` -- both `feEqualCT`
  ## OR-terms inside `ristretto.\`==\`` hit their TRUE branch. Class B
  ## (random): `q` is a fresh rejection-sampled point, essentially always
  ## unequal to `fixedRistrettoPoint` -- FALSE throughout. `uint64(bool)`
  ## folds the single-bit result into the anti-DCE sink the same way
  ## every other target's byte-fold does.
  uint64(fixedRistrettoPoint == q)

# ---------------------------------------------------------------------------
# Target 9: ristretto.ristrettoFromUniformBytes -- fixed-vs-random 64-byte
# INPUT (the map's own domain; OPRF blinding maps a private input here).
# RFC-004 slice 7b.
# ---------------------------------------------------------------------------

## Arbitrary fixed 64-byte input for the `ristrettoFromUniformBytes`
## fixed class -- a distinct byte pattern from
## `fixedRistrettoStaticBytes64` above purely so the two constants are
## visually distinguishable in this file; `ristrettoMap`/
## `ristrettoFromUniformBytes` are TOTAL functions that treat every
## input uniformly regardless of byte pattern.
const fixedUniformBytes64: array[64, byte] = block:
  var b: array[64, byte]
  for i in 0 ..< 64: b[i] = byte(i * 13 + 7)
  b

proc opRistrettoFromUniformBytes(bytes: array[64, byte]): uint64 =
  let p = ristrettoFromUniformBytes(bytes)
  foldBytes32(toBytes(ristrettoEncode(p)))

# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

proc parseSamples(): int =
  result = DefaultSamplesPerClass
  if paramCount() >= 1:
    var v: int
    if parseInt(paramStr(1), v) > 0 and v > 0:
      result = v

when isMainModule:
  randomize()
  let n = parseSamples()
  echo "dudect harness -- samples/class = ", n
  echo ""

  var reports: seq[DudectReport]

  block:
    let fixedSecret = block:
      var s: array[32, byte]
      s[0] = 0x10'u8 # even -> always the slow branch in the fixed class
      s
    reports.add runDudect("positive_control (expected FAIL -- harness self-test)",
      n, fixedSecret, randomBytes32, leakyOp)

  block:
    let fixedSeed = block:
      var s: array[32, byte]
      for i in 0 ..< 32: s[i] = byte(i)
      s
    reports.add runDudect("backend.signDetached", n, fixedSeed, randomBytes32, opSignDetached)

  block:
    let fixedScalar = clampedRandomScalar()
    reports.add runDudect("scalar.geScalarmultBase", n, fixedScalar, clampedRandomScalar, opGeScalarmultBase)

  block:
    let fixedSecret = randomBytes32()
    reports.add runDudect("x25519.x25519Base", n, fixedSecret, randomBytes32, opX25519Base)

  block:
    # Both classes do identical work (see module doc comment and
    # opX25519EphemeralConsume's own doc comment) -- `true`/`false` here
    # are arbitrary, unread labels, not a fixed-vs-random secret pair.
    proc makeDummyRandomLabel(): bool = true
    reports.add runDudect("x25519(ephemeral) construct+consume", n, true,
      makeDummyRandomLabel, opX25519EphemeralConsume)

  block:
    let fixedSecret = randomBytes32()
    reports.add runDudect("x25519(static) vs peer", n, fixedSecret, randomBytes32, opX25519StaticDH)

  block:
    reports.add runDudect("ristretto.ristrettoScalarmult", n,
      fixedRistrettoStaticBytes64, randomBytes64, opRistrettoScalarmult)

  block:
    reports.add runDudect("ristretto.ristrettoEncode", n,
      fixedRistrettoPoint, randomRistrettoPoint, opRistrettoEncode)

  block:
    reports.add runDudect("ristretto.`==` (P,P) vs (P,Q)", n,
      fixedRistrettoPoint, randomRistrettoPoint, opRistrettoEqual)

  block:
    reports.add runDudect("ristretto.ristrettoFromUniformBytes", n,
      fixedUniformBytes64, randomBytes64, opRistrettoFromUniformBytes)

  for r in reports:
    report(r)
    echo ""

  echo "(sink, ignore: ", sinkValue(), ")"

  # Exit nonzero only if a REAL target (not the positive control, whose
  # FAIL is the expected/correct outcome) fails at the |t| > 10 level --
  # see docs/ct-results.md for the policy on WARN-level results.
  var hardFailure = false
  for r in reports:
    if r.name.startsWith("positive_control"):
      if r.verdict != vFail:
        echo "HARNESS SELF-TEST FAILED: positive control did not trip the detector (verdict=", r.verdict, ") -- the harness itself cannot be trusted; see docs/ct-results.md."
        hardFailure = true
    else:
      if r.verdict == vFail:
        echo "TIMING FAILURE: ", r.name, " exceeded |t| > 10 -- see docs/ct-results.md."
        hardFailure = true

  if hardFailure:
    quit(1)
