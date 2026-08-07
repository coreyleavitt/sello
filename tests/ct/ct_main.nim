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

import std/[os, parseutils, strutils, random, options]
import sello/private/backend
import sello/field
import sello/scalar
import sello/x25519
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
  let enc = pointEncode(geScalarmultBase(s))
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
