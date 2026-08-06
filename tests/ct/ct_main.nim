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
##
## For every real target, only the SECRET varies between classes (fixed
## vs. per-sample random); any public input (message, peer point) is
## held identically fixed in both classes, so a detected timing
## difference can only be attributed to the secret.

import std/[os, parseutils, strutils, random]
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
