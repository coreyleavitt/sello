## Property-based coverage for sign -> verify (RFC-001 finding 10, plus a
## slice of finding 12's "verify never fuzzed on unstructured input" --
## the single-bit-flip properties below are a structured complement to
## the raw-bytes libFuzzer work the B4b batch adds on top).
##
## See test_properties_field.nim's module doc comment for the nelli
## wiring notes (optional milpa dep, z3-avoidance) -- not repeated here.

import std/[unittest]
import nelli
import sello/signing
import sello/ed25519
import ./property_crank

proc randByte(): Strategy[byte] =
  integers(0, 255).map(proc(x: int): byte = byte(x))

proc seedBytes32(): Strategy[array[32, byte]] =
  arrays[32, byte](randByte())

proc settingsWithExamples(n: int): Settings =
  ## RFC-002 slice 3 item 3: `coverageGuided` also flipped on here -- see
  ## test_properties_field.nim's `covSettings` doc comment for the full
  ## rationale (not repeated here). `n` routed through `cranked()`
  ## (RFC-005 slice 26) -- see tests/unit/property_crank.nim.
  result = defaultSettings()
  result.maxExamples = cranked(n)
  result.coverageGuided = true

let propertySettings50 = settingsWithExamples(50)

suite "signing property: sign -> verify roundtrip":
  property "a fresh keypair's own signature over a random message always verifies":
    with propertySettings50
    given sb in seedBytes32(), msg in bytes(0, 256)
    let kp = keypair(toSeed(sb))
    let sig = kp.sign(msg)
    ensure verify(kp.public(), msg, sig)

suite "signing property: single-bit-flip rejection":
  property "flipping one bit of the signature is rejected":
    with propertySettings50
    given sb in seedBytes32(), msg in bytes(0, 256),
          byteIdx in integers(0, 63), bitIdx in integers(0, 7)
    let kp = keypair(toSeed(sb))
    var sigBytes = toBytes(kp.sign(msg))
    sigBytes[byteIdx] = sigBytes[byteIdx] xor byte(1 shl bitIdx)
    ensure not verify(kp.public(), msg, toSignature(sigBytes))

  property "flipping one bit of a nonempty message is rejected":
    with propertySettings50
    given sb in seedBytes32(), msg in bytes(1, 256),
          byteIdx in integers(0, 255), bitIdx in integers(0, 7)
    let kp = keypair(toSeed(sb))
    let sig = kp.sign(msg)
    var tampered = msg
    let idx = byteIdx mod tampered.len
    tampered[idx] = tampered[idx] xor byte(1 shl bitIdx)
    ensure not verify(kp.public(), tampered, sig)
