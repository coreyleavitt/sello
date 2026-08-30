## tests/ct_taint/target_keypair_expected_public.nim -- RFC-005 slice 21
## (A1). Taint target for `signing.keypair(seed: sink Seed; expectedPublic:
## PublicKey): Option[Keypair]` (janus consumer finding 2's load-time gate
## for persisted keys): SEED tainted, both MATCH and MISMATCH arms driven
## via `-d:keypairMismatch` (A1's own "both verdict arms" definition of
## done).
##
## **No new `DeclassId`/call site needed** (recorded in
## `private/taint.declassRegister`'s `stKeypairExpectedPublic` register
## entry, `tests/registers/secret_targets.nim`): by the time this proc's
## `kp.public == expectedPublic` compare runs, `kp.public`'s bytes are
## ALREADY DEFINED -- `keypair(seed)` (called internally, first line of
## this proc) already declassified them via the shipped
## `declassify(diDerivePublicKey, result)` call site inside
## `backend.derivePublic`, and a copy of already-defined bytes stays
## defined. So the interior vartime `==` compare this proc performs runs
## on fully-defined data regardless of arm, and this target's whole
## purpose is confirming exactly that: BOTH the match and mismatch arms
## run clean, with `diDerivePublicKey`'s exercise counter bumped once per
## arm (two keypair(seed) constructions -- see below) and no additional
## disclosure needed for the compare itself.
##
## The zero-annotation red->green arc: run against the pre-declassify
## state of `private/backend.nim` (the same tree state
## `target_sign.nim`'s own header comment describes), this target is
## expected to be RED at `kp.public`'s own construction inside the first
## `keypair(seed)` call (the interior return-copy inside `derivePublic`
## reads `result` while still undefined) -- the SAME red finding
## `target_sign.nim` already documents, not a new one; this target adds
## no new disclosure point of its own.
import std/options
import sello/signing
import sello/wire
import sello/private/taint

var seedBytes: array[32, byte]
for i in 0 ..< 32: seedBytes[i] = byte(i * 3 + 1)
markUndefined(seedBytes)

let kp = keypair(toSeed(seedBytes))
let realPublic = kp.public()
checkDefined(toBytes(realPublic))

when defined(keypairMismatch):
  var wrongBytes = toBytes(realPublic)
  wrongBytes[0] = wrongBytes[0] xor 0xFF'u8
  let expected = toPublicKey(wrongBytes)
else:
  let expected = realPublic

var seedBytes2: array[32, byte]
for i in 0 ..< 32: seedBytes2[i] = byte(i * 3 + 1)
markUndefined(seedBytes2)

var loaded = keypair(toSeed(seedBytes2), expected)
  ## Calls `keypair(seed)` internally (the real, shipped
  ## `declassify(diDerivePublicKey, result)` call site fires here, GREEN
  ## state only), then the interior vartime `kp.public == expectedPublic`
  ## compare -- sanctioned per this file's own header comment, no
  ## separate declassify needed.

when defined(keypairMismatch):
  doAssert loaded.isNone, "expected the mismatch arm to yield none"
  echo "target_keypair_expected_public(mismatch): none, as expected"
else:
  doAssert loaded.isSome, "expected the match arm to yield some"
  let extractedKp = move(loaded.get())
  checkDefined(toBytes(extractedKp.public()))
  echo "target_keypair_expected_public(match): some, as expected"

echo "target_keypair_expected_public: diDerivePublicKey exercises = ", exerciseCount(diDerivePublicKey)
