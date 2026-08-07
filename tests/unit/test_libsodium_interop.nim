## tests/unit/test_libsodium_interop.nim — bidirectional pure-Nim <->
## libsodium interop (RFC-001 slice 10).
##
## This file is a permanent member of the shared `unit_test_files` array
## (`scripts/lib/unit-test-files.sh`, `source`d by both `scripts/test.sh`
## and `scripts/test-libsodium.sh` -- round-2 finding 25) -- but its actual
## body only exists `when defined(selloLibsodium)`. Under plain
## `scripts/test.sh` (no flag),
## `sello/private/backend_sodium` is never imported and this file
## contributes a single no-op "skipped" test, so the suite still reports
## green without ever touching libsodium or requiring it to be installed.
## Under `-d:selloLibsodium` (`scripts/test-libsodium.sh`, run inside the
## sello-owned libsodium image), the real bidirectional interop checks run.
##
## Interop is strictly stronger evidence than both backends separately
## passing the same fixed RFC/Wycheproof vectors: it proves sello's
## pure-Nim signer and libsodium's audited signer are talking the same
## protocol, in both directions, against each other -- not just against
## a shared paper spec.

import std/unittest

when defined(selloLibsodium):
  import std/options
  import proptest
  import sello/signing
  import sello/ed25519
  import sello/x25519
  import sello/private/backend
  import sello/private/backend_sodium
  import ./wycheproof_vectors

  # RFC 8032 §7.1 TEST 1 seed -- reused here purely as a convenient fixed
  # 32-byte value; this suite is about cross-backend agreement, not RFC
  # vector coverage (that's test_signing.nim/test_ed25519.nim's job).
  const
    seedBytes: array[32, byte] = [
      0x9d'u8, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
      0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
      0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
      0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
    ]

  # `staticRead` must be evaluated at a module/const-level call site --
  # invoking it directly inside a `test`/`property` template body (rather
  # than a top-level `const`) is a compile error ("can only be used in
  # compile-time context"), even though the read itself is compile-time
  # regardless of where the RESULT is consumed. Hoisted here, matching
  # test_wycheproof.nim/test_wycheproof_x25519.nim's own top-level-const
  # convention for the identical files.
  const
    rawEd25519Vectors = staticRead("../vectors/ed25519_test.json")
    rawX25519Vectors = staticRead("../vectors/x25519_test.json")

  suite "libsodium interop (bidirectional) - RFC-001 slice 10":
    test "keygen parity: same seed derives the same public key in both backends":
      let purePk = keypair(toSeed(seedBytes)).public
      let sodiumPk = backend_sodium.derivePublic(seedBytes)
      check array[32, byte](purePk) == sodiumPk

    test "pure-Nim signature verifies under libsodium's own crypto_sign_verify_detached":
      let kp = keypair(toSeed(seedBytes))
      let msg = "sello <-> libsodium interop (pure sign, sodium verify)"
      let sig = kp.sign(msg)
      check backend_sodium.sodiumVerifyDetached(array[64, byte](sig),
        msg.toOpenArrayByte(0, msg.len - 1), array[32, byte](kp.public))

    test "libsodium-produced signature verifies under sello's pure verify":
      let msg = "sello <-> libsodium interop (sodium sign, pure verify)"
      let pk = keypair(toSeed(seedBytes)).public
      let sodiumSig = backend_sodium.signDetached(seedBytes, array[32, byte](pk),
        msg.toOpenArrayByte(0, msg.len - 1))
      check verify(pk, msg, Signature(sodiumSig))

    test "identical signatures byte-for-byte for the same (seed, msg) -- deterministic EdDSA":
      let kp = keypair(toSeed(seedBytes))
      let msg = "sello <-> libsodium interop (determinism)"
      let pureSig = kp.sign(msg)
      let sodiumSig = backend_sodium.signDetached(seedBytes, array[32, byte](kp.public),
        msg.toOpenArrayByte(0, msg.len - 1))
      check array[64, byte](pureSig) == sodiumSig

    test "empty-message interop (RFC 8032 TEST1's degenerate edge case)":
      let emptyMsg: array[0, byte] = []
      let kp = keypair(toSeed(seedBytes))
      let pureSig = kp.sign(emptyMsg)
      let sodiumSig = backend_sodium.signDetached(seedBytes, array[32, byte](kp.public), emptyMsg)
      check array[64, byte](pureSig) == sodiumSig
      check backend_sodium.sodiumVerifyDetached(array[64, byte](pureSig), emptyMsg,
        array[32, byte](kp.public))
      check verify(kp.public, emptyMsg, Signature(sodiumSig))

  # ---------------------------------------------------------------------
  # Differential adversarial testing against libsodium (round-3 fix batch
  # B, finding B1). The bidirectional suite above proves interop on a
  # handful of hand-picked messages; this proves it on the FULL adversarial
  # corpus both `test_wycheproof.nim`/`test_wycheproof_x25519.nim` already
  # exercise against sello alone -- the empirical "does sello disagree with
  # an audited implementation under adversarial pressure" question the
  # round-2 audit flagged as unanswered. Vector parsing is shared
  # (`wycheproof_vectors.nim`), not re-copied, per the finding's own
  # instruction.
  #
  # These assert AGREEMENT between the two backends' verdicts on every
  # vector -- not agreement with the vector's own `expected`/`shared`
  # field (that's what test_wycheproof*.nim already checks against sello
  # alone). A vector both backends mishandle identically would pass this
  # suite and still be caught by the single-backend suites' `expected`
  # comparison; this suite's whole job is catching the case where the two
  # backends disagree with EACH OTHER, which single-backend testing can
  # never observe.
  suite "differential: sello.verify vs libsodium crypto_sign_verify_detached, full Wycheproof ed25519 corpus":
    test "verdict agreement on every eddsa_verify vector":
      let vectors = loadEd25519Vectors(rawEd25519Vectors)
      var checked = 0
      var mismatches = 0
      var comparable = 0
      for v in vectors:
        inc checked
        # libsodium's crypto_sign_verify_detached has no siglen parameter
        # at all (its C prototype hard-codes CRYPTO_SIGN_BYTES=64) -- a
        # non-64-byte signature literally cannot be represented in that
        # call, the same reason test_wycheproof.nim treats it as an
        # automatic reject rather than calling into verify's 64-byte API.
        # Such a vector contributes no differential evidence either way
        # (there is no libsodium call to compare sello's rejection
        # against), so it's counted toward `checked` but skipped here,
        # same as it is dropped from that suite's `got` computation.
        if v.sig.len != 64: continue
        inc comparable
        var sigArr: array[64, byte]
        for i in 0 ..< 64: sigArr[i] = v.sig[i]
        let pureGot = verify(toPublicKey(v.pk), v.msg, toSignature(sigArr))
        let sodiumGot = backend_sodium.sodiumVerifyDetached(sigArr, v.msg, v.pk)
        if pureGot != sodiumGot:
          inc mismatches
          echo "  DIFFERENTIAL MISMATCH tcId=", v.tcId, " pure=", pureGot,
               " sodium=", sodiumGot, " comment=", v.comment
      echo "  ed25519 differential: ", comparable, "/", checked,
           " vectors comparable (64-byte sig), ", mismatches, " mismatches"
      check mismatches == 0
      check checked == vectors.len

  suite "differential: sello.x25519 vs libsodium crypto_scalarmult, full Wycheproof X25519 corpus":
    test "shared-secret / none agreement on every xdh_comp vector":
      let vectors = loadX25519Vectors(rawX25519Vectors)
      var checked = 0
      var mismatches = 0
      for v in vectors:
        inc checked
        let pureGot = x25519(toX25519StaticSecret(v.priv), toX25519Public(v.pub))
        let sodiumGot = backend_sodium.sodiumScalarmult(v.priv, v.pub)
        # libsodium's crypto_scalarmult returns -1 (mapped to `none` by
        # sodiumScalarmult) on an all-zero output, the exact same
        # small-order-rejection contract sello's x25519 signals with
        # `none` -- so "both none" and "both some with equal bytes" are
        # the only agreement shapes.
        let agree =
          (pureGot.isNone and sodiumGot.isNone) or
          (pureGot.isSome and sodiumGot.isSome and toBytes(pureGot.get) == sodiumGot.get)
        if not agree:
          inc mismatches
          echo "  DIFFERENTIAL MISMATCH tcId=", v.tcId,
               " pureSome=", pureGot.isSome, " sodiumSome=", sodiumGot.isSome,
               " comment=", v.comment
      echo "  x25519 differential: ", checked, " vectors, ", mismatches, " mismatches"
      check mismatches == 0
      check checked == vectors.len

  # RFC-002 slice 4 item 1: random-seed backend parity property. The fixed
  # tests above pin exactly one seed (RFC 8032's TEST 1 seed); this
  # generalizes to a `forAll` over random seeds AND random messages,
  # calling the two backends' seed-level primitives directly
  # (`sello/private/backend` vs. `sello/private/backend_sodium`) rather
  # than going through `Keypair`/`sign` -- both backends share the
  # identical `derivePublic`/`signDetached(seed, publicBytes, msg)`
  # contract (RFC-001 ledger finding 13) precisely so this kind of
  # cross-backend comparison is a direct call-for-call match, with no
  # `Keypair` wrapping needed on either side. Homed here (not a
  # `test_properties_*` file) because this suite is already the
  # established location for cross-backend agreement coverage, and it
  # already carries the `when defined(selloLibsodium)` skip pattern that
  # keeps plain `scripts/test.sh` green without libsodium installed.
  proc randByte(): Strategy[byte] =
    integers(0, 255).map(proc(x: int): byte = byte(x))

  proc seedBytes32(): Strategy[array[32, byte]] =
    arrays[32, byte](randByte())

  proc paritySettings(): Settings =
    result = defaultSettings()
    result.maxExamples = 50

  suite "libsodium interop property: random-seed/message backend parity":
    property "derivePublic and signDetached agree byte-for-byte across backends":
      with paritySettings()
      given sb in seedBytes32(), msg in bytes(0, 256)
      let purePub = backend.derivePublic(sb)
      let sodiumPub = backend_sodium.derivePublic(sb)
      let pureSig = backend.signDetached(sb, purePub, msg)
      let sodiumSig = backend_sodium.signDetached(sb, sodiumPub, msg)
      ensure purePub == sodiumPub and pureSig == sodiumSig
else:
  suite "libsodium interop (skipped)":
    test "skipped: build with -d:selloLibsodium (scripts/test-libsodium.sh) to run this suite":
      skip()
