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
##
## SELLO_REQUIRE_LIBSODIUM=1 (RFC-005 slice 14): the `else` branch below
## is this file's ONLY skip() path -- reached exactly when
## `-d:selloLibsodium` is absent from the compile. The merge gate's
## `unit-linux-amd64-gcc-libsodium` job exists specifically to run this
## suite for real, so a silent skip there (e.g. a future edit to
## scripts/test-libsodium.sh that accidentally drops -d:selloLibsodium,
## or the job running against the wrong image/script) must be a red
## check, not a quietly-degraded no-op -- the same "silent skip is a red
## check" posture scripts/ci-property.sh's nelli-skip-banner assertion
## and the macOS/Windows legs' --expect-nelli-skip already hold
## elsewhere in this codebase. When this env var is set to "1" and the
## else branch is reached, the skipped test fails loud via doAssert
## instead of calling skip() -- see that branch, at the bottom of this
## file, for the exact message. Left unset (every other caller: a plain
## `scripts/test.sh` run, a maintainer's local `nim c -r` with no
## -d:selloLibsodium, `scripts/test.sh --cpu i386`'s own
## test_libsodium_interop.nim compile, etc.), behavior is byte-identical
## to before this slice -- a quiet, green skip.

import std/unittest

when defined(selloLibsodium):
  import std/[options, strutils]
  import nelli
  import sello/signing
  import sello/ed25519
  import sello/x25519
  import sello/ristretto
  import sello/scalar
  import sello/private/backend
  import sello/private/backend_sodium
  import sello/private/sha512
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

  # ---------------------------------------------------------------------
  # RFC-006 slice 2: differential testing against libsodium's OWN
  # crypto_hash_sha512 (`sodiumHashSha512`, `sello/private/backend_sodium`)
  # -- the differential oracle for `sello/private/sha512`'s in-house
  # implementation, landing BEFORE slice 3 lets it sign anything. Fixed
  # vectors plus a random-length one-shot sweep plus a random-split
  # incremental sweep, matching this RFC's own "one-shot + random-split
  # incremental" wording.
  # ---------------------------------------------------------------------

  suite "differential: sello.private.sha512 vs libsodium crypto_hash_sha512 (RFC-006 slice 2)":
    test "fixed vectors: empty message, \"abc\", and a two-block-boundary message agree":
      let empty: seq[byte] = @[]
      check backend_sodium.sodiumHashSha512(empty) == sha512(empty)

      let abc = @[byte(0x61), 0x62, 0x63]
      check backend_sodium.sodiumHashSha512(abc) == sha512(abc)

      let twoBlock = newSeq[byte](200)
      check backend_sodium.sodiumHashSha512(twoBlock) == sha512(twoBlock)

  proc randByteSha512(): Strategy[byte] =
    integers(0, 255).map(proc(x: int): byte = byte(x))

  proc sha512SweepSettings(): Settings =
    result = defaultSettings()
    result.maxExamples = 50

  suite "differential: sha512 random-input sweep (RFC-006 slice 2)":
    property "one-shot agreement on random-length messages":
      with sha512SweepSettings()
      given msg in bytes(0, 300)
      ensure backend_sodium.sodiumHashSha512(msg) == sha512(msg)

    property "incremental (random split point) agreement":
      with sha512SweepSettings()
      given msg in bytes(0, 300), splitFrac in integers(0, 1000)
      let splitPoint = if msg.len == 0: 0 else: (splitFrac * msg.len) div 1000
      var ctx: sha512.Sha512Context
      ctx.init()
      ctx.update(msg[0 ..< splitPoint])
      ctx.update(msg[splitPoint ..< msg.len])
      var digest: array[64, byte]
      ctx.finish(digest)
      ensure backend_sodium.sodiumHashSha512(msg) == digest

  # ---------------------------------------------------------------------
  # RFC-004 slice 8c: differential testing against libsodium's OWN
  # ristretto255 API (`crypto_core_ristretto255_*`/
  # `crypto_scalarmult_ristretto255[_base]`, wrapped in
  # `sello/private/backend_sodium`) -- the round-3 B1 register (this
  # file's ed25519/X25519 suites above) extended to ristretto255, per
  # this RFC's own Adversarial-battery entry: every RFC 9496 Appendix
  # A.1/A.2/A.3 vector, plus a random-input sweep, run through both
  # `sello/ristretto` and libsodium, asserting verdict-AND-value
  # agreement, not merely that each backend independently matches the
  # RFC's own expected answer (`test_ristretto.nim`'s job).
  #
  # Vector values below are transcribed independently from RFC 9496
  # Appendix A here (not imported from `test_ristretto.nim`, whose own
  # A.1/A.2/A.3 consts are private to that module) -- the same
  # independent-per-file-transcription register `fuzz_common.nim`'s own
  # `ristrettoDecodeSeeds()` doc comment states explicitly. They agree
  # byte-for-byte with `test_ristretto.nim`'s transcription of the same
  # appendix, which already checks them against sello alone; this
  # suite's whole point is the orthogonal question of whether
  # libsodium's audited implementation agrees with sello's on the exact
  # same inputs.
  # ---------------------------------------------------------------------

  proc hexToArray32(s: string): array[32, byte] =
    doAssert s.len == 64
    for i in 0 ..< 32:
      result[i] = byte(parseHexInt(s[2 * i .. 2 * i + 1]))

  proc hexToArray64(s: string): array[64, byte] =
    doAssert s.len == 128
    for i in 0 ..< 64:
      result[i] = byte(parseHexInt(s[2 * i .. 2 * i + 1]))

  # RFC 9496 Appendix A.1 -- encodings of the multiples 0..15 of the
  # canonical generator.
  const A1Encodings: array[16, string] = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
    "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
    "94741f5d5d52755ece4f23f044ee27d5d1ea1e2bd196b462166b16152a9d0259",
    "da80862773358b466ffadfe0b3293ab3d9fd53c5ea6c955358f568322daf6a57",
    "e882b131016b52c1d3337080187cf768423efccbb517bb495ab812c4160ff44e",
    "f64746d3c92b13050ed8d80236a7f0007c3b3f962f5ba793d19a601ebb1df403",
    "44f53520926ec81fbd5a387845beb7df85a96a24ece18738bdcfa6a7822a176d",
    "903293d8f2287ebe10e2374dc1a53e0bc887e592699f02d077d5263cdd55601c",
    "02622ace8f7303a31cafc63f8fc48fdc16e1c8c8d234b2f0d6685282a9076031",
    "20706fd788b2720a1ed2a5dad4952b01f413bcf0e7564de8cdc816689e2db95f",
    "bce83f8ba5dd2fa572864c24ba1810f9522bc6004afe95877ac73241cafdab42",
    "e4549ee16b9aa03099ca208c67adafcafa4c3f3e4e5303de6026e3ca8ff84460",
    "aa52e000df2e16f55fb1032fc33bc42742dad6bd5a8fc0be0167436c5948501f",
    "46376b80f409b29dc2b5f6f0c52591990896e5716f41477cd30085ab7f10301e",
    "e0c418f7c8d9c4cdd7395b93ea124f3ad99021bb681dfc3302a9d99a2e53e64e",
  ]

  # RFC 9496 Appendix A.2 -- invalid encodings, every reject category.
  const A2NonCanonical: array[4, string] = [
    "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  ]

  const A2NegativeFieldElements: array[8, string] = [
    "0100000000000000000000000000000000000000000000000000000000000000",
    "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "ed57ffd8c914fb201471d1c3d245ce3c746fcbe63a3679d51b6a516ebebe0e20",
    "c34c4e1826e5d403b78e246e88aa051c36ccf0aafebffe137d148a2bf9104562",
    "c940e5a4404157cfb1628b108db051a8d439e1a421394ec4ebccb9ec92a8ac78",
    "47cfc5497c53dc8e61c91d17fd626ffb1c49e2bca94eed052281b510b1117a24",
    "f1c6165d33367351b0da8f6e4511010c68174a03b6581212c71c0e1d026c3c72",
    "87260f7a2f12495118360f02c26a470f450dadf34a413d21042b43b9d93e1309",
  ]

  const A2NonSquareXSq: array[8, string] = [
    "26948d35ca62e643e26a83177332e6b6afeb9d08e4268b650f1f5bbd8d81d371",
    "4eac077a713c57b4f4397629a4145982c661f48044dd3f96427d40b147d9742f",
    "de6a7b00deadc788eb6b6c8d20c0ae96c2f2019078fa604fee5b87d6e989ad7b",
    "bcab477be20861e01e4a0e295284146a510150d9817763caf1a6f4b422d67042",
    "2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08",
    "f4a9e534fc0d216c44b218fa0c42d99635a0127ee2e53c712f70609649fdff22",
    "8268436f8c4126196cf64b3c7ddbda90746a378625f9813dd9b8457077256731",
    "2810e5cbc2cc4d4eece54f61c6f69758e289aa7ab440b3cbeaa21995c2f4232b",
  ]

  const A2NegativeXY: array[8, string] = [
    "3eb858e78f5a7254d8c9731174a94f76755fd3941c0ac93735c07ba14579630e",
    "a45fdc55c76448c049a1ab33f17023edfb2be3581e9c7aade8a6125215e04220",
    "d483fe813c6ba647ebbfd3ec41adca1c6130c2beeee9d9bf065c8d151c5f396e",
    "8a2e1d30050198c65a54483123960ccc38aef6848e1ec8f5f780e8523769ba32",
    "32888462f8b486c68ad7dd9610be5192bbeaf3b443951ac1a8118419d9fa097b",
    "227142501b9d4355ccba290404bde41575b037693cef1f438c47f8fbf35d1165",
    "5c37cc491da847cfeb9281d407efc41e15144c876e0170b499a96a22ed31e01e",
    "445425117cb8c90edcbc7c1cc0e74f747f2c1efa5630a967c64f287792a48a4b",
  ]

  const A2SMinusOneYZero: array[1, string] = [
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  ]

  # RFC 9496 Appendix A.3 -- direct element-derivation-function input/output
  # pairs.
  const A3DirectInputs: array[7, string] = [
    "5d1be09e3d0c82fc538112490e35701979d99e06ca3e2b5b54bffe8b4dc772c14d98b696a1bbfb5ca32c436cc61c16563790306c79eaca7705668b47dffe5bb6",
    "f116b34b8f17ceb56e8732a60d913dd10cce47a6d53bee9204be8b44f6678b270102a56902e2488c46120e9276cfe54638286b9e4b3cdb470b542d46c2068d38",
    "8422e1bbdaab52938b81fd602effb6f89110e1e57208ad12d9ad767e2e25510c27140775f9337088b982d83d7fcf0b2fa1edffe51952cbe7365e95c86eaf325c",
    "ac22415129b61427bf464e17baee8db65940c233b98afce8d17c57beeb7876c2150d15af1cb1fb824bbd14955f2b57d08d388aab431a391cfc33d5bafb5dbbaf",
    "165d697a1ef3d5cf3c38565beefcf88c0f282b8e7dbd28544c483432f1cec7675debea8ebb4e5fe7d6f6e5db15f15587ac4d4d4a1de7191e0c1ca6664abcc413",
    "a836e6c9a9ca9f1e8d486273ad56a78c70cf18f0ce10abb1c7172ddd605d7fd2979854f47ae1ccf204a33102095b4200e5befc0465accc263175485f0e17ea5c",
    "2cdc11eaeb95daf01189417cdddbf95952993aa9cb9c640eb5058d09702c74622c9965a697a3b345ec24ee56335b556e677b30e6f90ac77d781064f866a3c982",
  ]

  const A3DirectOutputs: array[7, string] = [
    "3066f82a1a747d45120d1740f14358531a8f04bbffe6a819f86dfe50f44a0a46",
    "f26e5b6f7d362d2d2a94c5d0e7602cb4773c95a2e5c31a64f133189fa76ed61b",
    "006ccd2a9e6867e6a2c5cea83d3302cc9de128dd2a9a57dd8ee7b9d7ffe02826",
    "f8f0c87cf237953c5890aec3998169005dae3eca1fbb04548c635953c817f92a",
    "ae81e7dedf20a497e10c304a765c1767a42d6e06029758d2d7e8ef7cc4c41179",
    "e2705652ff9f5e44d3e841bf1c251cf7dddb77d140870d1ab2ed64f1a9ce8628",
    "80bd07262511cdde4863f8a7434cef696750681cb9510eea557088f76d9e5065",
  ]

  # RFC 9496 Appendix A.3 -- the closing four-inputs-one-output convergence
  # set.
  const A3ConvergenceInputs: array[4, string] = [
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1200000000000000000000000000000000000000000000000000000000000000",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "0000000000000000000000000000000000000000000000000000000000000080ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "00000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000080",
  ]

  const A3ConvergenceOutput = "304282791023b73128d277bdcb5c7746ef2eac08dde9f2983379cb8e5ef0517f"

  block ristrettoLibsodiumVersionPreflight:
    ## Asserted ONCE, up front, at module-init time -- ahead of every
    ## suite below, matching this RFC's own Adversarial-battery wording
    ## ("the differential suite asserts the version once up front")
    ## rather than betting silently on the `sello-dev` image's package
    ## resolution. `major`/`minor` here are `sodium_library_version_*`'s
    ## RUNTIME-queried ABI pair (via `backend_sodium.sodiumLibraryVersion`),
    ## not the compile-time `SODIUM_LIBRARY_VERSION_MAJOR`/`_MINOR` header
    ## macros -- this checks what actually got dynamically linked.
    ##
    ## The `(10, 3)` threshold is an EMPIRICAL finding, not an assumption:
    ## confirmed directly against libsodium's own upstream `configure.ac`
    ## at both the 1.0.17 and 1.0.18 release tags -- 1.0.17 sets
    ## `SODIUM_LIBRARY_VERSION_MAJOR/MINOR` to `(10, 2)`, and
    ## `crypto_core_ristretto255.h` is absent from that tag's source tree
    ## entirely; 1.0.18 sets the pair to `(10, 3)`, with
    ## `crypto_core_ristretto255.h` AND `crypto_scalarmult_ristretto255.h`
    ## both present -- exactly the release RFC 9496's ristretto255 API
    ## shipped in libsodium. Lexicographic `(major, minor)` comparison
    ## stays a valid `>= 1.0.18` proxy for every release after that too:
    ## 1.0.19 jumps the pair to `(26, 1)` on a soname bump, still greater
    ## than `(10, 3)` under this ordering, and no later release's major
    ## drops back below 26.
    let (major, minor) = backend_sodium.sodiumLibraryVersion()
    doAssert major > 10 or (major == 10 and minor >= 3),
      "sello ristretto255 differential suite requires libsodium >= 1.0.18 " &
      "(SODIUM_LIBRARY_VERSION >= (10, 3)); linked library reports (" &
      $major & ", " & $minor & ")"

  suite "differential: ristretto255 decode verdict agreement vs libsodium crypto_core_ristretto255_is_valid_point -- RFC 9496 Appendix A.1/A.2":
    test "A.1 valid encodings: both backends accept":
      var mismatches = 0
      for s in A1Encodings:
        let bytes = hexToArray32(s)
        let pureGot = ristrettoDecode(toRistrettoEncoded(bytes)).isSome
        let sodiumGot = backend_sodium.sodiumRistrettoIsValidPoint(bytes)
        if (not pureGot) or (not sodiumGot):
          inc mismatches
          echo "  DIFFERENTIAL MISMATCH A.1 encoding=", s,
               " pureAccept=", pureGot, " sodiumAccept=", sodiumGot
      check mismatches == 0

    test "A.2 invalid encodings, every reject category: both backends reject":
      var invalid: seq[string] = @[]
      invalid.add(A2NonCanonical)
      invalid.add(A2NegativeFieldElements)
      invalid.add(A2NonSquareXSq)
      invalid.add(A2NegativeXY)
      invalid.add(A2SMinusOneYZero)
      var mismatches = 0
      for s in invalid:
        let bytes = hexToArray32(s)
        let pureGot = ristrettoDecode(toRistrettoEncoded(bytes)).isSome
        let sodiumGot = backend_sodium.sodiumRistrettoIsValidPoint(bytes)
        if pureGot or sodiumGot:
          inc mismatches
          echo "  DIFFERENTIAL MISMATCH A.2 encoding=", s,
               " pureAccept=", pureGot, " sodiumAccept=", sodiumGot
      check mismatches == 0

  suite "differential: ristretto255 hash-to-group value agreement vs libsodium crypto_core_ristretto255_from_hash -- RFC 9496 Appendix A.3":
    test "direct pairs: sello ristrettoFromUniformBytes and libsodium from_hash agree byte-for-byte":
      var mismatches = 0
      for i in 0 ..< A3DirectInputs.len:
        let input = hexToArray64(A3DirectInputs[i])
        let pureOut = toBytes(ristrettoEncode(ristrettoFromUniformBytes(input)))
        let sodiumOut = backend_sodium.sodiumRistrettoFromHash(input)
        if pureOut != sodiumOut:
          inc mismatches
          echo "  DIFFERENTIAL MISMATCH A.3 direct input=", A3DirectInputs[i],
               " pure=", pureOut, " sodium=", sodiumOut
        check pureOut == hexToArray32(A3DirectOutputs[i])
      check mismatches == 0

    test "convergence set: sello and libsodium agree on each input, and both land on the labeled output":
      let expected = hexToArray32(A3ConvergenceOutput)
      var mismatches = 0
      for s in A3ConvergenceInputs:
        let input = hexToArray64(s)
        let pureOut = toBytes(ristrettoEncode(ristrettoFromUniformBytes(input)))
        let sodiumOut = backend_sodium.sodiumRistrettoFromHash(input)
        if pureOut != sodiumOut:
          inc mismatches
          echo "  DIFFERENTIAL MISMATCH A.3 convergence input=", s,
               " pure=", pureOut, " sodium=", sodiumOut
        check pureOut == expected
      check mismatches == 0

  # -----------------------------------------------------------------------
  # Scalarmult value agreement. See `backend_sodium.sodiumRistrettoScalarmult`/
  # `sodiumRistrettoScalarmultBase`'s own doc comments for why raw byte
  # equality is the WRONG predicate on its own: libsodium refuses (returns
  # `none` here) whenever the literal scalar multiple is the identity
  # element -- including simply because the scalar is zero mod L -- a
  # documented API safety choice (never hand back a degenerate all-zero DH
  # output), not a disagreement about the underlying group element. sello's
  # scalarmult family has no such carve-out: `RistrettoPoint` carries no
  # accept/reject verdict of its own (see `sello/ristretto`'s module doc
  # comment), so `RistrettoIdentity` is an ordinary, valid result.
  # -----------------------------------------------------------------------

  proc scalarmultAgrees(sodiumResult: Option[array[32, byte]]; selloResult: RistrettoPoint): bool =
    if sodiumResult.isSome:
      sodiumResult.get() == toBytes(ristrettoEncode(selloResult))
    else:
      selloResult == RistrettoIdentity

  proc detScalars(): seq[array[32, byte]] =
    ## Deterministic scalars spanning both agreement branches above:
    ## `zero` and `scalar.L` itself both drive libsodium's identity-refusal
    ## path (0*P and L*P are both the identity, for any point P of order
    ## L); `L - 1`/`L + 1` are the boundary-adjacent nonzero-mod-L cases
    ## (matching `test_ristretto.nim`'s own `lMinus1Bytes()` boundary
    ## discipline); `1`/`2` are small ordinary multiples.
    var zero: array[32, byte]
    var one: array[32, byte]
    one[0] = 1
    var two: array[32, byte]
    two[0] = 2
    var lMinus1 = scalar.L
    lMinus1[0] = lMinus1[0] - 1
    var lPlus1 = scalar.L
    lPlus1[0] = lPlus1[0] + 1
    @[zero, one, two, lMinus1, scalar.L, lPlus1]

  suite "differential: ristretto255 scalarmult value agreement vs libsodium crypto_scalarmult_ristretto255[_base]":
    test "deterministic scalars vs the base point (incl. libsodium's identity-refusal edge cases)":
      var mismatches = 0
      for s in detScalars():
        let sodiumGot = backend_sodium.sodiumRistrettoScalarmultBase(s)
        let selloGot = ristrettoScalarmultVartime(s, RistrettoBasePoint)
        if not scalarmultAgrees(sodiumGot, selloGot):
          inc mismatches
          echo "  DIFFERENTIAL MISMATCH base-mult scalar=", s,
               " sodiumSome=", sodiumGot.isSome,
               " selloEncoded=", toBytes(ristrettoEncode(selloGot))
      check mismatches == 0

    test "deterministic scalars vs a fixed non-base point (variable-base agreement)":
      let p = ristrettoFromUniformBytes(hexToArray64(A3DirectInputs[0]))
      let pBytes = toBytes(ristrettoEncode(p))
      var mismatches = 0
      for s in detScalars():
        let sodiumGot = backend_sodium.sodiumRistrettoScalarmult(s, pBytes)
        let selloGot = ristrettoScalarmultVartime(s, p)
        if not scalarmultAgrees(sodiumGot, selloGot):
          inc mismatches
          echo "  DIFFERENTIAL MISMATCH variable-mult scalar=", s,
               " point=", pBytes, " sodiumSome=", sodiumGot.isSome,
               " selloEncoded=", toBytes(ristrettoEncode(selloGot))
      check mismatches == 0

    test "random canonical scalars: RistrettoStaticSecret-role base-mult and variable-base-mult agree with libsodium":
      var mismatches = 0
      for i in 0 ..< 20:
        let secret = ristrettoStaticSecret()
        let sBytes = toBytes(secret)
        block baseMult:
          let sodiumGot = backend_sodium.sodiumRistrettoScalarmultBase(sBytes)
          let selloGot = ristrettoScalarmultBase(secret)
          if not scalarmultAgrees(sodiumGot, selloGot):
            inc mismatches
            echo "  DIFFERENTIAL MISMATCH random base-mult scalar=", sBytes,
                 " sodiumSome=", sodiumGot.isSome,
                 " selloEncoded=", toBytes(ristrettoEncode(selloGot))
        block variableMult:
          let (_, p) = ristrettoStaticPair()
          let pBytes = toBytes(ristrettoEncode(p))
          let sodiumGot = backend_sodium.sodiumRistrettoScalarmult(sBytes, pBytes)
          let selloGot = ristrettoScalarmult(secret, p)
          if not scalarmultAgrees(sodiumGot, selloGot):
            inc mismatches
            echo "  DIFFERENTIAL MISMATCH random variable-mult scalar=", sBytes,
                 " point=", pBytes, " sodiumSome=", sodiumGot.isSome,
                 " selloEncoded=", toBytes(ristrettoEncode(selloGot))
      check mismatches == 0

  # -----------------------------------------------------------------------
  # Random-input sweep (round-3 B1 property-based-sweep register, `n = 50`
  # examples per property -- matching that suite's own `paritySettings()`
  # size/style above).
  # -----------------------------------------------------------------------

  proc randByteRistretto(): Strategy[byte] =
    integers(0, 255).map(proc(x: int): byte = byte(x))

  proc randomBytes32Ristretto(): Strategy[array[32, byte]] =
    arrays[32, byte](randByteRistretto())

  proc randomBytes64Ristretto(): Strategy[array[64, byte]] =
    arrays[64, byte](randByteRistretto())

  proc randomCanonicalScalarBytesRistretto(): Strategy[array[32, byte]] =
    ## Wide-reduces a uniformly random 64-byte draw mod L (`scReduce`) --
    ## the same route `ristrettoStaticSecret()`/`toRistrettoStaticSecretWide`
    ## use internally, matching `test_properties_ristretto.nim`'s own
    ## `randomCanonicalScalarBytes()` generator (reimplemented here rather
    ## than imported, per this file's per-module-transcription register).
    randomBytes64Ristretto().map(proc(wide: array[64, byte]): array[32, byte] =
      scReduce(result, wide))

  proc ristrettoSweepSettings(): Settings =
    result = defaultSettings()
    result.maxExamples = 50

  suite "differential: ristretto255 random-input sweep (RFC-004 slice 8c)":
    property "decode verdict agreement on uniformly random 32-byte candidates (accept AND reject)":
      with ristrettoSweepSettings()
      given bytes in randomBytes32Ristretto()
      let pureGot = ristrettoDecode(toRistrettoEncoded(bytes)).isSome
      let sodiumGot = backend_sodium.sodiumRistrettoIsValidPoint(bytes)
      ensure pureGot == sodiumGot

    property "hash-to-group value agreement on random 64-byte inputs":
      with ristrettoSweepSettings()
      given bytes in randomBytes64Ristretto()
      let pureOut = toBytes(ristrettoEncode(ristrettoFromUniformBytes(bytes)))
      let sodiumOut = backend_sodium.sodiumRistrettoFromHash(bytes)
      ensure pureOut == sodiumOut

    property "scalarmult value agreement: random scalar x random valid point":
      with ristrettoSweepSettings()
      given sBytes in randomCanonicalScalarBytesRistretto(), pBytes in randomBytes64Ristretto()
      let p = ristrettoFromUniformBytes(pBytes)
      let sodiumGot = backend_sodium.sodiumRistrettoScalarmult(sBytes, toBytes(ristrettoEncode(p)))
      let selloGot = ristrettoScalarmultVartime(sBytes, p)
      ensure scalarmultAgrees(sodiumGot, selloGot)

else:
  import std/os

  suite "libsodium interop (skipped)":
    test "skipped: build with -d:selloLibsodium (scripts/test-libsodium.sh) to run this suite":
      # RFC-005 slice 14 -- see this file's own module doc comment for the
      # full rationale. SELLO_REQUIRE_LIBSODIUM=1 is exported by
      # scripts/test-libsodium.sh itself (both the SELLO_IN_CONTAINER=1
      # in-container body and the host-mode podman recursion), so a suite
      # run through that script -- the merge gate's
      # unit-linux-amd64-gcc-libsodium job included -- can never quietly
      # land here and still report green.
      if getEnv("SELLO_REQUIRE_LIBSODIUM", "") == "1":
        doAssert false,
          "SELLO_REQUIRE_LIBSODIUM=1 is set, but test_libsodium_interop.nim " &
          "compiled WITHOUT -d:selloLibsodium -- the libsodium differential " &
          "job (unit-linux-amd64-gcc-libsodium) must never silently degrade " &
          "to this no-op skip suite. Investigate why -d:selloLibsodium did " &
          "not reach this compile (scripts/test-libsodium.sh's own per-file " &
          "nim c invocation, or the job's container/script wiring) -- do " &
          "not silence this by unsetting the env var."
      skip()
