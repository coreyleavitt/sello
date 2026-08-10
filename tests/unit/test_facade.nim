## Facade regression test (RFC-001 slice 7): `sello.nim` must re-export
## the full signing surface (`Seed`, `Keypair`, `toSeed`, `keypair`,
## `sign` incl. the `string` overload, `wipe`, `public`, `toBytes`)
## alongside the pre-existing verify/X25519 surface, and it must all work
## through `import sello` alone -- no reaching into `sello/signing` or
## `sello/ed25519` directly. The submodule-level tests (test_signing.nim,
## test_ed25519.nim) own the actual behavioral coverage; this file's only
## job is to catch a facade export that goes missing or gets misspelled.

import std/[unittest, options, tables, sets]
import sello

suite "facade - public surface (sello.nim re-exports)":
  test "keypair() / sign / verify round trip entirely through the facade":
    let kp = keypair()
    let sig = kp.sign("facade smoke test")
    check verify(kp.public, "facade smoke test", sig)

  test "keypair(seed) via toSeed is deterministic":
    let seedBytes = default(array[32, byte])
    let kp1 = keypair(toSeed(seedBytes))
    let kp2 = keypair(toSeed(seedBytes))
    check kp1.public == kp2.public

  test "wipe(kp: var Keypair) is reachable through the facade (RFC-001 ledger finding 16)":
    ## Confirms both halves of the contract: the secret half zeroes
    ## (observed via `toSeedBytes(kp)`, RFC-002 slice 1's replacement for
    ## the old `seed()` accessor, renamed from `toBytes` by round-3 finding
    ## A7) and the public half survives untouched.
    var kp = keypair()
    let publicBefore = kp.public
    wipe(kp)
    check kp.public == publicBefore
    check toSeedBytes(kp) == default(array[32, byte])

  test "keypair(seed, expectedPublic) is reachable through the facade (janus finding 2)":
    let kp = keypair()
    let seedBytes = toSeedBytes(kp)
    check keypair(toSeed(seedBytes), kp.public).isSome
    var wrong = toBytes(kp.public)
    wrong[0] = wrong[0] xor 0x01
    check keypair(toSeed(seedBytes), toPublicKey(wrong)).isNone

  test "toSeedBytes(kp: Keypair) is reachable through the facade (RFC-002 slice 1, renamed by round-3 finding A7)":
    let kp = keypair()
    check keypair(toSeed(toSeedBytes(kp))).public == kp.public

  test "wipe(sink Seed) is reachable through the facade":
    ## `wipe` takes `sink`, not `var` (round-4 finding R4), so it consumes
    ## `s` -- `move(s)` is required inside `test:`'s implicit try/finally
    ## even for this sole remaining use.
    ##
    ## Round-4 finding R16: this test used to also capture a raw-pointer
    ## probe on `s` BEFORE the wipe and assert it read zero afterward. That
    ## assertion was vacuous: `move(s)` itself resets the moved-from
    ## SOURCE to binary zero via the compiler's default `=wasMoved` (`Seed`
    ## defines no custom `=wasMoved`), so the probe read zero because of
    ## `move`, not because of `wipe` -- the assertion would have passed
    ## even with a no-op `wipe`. A move-only sink type's caller-side local
    ## can never be observed post-move for exactly this reason, so no
    ## caller-side byte-probe on `Seed` can be a real wipe test here. This
    ## test's remaining job is purely facade-reachability (the call
    ## compiles and runs through `import sello` alone); genuine
    ## zero-on-wipe coverage lives in `tests/unit/test_ct.nim` (direct
    ## `ct.wipe` coverage) and in `test_signing.nim`'s `Seed` destructor
    ## smoke tests (which observe a real, non-moved scope-exit wipe).
    var s = toSeed([1'u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32])
    wipe(move(s))

  test "openArray[byte] overload is reachable through the facade":
    let kp = keypair()
    let msg = @[0x01'u8, 0x02, 0x03]
    check verify(kp.public, msg, kp.sign(msg))

  test "toPublicKey / toSignature / toBytes are reachable through the facade":
    let kp = keypair()
    let sig = kp.sign("nominal types")
    let pk2 = toPublicKey(toBytes(kp.public))
    let sig2 = toSignature(toBytes(sig))
    check verify(pk2, "nominal types", sig2)

  test "toX25519Public / toBytes are reachable through the facade (RFC-001 finding 26)":
    let raw = [0x0a'u8, 0x0b, 0x0c, 0x0d, 0, 0, 0, 0, 0, 0, 0, 0,
               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    let pub = toX25519Public(raw)
    check toBytes(pub) == raw

suite "facade - hash() for the public wire types (RFC-002 slice 1)":
  test "PublicKey/Signature/X25519Public are usable as Table/HashSet keys":
    let kp = keypair()
    let sig = kp.sign("hash smoke test")
    let pub = x25519Base(x25519StaticSecret())

    var pkTable = initTable[PublicKey, string]()
    pkTable[kp.public] = "alice"
    check pkTable[kp.public] == "alice"

    var sigSet = initHashSet[Signature]()
    sigSet.incl sig
    check sig in sigSet

    var pubSet = initHashSet[X25519Public]()
    pubSet.incl pub
    check pub in pubSet

suite "facade - $ for the public wire types (round-4 finding R11)":
  test "$ on PublicKey/Signature/X25519Public matches the underlying bytes' own stringification":
    ## `$` for these three types is `{.borrow.}`ed straight from the
    ## underlying `array[N, byte]` (`wire.nim`/`x25519.nim`), the same way
    ## `==`/`hash` are (pinned just above) -- so the behavioral check is
    ## that stringifying the nominal type matches stringifying its own
    ## `toBytes()`, not merely "returns something non-empty".
    let kp = keypair()
    let sig = kp.sign("dollar smoke test")
    let pub = x25519Base(x25519StaticSecret())

    check $(kp.public) == $(toBytes(kp.public))
    check $(sig) == $(toBytes(sig))
    check $(pub) == $(toBytes(pub))
    check len($(kp.public)) > 0
    check len($(sig)) > 0
    check len($(pub)) > 0

suite "facade - X25519 three-role API (RFC-001 ledger #29 revisited)":
  test "X25519StaticSecret/X25519Public/X25519Shared and their converters are reachable through the facade":
    let aliceSecret = x25519StaticSecret()
    let bobSecret = x25519StaticSecret()
    let alicePublic = x25519Base(aliceSecret)
    let bobPublic = x25519Base(bobSecret)
    let sharedA = x25519(aliceSecret, bobPublic)
    let sharedB = x25519(bobSecret, alicePublic)
    check sharedA.isSome and sharedB.isSome
    check toBytes(sharedA.get) == toBytes(sharedB.get)

    let raw = default(array[32, byte])
    let secret2 = toX25519StaticSecret(raw)
    let public2 = toX25519Public(raw)
    check toBytes(secret2) == raw
    check toBytes(public2) == raw

  test "x25519StaticPair() is reachable through the facade (RFC-003 slice 1 item 5)":
    let (secretA, publicA) = x25519StaticPair()
    let (secretB, publicB) = x25519StaticPair()
    check toBytes(publicA) == toBytes(x25519Base(secretA))
    let sharedA = x25519(secretA, publicB)
    let sharedB = x25519(secretB, publicA)
    check sharedA.isSome and sharedB.isSome
    check toBytes(sharedA.get) == toBytes(sharedB.get)

  test "X25519EphemeralSecret / x25519EphemeralSecret are reachable through the facade (static/ephemeral split)":
    var eph = x25519EphemeralSecret()
    let pub = x25519Base(eph)
    check toBytes(pub) != default(array[32, byte])
    let shared = x25519(move(eph), x25519Base(x25519EphemeralSecret()))
    check shared.isSome

  test "x25519EphemeralPair() is reachable through the facade (RFC-002 slice 1)":
    ## `var`, not `let`, and an explicit `move(eph)`: `unittest`'s `test`
    ## template wraps this body in an implicit try/finally, which requires
    ## the same `move()` ceremony even for a sole sink-consuming use (see
    ## `test_x25519.nim`'s dedicated, non-`test:`-wrapped proof that the
    ## natural top-level flow needs no `move()` at all -- that is the
    ## actual point `x25519EphemeralPair` exists to make).
    var (eph, pub) = x25519EphemeralPair()
    check toBytes(pub) != default(array[32, byte])
    let shared = x25519(move(eph), x25519Base(x25519EphemeralSecret()))
    check shared.isSome

  test "wipe(sink X25519EphemeralSecret) is reachable through the facade":
    ## `wipe` takes `sink`, not `var` (round-4 finding R4), so it consumes
    ## `eph` -- `move(eph)` is required inside `test:`'s implicit
    ## try/finally even for this sole remaining use.
    ##
    ## Round-4 finding R16: this test used to also capture a raw-pointer
    ## probe on `eph` BEFORE the wipe and assert it read zero afterward.
    ## That assertion was vacuous for the same reason the `Seed` wipe test
    ## above is: `move(eph)` resets the moved-from SOURCE to binary zero
    ## via the compiler's default `=wasMoved` before `wipe`'s own body
    ## ever runs, so the probe read zero regardless of whether `wipe`
    ## worked. A move-only sink type's caller-side local can never be
    ## observed post-move, so no caller-side byte-probe here can be a real
    ## wipe test. This test's remaining job is purely facade-reachability;
    ## genuine zero-on-wipe coverage for this type lives in
    ## `test_x25519.nim`'s ephemeral-secret destructor/scope-exit smoke
    ## tests (real, non-moved wipes) and `tests/unit/test_ct.nim` (direct
    ## `ct.wipe` coverage).
    var eph = x25519EphemeralSecret()
    wipe(move(eph))

  test "wipe(X25519StaticSecret) / wipe(X25519Shared) are reachable through the facade":
    ## Unlike `Seed`/`X25519EphemeralSecret` above, these two types use the
    ## `var` (non-sink) `wipe` overload -- `secret`/`shared` are NOT moved
    ## anywhere, so this genuinely observes `wipe`'s own zeroization: if
    ## `ct.wipe` were a no-op, `secret`/`shared` would still hold their
    ## original (essentially-never-all-zero) random secret material and
    ## the `toBytes(...) == default(...)` checks below would fail.
    var secret = x25519StaticSecret()
    doAssert toBytes(secret) != default(array[32, byte]) # sanity: nonzero before wipe
    wipe(secret)
    check toBytes(secret) == default(array[32, byte])

    let peer = x25519Base(x25519StaticSecret())
    var shared = x25519(x25519StaticSecret(), peer).get
    doAssert toBytes(shared) != default(array[32, byte]) # sanity: nonzero before wipe
    wipe(shared)
    check toBytes(shared) == default(array[32, byte])

suite "facade - nominal typing (RFC-001 finding 9, compile-time)":
  test "a bare array[32, byte] is not implicitly usable as a PublicKey":
    check(not compiles(block:
      let raw = default(array[32, byte])
      let sig = default(Signature)
      discard verify(raw, "msg", sig)
    ))

  test "x25519(secret, peer) does not compile with arguments swapped":
    check(not compiles(block:
      let secret = x25519StaticSecret()
      let peer = x25519Base(x25519StaticSecret())
      discard x25519(peer, secret) # (X25519Public, X25519StaticSecret) -- wrong order
    ))

  test "an X25519Public is not implicitly usable as an ed25519 PublicKey":
    check(not compiles(block:
      let pub = x25519Base(x25519StaticSecret())
      let sig = default(Signature)
      discard verify(pub, "msg", sig)
    ))

  test "an ed25519 PublicKey is not implicitly usable as an X25519Public":
    check(not compiles(block:
      let pk = toPublicKey(default(array[32, byte]))
      let secret = x25519StaticSecret()
      discard x25519(secret, pk)
    ))

  test "X25519StaticSecret does not implicitly convert to X25519Public":
    check(not compiles(block:
      let secret = x25519StaticSecret()
      let pub: X25519Public = secret
    ))

  test "X25519StaticSecret does not implicitly convert to array[32, byte]":
    check(not compiles(block:
      let secret = x25519StaticSecret()
      let raw: array[32, byte] = secret
    ))

  test "X25519EphemeralSecret has no toBytes overload (unpersistable by design)":
    ## Absence checks, not move-only enforcement -- `not compiles(...)` CAN
    ## see a missing overload (unlike the `=copy`/sink violations, which
    ## need the subprocess-`nim c` fixtures in test_x25519.nim). No
    ## `toBytes(X25519EphemeralSecret)` exists at all: an ephemeral secret
    ## that could be exported to bytes could be persisted, defeating the
    ## whole point.
    check(not compiles(block:
      let eph = x25519EphemeralSecret()
      discard toBytes(eph)
    ))

  test "X25519EphemeralSecret has no toX25519EphemeralSecret(bytes) constructor (freshness by construction)":
    ## The only constructor is `x25519EphemeralSecret()` itself (fresh from
    ## the OS CSPRNG) -- no from-bytes route exists to resurrect or replay
    ## a previous value.
    check(not compiles(block:
      let raw = default(array[32, byte])
      discard toX25519EphemeralSecret(raw)
    ))

suite "facade - declared effect contract (janus finding 3)":
  ## The "nothing else in the pure surface raises" promise used to be
  ## prose, held only by downstream consumers' own `{.raises: [].}`
  ## annotations via cross-module effect inference -- a regression in sello
  ## kept sello's own build green and broke consumers with an opaque
  ## effect-inference error at their call sites. Every module now carries
  ## `{.push raises: [], gcsafe.}` (with per-constructor `OSError`
  ## overrides), so the pins below fail to COMPILE if any declared effect
  ## grows -- the same shape as a consumer's annotated closure, checked in
  ## sello's own suite. `-d:selloLibsodium` widens the sign/keygen path by
  ## `SodiumInitError` (a declared, exported effect on that backend), which
  ## is why those pins split on the define.
  test "verify and the X25519 exchange satisfy {.raises: [], gcsafe.} by declaration":
    proc pinVerify(pk: PublicKey; msg: string; sig: Signature): bool {.raises: [], gcsafe.} =
      pk.verify(msg, sig)
    proc pinDh(s: X25519StaticSecret; p: X25519Public): Option[X25519Shared] {.raises: [], gcsafe.} =
      x25519(s, p)

    let kp = keypair()
    check pinVerify(kp.public, "m", kp.sign("m"))
    let (sa, pa) = x25519StaticPair()
    let (sb, pb) = x25519StaticPair()
    check pinDh(sa, pb).get().toBytes() == pinDh(sb, pa).get().toBytes()

  test "sign / keypair(seed) / keypair(seed, expectedPublic) declare exactly the backend's effect set":
    when defined(selloLibsodium):
      proc pinSign(kp: Keypair; msg: string): Signature {.raises: [SodiumInitError], gcsafe.} =
        kp.sign(msg)
      proc pinDerive(s: sink Seed): Keypair {.raises: [SodiumInitError], gcsafe.} =
        keypair(s)
      proc pinLoad(s: sink Seed; expected: PublicKey): Option[Keypair] {.raises: [SodiumInitError], gcsafe.} =
        keypair(s, expected)
    else:
      proc pinSign(kp: Keypair; msg: string): Signature {.raises: [], gcsafe.} =
        kp.sign(msg)
      proc pinDerive(s: sink Seed): Keypair {.raises: [], gcsafe.} =
        keypair(s)
      proc pinLoad(s: sink Seed; expected: PublicKey): Option[Keypair] {.raises: [], gcsafe.} =
        keypair(s, expected)

    let kp = pinDerive(toSeed(default(array[32, byte])))
    check verify(kp.public, "m", pinSign(kp, "m"))
    check pinLoad(toSeed(toSeedBytes(kp)), kp.public).isSome

  test "the five fresh-secret constructors declare {.raises: [OSError].}":
    when defined(selloLibsodium):
      proc pinFresh(): Keypair {.raises: [OSError, SodiumInitError], gcsafe.} =
        keypair()
    else:
      proc pinFresh(): Keypair {.raises: [OSError], gcsafe.} =
        keypair()
    proc pinStatic(): X25519StaticSecret {.raises: [OSError], gcsafe.} =
      x25519StaticSecret()
    proc pinEph(): X25519EphemeralSecret {.raises: [OSError], gcsafe.} =
      x25519EphemeralSecret()
    proc pinStaticPair(): tuple[secret: X25519StaticSecret, public: X25519Public] {.raises: [OSError], gcsafe.} =
      x25519StaticPair()
    proc pinEphPair(): tuple[secret: X25519EphemeralSecret, public: X25519Public] {.raises: [OSError], gcsafe.} =
      x25519EphemeralPair()

    let kp = pinFresh()
    check verify(kp.public, "m", kp.sign("m"))
    let stat = pinStatic()
    discard x25519Base(stat)
    wipe(pinEph())
    let (ss, sp) = pinStaticPair()
    var (es, ep) = pinEphPair()
    check x25519(move(es), sp).isSome
    check x25519(ss, ep).isSome
