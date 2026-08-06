## Facade regression test (RFC-001 slice 7): `sello.nim` must re-export
## the full signing surface (`Seed`, `Keypair`, `toSeed`, `keypair`,
## `sign` incl. the `string` overload, `wipe`, `public`, `seed`) alongside
## the pre-existing verify/X25519 surface, and it must all work through
## `import sello` alone -- no reaching into `sello/signing` or
## `sello/ed25519` directly. The submodule-level tests (test_signing.nim,
## test_ed25519.nim) own the actual behavioral coverage; this file's only
## job is to catch a facade export that goes missing or gets misspelled.

import std/[unittest, options]
import sello

suite "facade - public surface (sello.nim re-exports)":
  test "keypair() / sign / verify round trip entirely through the facade":
    let kp = keypair()
    let sig = kp.sign("facade smoke test")
    check verify(sig, "facade smoke test", kp.public)

  test "keypair(seed) via toSeed is deterministic":
    let seedBytes = default(array[32, byte])
    let kp1 = keypair(toSeed(seedBytes))
    let kp2 = keypair(toSeed(seedBytes))
    check kp1.public == kp2.public

  test "wipe(kp: var Keypair) is reachable through the facade (RFC-001 ledger finding 16)":
    ## Confirms both halves of the contract: the secret half zeroes (via
    ## re-deriving through the now-zero seed, same technique as the
    ## Seed-wipe check just below) and the public half survives untouched.
    var kp = keypair()
    let publicBefore = kp.public
    wipe(kp)
    check kp.public == publicBefore
    let zeroKp = keypair(toSeed(default(array[32, byte])))
    check keypair(kp.seed()).public == zeroKp.public

  test "seed() / wipe() are reachable through the facade":
    ## Confirms wipe zeroed `s` by re-deriving through it, rather than via
    ## Seed's `==` -- the facade deliberately does not re-export `==`
    ## (documented in sello/signing as vartime, tests/tooling only).
    let kp = keypair()
    var s = kp.seed()
    wipe(s)
    let zeroKp = keypair(toSeed(default(array[32, byte])))
    check keypair(s).public == zeroKp.public

  test "openArray[byte] overload is reachable through the facade":
    let kp = keypair()
    let msg = @[0x01'u8, 0x02, 0x03]
    check verify(kp.sign(msg), msg, kp.public)

  test "toPublicKey / toSignature / toBytes are reachable through the facade":
    let kp = keypair()
    let sig = kp.sign("nominal types")
    let pk2 = toPublicKey(toBytes(kp.public))
    let sig2 = toSignature(toBytes(sig))
    check verify(sig2, "nominal types", pk2)

  test "toX25519Public / toBytes are reachable through the facade (RFC-001 finding 26)":
    let raw = [0x0a'u8, 0x0b, 0x0c, 0x0d, 0, 0, 0, 0, 0, 0, 0, 0,
               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    let pub = toX25519Public(raw)
    check toBytes(pub) == raw

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

  test "X25519EphemeralSecret / x25519EphemeralSecret are reachable through the facade (static/ephemeral split)":
    var eph = x25519EphemeralSecret()
    let pub = x25519Base(eph)
    check toBytes(pub) != default(array[32, byte])
    let shared = x25519(move(eph), x25519Base(x25519EphemeralSecret()))
    check shared.isSome

  test "wipe(var X25519EphemeralSecret) is reachable through the facade":
    var eph = x25519EphemeralSecret()
    wipe(eph)
    let probe = cast[ptr array[32, byte]](addr eph)
    check probe[] == default(array[32, byte])

  test "wipe(X25519StaticSecret) / wipe(X25519Shared) are reachable through the facade":
    var secret = x25519StaticSecret()
    wipe(secret)
    check toBytes(secret) == default(array[32, byte])

    let peer = x25519Base(x25519StaticSecret())
    var shared = x25519(x25519StaticSecret(), peer).get
    wipe(shared)
    check toBytes(shared) == default(array[32, byte])

suite "facade - nominal typing (RFC-001 finding 9, compile-time)":
  test "a bare array[32, byte] is not implicitly usable as a PublicKey":
    check(not compiles(block:
      let raw = default(array[32, byte])
      let sig = default(Signature)
      discard verify(sig, "msg", raw)
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
      discard verify(sig, "msg", pub)
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
