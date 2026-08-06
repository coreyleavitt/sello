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

  test "toX25519Key / toBytes are reachable through the facade (RFC-001 finding 26)":
    let raw = [0x0a'u8, 0x0b, 0x0c, 0x0d, 0, 0, 0, 0, 0, 0, 0, 0,
               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    let key = toX25519Key(raw)
    check toBytes(key) == raw

  test "X25519Key / x25519 / x25519Base / x25519.wipe are reachable through the facade":
    let aliceSk = X25519Key([0x01'u8, 0x02, 0x03, 0x04, 0, 0, 0, 0, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    var bobSk = X25519Key([0x05'u8, 0x06, 0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    let alicePk = x25519Base(aliceSk)
    let bobPk = x25519Base(bobSk)
    let sharedA = x25519(aliceSk, bobPk)
    let sharedB = x25519(bobSk, alicePk)
    check sharedA.isSome and sharedB.isSome
    check sharedA.get == sharedB.get
    wipe(bobSk)
    check bobSk == X25519Key(default(array[32, byte]))

suite "facade - nominal typing (RFC-001 finding 9, compile-time)":
  test "an X25519Key is not implicitly usable as an ed25519 PublicKey":
    check(not compiles(block:
      let x = X25519Key(default(array[32, byte]))
      let sig = default(Signature)
      discard verify(sig, "msg", x) # PublicKey parameter, X25519Key argument
    ))

  test "an ed25519 PublicKey is not implicitly usable as an X25519Key":
    check(not compiles(block:
      let pk = toPublicKey(default(array[32, byte]))
      discard x25519Base(pk) # X25519Key parameter, PublicKey argument
    ))

  test "a bare array[32, byte] is not implicitly usable as a PublicKey":
    check(not compiles(block:
      let raw = default(array[32, byte])
      let sig = default(Signature)
      discard verify(sig, "msg", raw)
    ))
