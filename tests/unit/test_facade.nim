## Facade regression test (RFC-001 slice 7): `sello.nim` must re-export
## the full signing surface (`Seed`, `Keypair`, `toSeed`, `keypair`,
## `sign` incl. the `string` overload, `wipe`, `public`, `seed`) alongside
## the pre-existing verify/X25519 surface, and it must all work through
## `import sello` alone -- no reaching into `sello/signing` or
## `sello/ed25519` directly. The submodule-level tests (test_signing.nim,
## test_ed25519.nim) own the actual behavioral coverage; this file's only
## job is to catch a facade export that goes missing or gets misspelled.

import std/unittest
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
