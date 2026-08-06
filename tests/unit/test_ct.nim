## tests/unit/test_ct.nim — sello/private/ct.wipe (RFC-001 slice 8).
##
## Unit-level coverage for the shared secret-wipe primitive itself, in
## addition to its integration call sites (backend.nim, x25519.nim,
## signing.nim) and the destructor smoke tests in test_signing.nim.

import std/unittest
import sello/private/ct
import nimcrypto/sha2

suite "ct.wipe":
  test "zeroes a 32-byte array":
    var a: array[32, byte]
    for i in 0 ..< 32: a[i] = byte(i + 1)
    ct.wipe(a)
    check a == default(array[32, byte])

  test "zeroes a 64-byte array":
    var a: array[64, byte]
    for i in 0 ..< 64: a[i] = byte(i + 1)
    ct.wipe(a)
    check a == default(array[64, byte])

  test "zeroes every byte, not just a prefix (boundary check)":
    var a: array[32, byte]
    a[31] = 0xff
    ct.wipe(a)
    check a[31] == 0

  test "is a no-op on an already-zero array":
    var a: array[32, byte]
    ct.wipe(a)
    check a == default(array[32, byte])

  test "zeroes a stack-only Sha2Context-shaped object (nimcrypto sha512)":
    var sha: sha512
    sha.init()
    sha.update(@[0x61'u8, 0x62, 0x63])
    var digest: array[64, byte]
    sha.finish(digest)
    # After finish(), the context's internal state/buffer/length are still
    # populated (finish() does not clear them) -- exactly the residue this
    # wipe call site exists to erase.
    ct.wipe(sha)
    var allZero = true
    for s in sha.state:
      if s != 0'u64: allZero = false
    for b in sha.buffer:
      if b != 0'u8: allZero = false
    if sha.length != 0'u64: allZero = false
    check allZero
