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

  test "zeroes an array[16, uint64] via the word-granular overload":
    # RFC-006 slice-1b amendment: coverage for the word-granular
    # `wipe[N](var array[N, uint64])` sibling overload (private/ct.nim),
    # added when sha512.compress's rolling 16-word message schedule
    # replaced the fully-materialized 80-word one to cut wipe cost. This
    # is refactor-under-green, not a REDable behavior change: the
    # pre-existing byte-generic `wipe[T]` already zeroed this exact shape
    # correctly (it wipes by raw byte reinterpretation regardless of
    # element type) -- the new overload changes wipe COST (word stores
    # instead of byte stores), not the observable zeroing behavior this
    # test checks.
    var w: array[16, uint64]
    for i in 0 ..< 16: w[i] = 0xDEAD_BEEF_0000_0000'u64 + uint64(i)
    ct.wipe(w)
    check w == default(array[16, uint64])

  test "zeroes an array[8, uint64] via the word-granular overload":
    var v: array[8, uint64]
    for i in 0 ..< 8: v[i] = 0xFFFF_FFFF_FFFF_FFFF'u64
    ct.wipe(v)
    check v == default(array[8, uint64])

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
