## tests/unit/test_ct.nim — sello/private/ct.wipe (RFC-001 slice 8).
##
## Unit-level coverage for the shared secret-wipe primitive itself, in
## addition to its integration call sites (backend.nim, x25519.nim,
## signing.nim) and the destructor smoke tests in test_signing.nim.

import std/unittest
import sello/private/ct
import sello/private/sha512

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

  test "zeroes a stack-only Sha512Context object (in-house SHA-512, RFC-006 slice 3)":
    # RFC-006 slice 3: this used to check nimcrypto's `sha512` context
    # field-by-field (state/buffer/length); that type is gone from the
    # dependency tree entirely. `Sha512Context`'s fields are private (see
    # `private/sha512.nim`'s own doc comment), so a foreign-module
    # field-by-field check is not available here -- a whole-object raw byte
    # scan is the only shape compatible with that, and it is strictly
    # stronger than the old field-by-field check besides (it also catches
    # any struct padding a field-by-field check would miss).
    var ctx: Sha512Context
    ctx.init()
    ctx.update(@[0x61'u8, 0x62, 0x63])
    var digest: array[64, byte]
    ctx.finish(digest)
    # After finish(), the context's internal state/buffer/length are still
    # populated (finish() does not clear them) -- exactly the residue this
    # wipe call site exists to erase.
    ct.wipe(ctx)
    let bytes = cast[ptr UncheckedArray[byte]](addr ctx)
    var allZero = true
    for i in 0 ..< sizeof(Sha512Context):
      if bytes[i] != 0'u8: allZero = false
    check allZero
