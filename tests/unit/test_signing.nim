## signing.nim: Seed/Keypair types, lifecycle, and RFC 8032 §5.1.5 keygen
## (RFC-001 slice 5).
##
## Keygen vectors: RFC 8032 §7.1 TEST 1, 2, 3, and TEST-1024 (seed ->
## public key only; the signatures themselves land with slices 6-7).

import std/[unittest, osproc, os, strutils, json]
import sello/signing
import sello/ed25519  # PublicKey/Signature types, and verify() for roundtrips

# RFC 8032 §7.1 TEST-1024: the 1023-byte-message vector, sourced by scripted
# extraction (never hand-retyped) from a verbatim paste of the RFC text --
# see tests/vectors/gen_test1024_vector.py for the extraction and the
# transcription self-checks (length, endpoint bytes, and cross-check
# against the tv1024_sk/tv1024_pk constants above) applied when
# tests/vectors/test1024_vector.json was generated. It is the only official
# vector long enough to exercise SHA-512's multi-block compression path --
# exactly where a fresh signer implementation tends to break.
const rawTest1024Vector = staticRead("../vectors/test1024_vector.json")

proc hexToBytes(s: string): seq[byte] =
  doAssert s.len mod 2 == 0
  result = newSeq[byte](s.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(s[2 * i .. 2 * i + 1]))

proc hexToArray64(s: string): array[64, byte] =
  let bytes = hexToBytes(s)
  doAssert bytes.len == 64
  for i in 0 ..< 64: result[i] = bytes[i]

const
  # RFC 8032 §7.1 TEST 1
  tv1_sk: array[32, byte] = [
    0x9d'u8, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
  ]
  tv1_pk: PublicKey = toPublicKey([
    0xd7'u8, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
  ])

  # RFC 8032 §7.1 TEST 2
  tv2_sk: array[32, byte] = [
    0x4c'u8, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda,
    0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24,
    0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb
  ]
  tv2_pk: PublicKey = toPublicKey([
    0x3d'u8, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a,
    0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
    0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c,
    0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c
  ])

  # RFC 8032 §7.1 TEST 3
  tv3_sk: array[32, byte] = [
    0xc5'u8, 0xaa, 0x8d, 0xf4, 0x3f, 0x9f, 0x83, 0x7b,
    0xed, 0xb7, 0x44, 0x2f, 0x31, 0xdc, 0xb7, 0xb1,
    0x66, 0xd3, 0x85, 0x35, 0x07, 0x6f, 0x09, 0x4b,
    0x85, 0xce, 0x3a, 0x2e, 0x0b, 0x44, 0x58, 0xf7
  ]
  tv3_pk: PublicKey = toPublicKey([
    0xfc'u8, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3,
    0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30, 0xf0, 0x58,
    0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x03, 0xac,
    0x5d, 0xeb, 0x91, 0x15, 0x48, 0x90, 0x80, 0x25
  ])

  # RFC 8032 §7.1 TEST-1024 seed/public key (the message/signature come
  # from the scripted extraction below -- 1023 bytes is too long to
  # hand-transcribe without risking exactly the transposed-digit bug this
  # vector exists to catch).
  tv1024_sk: array[32, byte] = [
    0xf5'u8, 0xe5, 0x76, 0x7c, 0xf1, 0x53, 0x31, 0x95,
    0x17, 0x63, 0x0f, 0x22, 0x68, 0x76, 0xb8, 0x6c,
    0x81, 0x60, 0xcc, 0x58, 0x3b, 0xc0, 0x13, 0x74,
    0x4c, 0x6b, 0xf2, 0x55, 0xf5, 0xcc, 0x0e, 0xe5
  ]
  tv1024_pk: PublicKey = toPublicKey([
    0x27'u8, 0x81, 0x17, 0xfc, 0x14, 0x4c, 0x72, 0x34,
    0x0f, 0x67, 0xd0, 0xf2, 0x31, 0x6e, 0x83, 0x86,
    0xce, 0xff, 0xbf, 0x2b, 0x24, 0x28, 0xc9, 0xc5,
    0x1f, 0xef, 0x7c, 0x59, 0x7f, 0x1d, 0x42, 0x6e
  ])

let
  tv1024Vector = parseJson(rawTest1024Vector)
  tv1024_msg: seq[byte] = hexToBytes(tv1024Vector["message"].getStr)
  tv1024_sig: Signature = toSignature(hexToArray64(tv1024Vector["signature"].getStr))

  # RFC 8032 §7.1 TEST 1: empty message
  tv1_msg: array[0, byte] = []
  tv1_sig: Signature = toSignature([
    0xe5'u8, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72,
    0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
    0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
    0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
    0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac,
    0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
    0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
    0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b
  ])

  # RFC 8032 §7.1 TEST 2: 1-byte message
  tv2_msg = [0x72'u8]
  tv2_sig: Signature = toSignature([
    0x92'u8, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8,
    0x72, 0x0e, 0x82, 0x0b, 0x5f, 0x64, 0x25, 0x40,
    0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f,
    0xb3, 0x76, 0x22, 0x23, 0xeb, 0xdb, 0x69, 0xda,
    0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99, 0x6e,
    0x45, 0x8f, 0x36, 0x13, 0xd0, 0xf1, 0x1d, 0x8c,
    0x38, 0x7b, 0x2e, 0xae, 0xb4, 0x30, 0x2a, 0xee,
    0xb0, 0x0d, 0x29, 0x16, 0x12, 0xbb, 0x0c, 0x00
  ])

  # RFC 8032 §7.1 TEST 3: 2-byte message
  tv3_msg = [0xaf'u8, 0x82]
  tv3_sig: Signature = toSignature([
    0x62'u8, 0x91, 0xd6, 0x57, 0xde, 0xec, 0x24, 0x02,
    0x48, 0x27, 0xe6, 0x9c, 0x3a, 0xbe, 0x01, 0xa3,
    0x0c, 0xe5, 0x48, 0xa2, 0x84, 0x74, 0x3a, 0x44,
    0x5e, 0x36, 0x80, 0xd7, 0xdb, 0x5a, 0xc3, 0xac,
    0x18, 0xff, 0x9b, 0x53, 0x8d, 0x16, 0xf2, 0x90,
    0xae, 0x67, 0xf7, 0x60, 0x98, 0x4d, 0xc6, 0x59,
    0x4a, 0x7c, 0x15, 0xe9, 0x71, 0x6e, 0xd2, 0x8d,
    0xc0, 0x27, 0xbe, 0xce, 0xea, 0x1e, 0xc4, 0x0a
  ])

suite "keypair(seed) - RFC 8032 keygen vectors":
  test "TEST 1: seed derives the expected public key":
    check keypair(toSeed(tv1_sk)).public == tv1_pk

  test "TEST 2: seed derives the expected public key":
    check keypair(toSeed(tv2_sk)).public == tv2_pk

  test "TEST 3: seed derives the expected public key":
    check keypair(toSeed(tv3_sk)).public == tv3_pk

  test "TEST-1024: seed derives the expected public key":
    check keypair(toSeed(tv1024_sk)).public == tv1024_pk

suite "sign - RFC 8032 §7.1 signature vectors (bit-exact)":
  test "TEST 1: empty message":
    check keypair(toSeed(tv1_sk)).sign(tv1_msg) == tv1_sig

  test "TEST 2: 1-byte message":
    check keypair(toSeed(tv2_sk)).sign(tv2_msg) == tv2_sig

  test "TEST 3: 2-byte message":
    check keypair(toSeed(tv3_sk)).sign(tv3_msg) == tv3_sig

  test "TEST-1024: 1023-byte message (exercises SHA-512's multi-block path)":
    doAssert tv1024_msg.len == 1023  # transcription self-check, belt-and-suspenders
    check keypair(toSeed(tv1024_sk)).sign(tv1024_msg) == tv1024_sig

suite "sign - roundtrip against the pure verifier":
  test "TEST 1: sello's own signature verifies under sello's own verify()":
    let kp = keypair(toSeed(tv1_sk))
    check verify(kp.public, tv1_msg, kp.sign(tv1_msg))

  test "TEST 2: sello's own signature verifies under sello's own verify()":
    let kp = keypair(toSeed(tv2_sk))
    check verify(kp.public, tv2_msg, kp.sign(tv2_msg))

  test "TEST 3: sello's own signature verifies under sello's own verify()":
    let kp = keypair(toSeed(tv3_sk))
    check verify(kp.public, tv3_msg, kp.sign(tv3_msg))

  test "TEST-1024: sello's own signature verifies under sello's own verify()":
    let kp = keypair(toSeed(tv1024_sk))
    check verify(kp.public, tv1024_msg, kp.sign(tv1024_msg))

  test "a tampered message fails verification":
    let kp = keypair(toSeed(tv1_sk))
    let sig = kp.sign(tv2_msg)
    check not verify(kp.public, tv1_msg, sig)

suite "sign - determinism (RFC-001 ledger finding 21a)":
  ## `sign`'s doc comment already states determinism as a contract
  ## ("the same (kp, msg) pair always yields the same signature") but
  ## nothing directly pinned it as a regression until now -- every other
  ## test compares against a fixed RFC vector or a roundtrip, neither of
  ## which would catch a hypothetical accidental source of nonce
  ## randomness (e.g. an errant `keypair()` call site) producing two
  ## different, both-individually-valid signatures for the same input.
  test "signing the same (kp, msg) pair twice yields byte-identical signatures":
    let kp = keypair(toSeed(tv1_sk))
    check kp.sign(tv1_msg) == kp.sign(tv1_msg)

  test "signing the same (kp, msg) pair twice yields byte-identical signatures (nonempty message)":
    let kp = keypair(toSeed(tv3_sk))
    check kp.sign(tv3_msg) == kp.sign(tv3_msg)

suite "sign/verify - SHA-512 block-boundary message lengths (RFC-001 ledger finding 21b)":
  ## SHA-512 pads with a 0x80 byte plus a 16-byte length field, so an
  ## input of N raw bytes fits in exactly one 128-byte block iff N <= 111
  ## (N=112 spills into a second block) -- RFC 8032's own vectors only
  ## exercise a single short message plus TEST-1024's 1023 bytes, so
  ## nothing pins this boundary directly. `signDetached`/`verify` never
  ## hash `msg` alone, though -- they hash a fixed-size prefix (the
  ## 32-byte nonce prefix, or the 64-byte R‖A challenge input) concatenated
  ## with `msg` via multi-part `update()` calls, so the byte offset at
  ## which a REAL call's total input crosses a block boundary is shifted
  ## by that prefix length rather than landing exactly at `msg.len` itself.
  ## Rather than hand-deriving the exact shifted boundary for every call
  ## site, this suite brackets the whole neighborhood -- 55/56, 64, 111/112
  ## (the boundary for a bare SHA-512(msg) call), and 127/128 (one full
  ## block) -- so multi-part hashing at a variety of block-relative offsets
  ## gets exercised regardless of which prefix length applies at a given
  ## call site.
  test "sign/verify roundtrips at every SHA-512 block-boundary length":
    let kp = keypair(toSeed(tv2_sk))
    for length in [55, 56, 64, 111, 112, 127, 128]:
      var msg = newSeq[byte](length)
      for i in 0 ..< length: msg[i] = byte((i * 37 + 11) mod 256)
      let sig = kp.sign(msg)
      check verify(kp.public, msg, sig)
      # Belt-and-suspenders: determinism holds at every boundary length too.
      check kp.sign(msg) == sig

suite "Keypair lifecycle (RFC-001 ledger finding 16)":
  test "wipe(kp) zeroes the secret half; the public key is untouched":
    ## Same probe methodology as `Seed`'s own destructor smoke tests above:
    ## a raw pointer captured before the wipe, re-read after. `Keypair`'s
    ## `seed` field is a `Seed` (itself a one-field object wrapping
    ## `array[32, byte]`), so aliasing `addr kp` as `ptr Seed` at the right
    ## offset would be fragile; instead this reads back through the public
    ## `toSeedBytes(kp)`/`public()` accessors (renamed from `toBytes` by
    ## round-3 finding A7), which is exactly what an external caller of
    ## `wipe(var Keypair)` can observe too.
    var kp = keypair(toSeed(tv1_sk))
    let publicBefore = kp.public
    wipe(kp)
    check kp.public == publicBefore  # untouched -- not secret, not wiped
    check toSeedBytes(kp) == default(array[32, byte])

  test "wipe(kp) does not prevent kp's own =destroy from firing safely at scope exit":
    ## Wiping twice (once explicitly, once via `=destroy` at scope exit)
    ## must not double-free or otherwise misbehave -- `ct.wipe` on an
    ## already-zero array is a defined, harmless no-op.
    block:
      var kp = keypair(toSeed(tv2_sk))
      wipe(kp)
      check toSeedBytes(kp) == default(array[32, byte])
    # No crash / defect on scope exit above is itself the assertion here.

suite "sign/verify - string overload (zero-copy openArray[byte] view)":
  test "sign(kp, string) matches sign(kp, openArray[byte]) for the same bytes":
    let kp = keypair(toSeed(tv1_sk))
    check kp.sign("hello") == kp.sign(@[0x68'u8, 0x65, 0x6c, 0x6c, 0x6f])

  test "sign(kp, string) is deterministic, same as the byte overload":
    let kp = keypair(toSeed(tv3_sk))
    check kp.sign("hi") == kp.sign(@[0x68'u8, 0x69])

  test "sign(kp, \"\") matches sign(kp, empty byte array)":
    let kp = keypair(toSeed(tv1_sk))
    check kp.sign("") == kp.sign(tv1_msg)

  test "verify(pk, string, sig) matches verify(pk, openArray[byte], sig)":
    let kp = keypair(toSeed(tv1_sk))
    let sig = kp.sign("hello")
    check verify(kp.public, "hello", sig)

  test "verify(pk, \"\", sig) matches the empty-message vector":
    check verify(tv1_pk, "", tv1_sig)

  test "string round trip: sign then verify via the string overloads":
    let kp = keypair(toSeed(tv2_sk))
    check verify(kp.public, "round trip", kp.sign("round trip"))

  test "string overload rejects a tampered message":
    let kp = keypair(toSeed(tv1_sk))
    let sig = kp.sign("hello")
    check not verify(kp.public, "goodbye", sig)

suite "keypair(seed) - invariant":
  test "kp.public == derive(kp.seed): re-deriving from toSeedBytes(kp) matches":
    let kp = keypair(toSeed(tv1_sk))
    check keypair(toSeed(toSeedBytes(kp))).public == kp.public

suite "Seed lifecycle":
  test "wipe(seed) zeroes the underlying bytes":
    ## `Seed` has no `==`/`toBytes` of its own (RFC-002 slice 1) -- the
    ## raw-pointer probe pattern (see the destructor smoke tests below)
    ## is how a standalone `Seed`'s bytes get observed from a test.
    var s = toSeed(tv1_sk)
    wipe(s)
    let probe = cast[ptr array[32, byte]](addr s)
    check probe[] == default(array[32, byte])

  test "different seed bytes derive keypairs with different toSeedBytes; equal seed bytes derive equal ones":
    ## `Seed.==` was deleted (RFC-002 slice 1, one principle/one layer with
    ## the X25519 secret family's total absence of `==`) -- compare via
    ## `toSeedBytes(kp)` (renamed from `toBytes` by round-3 finding A7) on a
    ## keypair derived from each seed instead.
    check toSeedBytes(keypair(toSeed(tv1_sk))) != toSeedBytes(keypair(toSeed(tv2_sk)))
    check toSeedBytes(keypair(toSeed(tv1_sk))) == tv1_sk

suite "Seed destructor smoke tests (RFC-001 slice 8)":
  ## `=destroy` is the whole point of `Seed` existing as its own type
  ## rather than a bare `array[32, byte]` -- these tests observe it firing
  ## via a raw pointer captured before destruction, per RFC-001's stated
  ## methodology. Best-effort, explicitly: reading memory through a pointer
  ## whose pointee has gone out of scope is not something the language
  ## guarantees stays untouched, under a managed allocator (ORC) or
  ## otherwise -- it only works here because nothing else runs between the
  ## destructor firing and the check. `Seed` is a one-field object
  ## (`bytes: array[32, byte]`, see the module doc comment for why), so
  ## reinterpreting `addr s` as `ptr array[32, byte]` aliases the exact
  ## same memory as the private `bytes` field without needing access to
  ## it -- deterministic and independent of `Seed`'s field being private.
  test "=destroy wipes the seed's memory at scope exit":
    var probe: ptr array[32, byte]
    block:
      var s = toSeed(tv1_sk)
      probe = cast[ptr array[32, byte]](addr s)
      check probe[] == tv1_sk # sanity: the probe aliases the real bytes
    # `s` is out of scope; `=destroy` must have fired and wiped it in place.
    check probe[] == default(array[32, byte])

  test "reassignment destroys (wipes) the old value, and =destroy still fires on scope exit afterward":
    var probe: ptr array[32, byte]
    block:
      var s = toSeed(tv1_sk)
      probe = cast[ptr array[32, byte]](addr s)
      check probe[] == tv1_sk
      s = toSeed(tv2_sk) # reassignment: the old (tv1_sk) value is torn
                          # down via `=destroy` before the new value lands
                          # in the same storage -- Nim's default `=sink`
                          # for a type with a custom `=destroy` and no
                          # custom `=copy`/`=sink` of its own destroys the
                          # old value first, then blits the new one in, all
                          # within this one statement, so the intermediate
                          # all-zero state is not independently observable
                          # from outside; what IS observable and checked
                          # here is that (a) the new value lands correctly
                          # and (b) `=destroy` is not somehow "used up" by
                          # firing once already -- it fires again, correctly,
                          # for tv2_sk below.
      check probe[] == tv2_sk
    check probe[] == default(array[32, byte])

suite "keypair() - fresh randomness":
  test "two calls produce different seeds":
    let kp1 = keypair()
    let kp2 = keypair()
    check toSeedBytes(kp1) != toSeedBytes(kp2)

  test "two calls produce different public keys":
    let kp1 = keypair()
    let kp2 = keypair()
    check kp1.public != kp2.public

suite "type and ownership safety (compile-time)":
  test "a PublicKey is not implicitly usable as a Seed (own nominal type, not an alias)":
    check(not compiles(block:
      let pk: PublicKey = tv1_pk
      let s: Seed = pk
      discard s
    ))

  test "Keypair cannot be copied — only moved (verified via a subprocess compile)":
    ## Neither `compiles()` nor `nim check` can express this one: both
    ## stop at semantic checking, and the `=copy {.error.}` violation is
    ## only raised by the later `injectdestructors` pass, which runs
    ## during a full `nim c` (confirmed empirically: both a `compiles()`
    ## wrapper and `nim check` on this exact fixture report success even
    ## though the copy is illegal). So this test shells out to a real
    ## `nim c` on tests/unit/fixtures/reject_keypair_copy.nim and asserts
    ## it fails with the expected `=copy` diagnostic — the only faithful
    ## way to pin this guarantee down as a regression test.
    let fixture = currentSourcePath().parentDir / "fixtures" / "reject_keypair_copy.nim"
    let repoRoot = currentSourcePath().parentDir.parentDir.parentDir
    let cmd = "nim c --hints:off --nimcache:" &
      (repoRoot / "build" / "nimcache_reject_keypair_copy") & " " & fixture
    let (output, exitCode) = execCmdEx(cmd, workingDir = repoRoot)
    check exitCode != 0
    check "=copy" in output

  test "Seed cannot be copied — only moved (verified via a subprocess compile, RFC-002 slice 1)":
    ## Same methodology as `Keypair`'s copy check just above --
    ## `tests/unit/fixtures/reject_seed_copy.nim` is deliberately invalid,
    ## and only a real `nim c` (not `compiles()`/`nim check`) surfaces the
    ## `=copy {.error.}` violation, raised by the later
    ## `injectdestructors` pass.
    let fixture = currentSourcePath().parentDir / "fixtures" / "reject_seed_copy.nim"
    let repoRoot = currentSourcePath().parentDir.parentDir.parentDir
    let cmd = "nim c --hints:off --nimcache:" &
      (repoRoot / "build" / "nimcache_reject_seed_copy") & " " & fixture
    let (output, exitCode) = execCmdEx(cmd, workingDir = repoRoot)
    check exitCode != 0
    check "=copy" in output
