## signing.nim: Seed/Keypair types, lifecycle, and RFC 8032 §5.1.5 keygen
## (RFC-001 slice 5).
##
## Keygen vectors: RFC 8032 §7.1 TEST 1, 2, 3, and TEST-1024 (seed ->
## public key only; the signatures themselves land with slices 6-7).

import std/[unittest, osproc, os, strutils]
import sello/signing
import sello/ed25519  # PublicKey type, for the vector tables below

const
  # RFC 8032 §7.1 TEST 1
  tv1_sk: array[32, byte] = [
    0x9d'u8, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
  ]
  tv1_pk: PublicKey = [
    0xd7'u8, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
  ]

  # RFC 8032 §7.1 TEST 2
  tv2_sk: array[32, byte] = [
    0x4c'u8, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda,
    0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24,
    0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb
  ]
  tv2_pk: PublicKey = [
    0x3d'u8, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a,
    0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
    0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c,
    0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c
  ]

  # RFC 8032 §7.1 TEST 3
  tv3_sk: array[32, byte] = [
    0xc5'u8, 0xaa, 0x8d, 0xf4, 0x3f, 0x9f, 0x83, 0x7b,
    0xed, 0xb7, 0x44, 0x2f, 0x31, 0xdc, 0xb7, 0xb1,
    0x66, 0xd3, 0x85, 0x35, 0x07, 0x6f, 0x09, 0x4b,
    0x85, 0xce, 0x3a, 0x2e, 0x0b, 0x44, 0x58, 0xf7
  ]
  tv3_pk: PublicKey = [
    0xfc'u8, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3,
    0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30, 0xf0, 0x58,
    0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x03, 0xac,
    0x5d, 0xeb, 0x91, 0x15, 0x48, 0x90, 0x80, 0x25
  ]

  # RFC 8032 §7.1 TEST-1024 (the 1023-byte-message vector; only the
  # seed/public-key half is needed until slices 6-7 add the signature).
  tv1024_sk: array[32, byte] = [
    0xf5'u8, 0xe5, 0x76, 0x7c, 0xf1, 0x53, 0x31, 0x95,
    0x17, 0x63, 0x0f, 0x22, 0x68, 0x76, 0xb8, 0x6c,
    0x81, 0x60, 0xcc, 0x58, 0x3b, 0xc0, 0x13, 0x74,
    0x4c, 0x6b, 0xf2, 0x55, 0xf5, 0xcc, 0x0e, 0xe5
  ]
  tv1024_pk: PublicKey = [
    0x27'u8, 0x81, 0x17, 0xfc, 0x14, 0x4c, 0x72, 0x34,
    0x0f, 0x67, 0xd0, 0xf2, 0x31, 0x6e, 0x83, 0x86,
    0xce, 0xff, 0xbf, 0x2b, 0x24, 0x28, 0xc9, 0xc5,
    0x1f, 0xef, 0x7c, 0x59, 0x7f, 0x1d, 0x42, 0x6e
  ]

suite "keypair(seed) - RFC 8032 keygen vectors":
  test "TEST 1: seed derives the expected public key":
    check keypair(toSeed(tv1_sk)).public == tv1_pk

  test "TEST 2: seed derives the expected public key":
    check keypair(toSeed(tv2_sk)).public == tv2_pk

  test "TEST 3: seed derives the expected public key":
    check keypair(toSeed(tv3_sk)).public == tv3_pk

  test "TEST-1024: seed derives the expected public key":
    check keypair(toSeed(tv1024_sk)).public == tv1024_pk

suite "keypair(seed) - invariant":
  test "kp.public == derive(kp.seed): re-deriving from the returned seed matches":
    let kp = keypair(toSeed(tv1_sk))
    let reseeded = kp.seed()
    check keypair(reseeded).public == kp.public

suite "Seed lifecycle":
  test "wipe(seed) zeroes the underlying bytes":
    var s = toSeed(tv1_sk)
    wipe(s)
    check s == toSeed(default(array[32, byte]))

  test "different seeds compare unequal, equal seeds compare equal":
    let a = toSeed(tv1_sk)
    let b = toSeed(tv2_sk)
    let aAgain = toSeed(tv1_sk)
    check a != b
    check a == aAgain

suite "keypair() - fresh randomness":
  test "two calls produce different seeds":
    let kp1 = keypair()
    let kp2 = keypair()
    check kp1.seed() != kp2.seed()

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
