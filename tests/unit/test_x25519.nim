import std/[unittest, options, strutils]
import sello/x25519
import sello/types  # generic array wipe (round-2 finding 28 -- see below)

proc fromHex(s: string): X25519Key =
  doAssert s.len == 64
  var bytes: array[32, byte]
  for i in 0 ..< 32:
    bytes[i] = byte(parseHexInt(s[2 * i .. 2 * i + 1]))
  X25519Key(bytes)

proc toHex(k: X25519Key): string =
  for b in array[32, byte](k): result.add b.toHex(2).toLowerAscii

suite "X25519 - RFC 7748 test vectors":
  test "5.2 vector 1":
    let k = fromHex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    let u = fromHex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
    let r = x25519(k, u)
    check r.isSome
    check r.get.toHex == "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"

  test "5.2 vector 2":
    let k = fromHex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
    let u = fromHex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")
    let r = x25519(k, u)
    check r.isSome
    check r.get.toHex == "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"

  test "5.2 iterated ladder: 1 and 1000 iterations":
    var k = X25519BasePoint
    var u = X25519BasePoint
    for i in 1 .. 1000:
      let r = x25519(k, u).get
      u = k
      k = r
      if i == 1:
        check k.toHex == "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"
    check k.toHex == "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"

  test "6.1 Diffie-Hellman":
    let aliceSk = fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    let bobSk   = fromHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")

    let alicePk = x25519Base(aliceSk)
    let bobPk   = x25519Base(bobSk)
    check alicePk.toHex == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    check bobPk.toHex   == "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"

    let sharedA = x25519(aliceSk, bobPk)
    let sharedB = x25519(bobSk, alicePk)
    check sharedA.isSome and sharedB.isSome
    check sharedA.get == sharedB.get
    check sharedA.get.toHex == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

  test "rejects small-order peer point (zero shared secret)":
    let zero = X25519Key(default(array[32, byte]))  # u = 0, order 1... produces 0
    let k = fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    check x25519(k, zero).isNone
    var oneArr: array[32, byte]
    oneArr[0] = 1                       # u = 1, order-4 point
    check x25519(k, X25519Key(oneArr)).isNone

suite "X25519 - public wipe (RFC-001 finding 11)":
  ## Before this, `private/ct.wipe` -- the one audited volatile-store
  ## primitive -- was reachable only by importing a `private/` module
  ## directly; `sello.wipe` covered `Seed` only. These probe-pattern tests
  ## (same methodology as test_signing.nim's Seed destructor suite: a raw
  ## pointer captured before the wipe, memory re-read after) confirm both
  ## public overloads actually reach it, for a caller holding X25519
  ## secret material outside of a Keypair/Seed.
  ##
  ## Round-2 finding 28: the `array[32, byte]` overload exercised by the
  ## first test below now lives in `sello/types` (it wipes any 32-byte
  ## secret, not just X25519 material), not in `sello/x25519` alongside
  ## the `X25519Key`-typed overload the second test covers. Both stay in
  ## this suite because both are exactly what a caller peeling an
  ## `X25519Key` down to raw bytes (or not) reaches for.
  test "wipe(var array[32, byte]) [sello/types] zeroes the array in place":
    var secret = fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    var raw = array[32, byte](secret)
    let probe = addr raw
    doAssert probe[] != default(array[32, byte]) # sanity: nonzero before wipe
    wipe(raw)
    check probe[] == default(array[32, byte])

  test "wipe(var X25519Key) zeroes the underlying bytes in place":
    var secret = fromHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    let probe = cast[ptr array[32, byte]](addr secret)
    doAssert probe[] != default(array[32, byte]) # sanity: nonzero before wipe
    wipe(secret)
    check probe[] == default(array[32, byte])
    check secret == X25519Key(default(array[32, byte]))
