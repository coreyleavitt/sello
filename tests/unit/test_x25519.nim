import std/[unittest, options, strutils, osproc, os]
import sello/x25519
import sello/types  # generic array wipe (round-2 finding 28 -- see below)

proc fromHex(s: string): array[32, byte] =
  doAssert s.len == 64
  for i in 0 ..< 32:
    result[i] = byte(parseHexInt(s[2 * i .. 2 * i + 1]))

proc toHex(bytes: array[32, byte]): string =
  for b in bytes: result.add b.toHex(2).toLowerAscii

suite "X25519 - RFC 7748 test vectors":
  ## Constructed through the role-typed API (RFC-001 ledger #29 revisited:
  ## `X25519StaticSecret`/`X25519Public`/`X25519Shared` replace `X25519Key`).
  test "5.2 vector 1":
    let k = toX25519StaticSecret(fromHex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"))
    let u = toX25519Public(fromHex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"))
    let r = x25519(k, u)
    check r.isSome
    check toBytes(r.get).toHex == "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"

  test "5.2 vector 2":
    let k = toX25519StaticSecret(fromHex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"))
    let u = toX25519Public(fromHex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"))
    let r = x25519(k, u)
    check r.isSome
    check toBytes(r.get).toHex == "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"

  test "5.2 iterated ladder: 1 and 1000 iterations":
    ## `k`/`u` here play a generic scalar/u-coordinate role, not a real
    ## secret/peer-public pairing (the RFC's own iterated-ladder construction
    ## feeds each output back in as both roles) -- tracked as raw bytes
    ## between iterations, wrapped into the role types only for each call.
    var k = toBytes(X25519BasePoint)
    var u = toBytes(X25519BasePoint)
    for i in 1 .. 1000:
      let r = toBytes(x25519(toX25519StaticSecret(k), toX25519Public(u)).get)
      u = k
      k = r
      if i == 1:
        check k.toHex == "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"
    check k.toHex == "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"

  test "6.1 Diffie-Hellman":
    let aliceSk = toX25519StaticSecret(fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
    let bobSk   = toX25519StaticSecret(fromHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))

    let alicePk = x25519Base(aliceSk)
    let bobPk   = x25519Base(bobSk)
    check toBytes(alicePk).toHex == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    check toBytes(bobPk).toHex   == "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"

    let sharedA = x25519(aliceSk, bobPk)
    let sharedB = x25519(bobSk, alicePk)
    check sharedA.isSome and sharedB.isSome
    check toBytes(sharedA.get) == toBytes(sharedB.get)
    check toBytes(sharedA.get).toHex == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

  test "rejects small-order peer point (zero shared secret)":
    let zero = toX25519Public(default(array[32, byte]))  # u = 0, order 1... produces 0
    let k = toX25519StaticSecret(fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
    check x25519(k, zero).isNone
    var oneArr: array[32, byte]
    oneArr[0] = 1                       # u = 1, order-4 point
    check x25519(k, toX25519Public(oneArr)).isNone

suite "X25519 - three-role API (RFC-001 ledger #29 revisited)":
  ## The role-typed constructors/wipe overloads and their RFC-vector
  ## agreement are exercised above and in "secret hygiene" below. This
  ## suite covers the one behavior with no equivalent in the old
  ## `X25519Key`-based suite: sourcing a fresh secret from the OS CSPRNG.
  test "x25519StaticSecret() generates a working secret (roundtrip DH with a second generated secret)":
    let a = x25519StaticSecret()
    let b = x25519StaticSecret()
    let aPub = x25519Base(a)
    let bPub = x25519Base(b)
    let sharedA = x25519(a, bPub)
    let sharedB = x25519(b, aPub)
    check sharedA.isSome and sharedB.isSome
    check toBytes(sharedA.get) == toBytes(sharedB.get)

suite "X25519 - secret hygiene (X25519StaticSecret/X25519Shared wipe)":
  ## Same probe-pattern methodology as test_signing.nim's Seed destructor
  ## suite: a raw pointer captured before the wipe, memory re-read after.
  ## X25519StaticSecret/X25519Shared are one-field objects (same representation
  ## as Seed and for the same reason -- see x25519.nim's module doc
  ## comment), so a pointer to the object aliases its sole `bytes` field.
  const tv = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"

  test "=destroy wipes X25519StaticSecret's memory at scope exit":
    var probe: ptr array[32, byte]
    block:
      var s = toX25519StaticSecret(fromHex(tv))
      probe = cast[ptr array[32, byte]](addr s)
      check probe[] == fromHex(tv) # sanity: the probe aliases the real bytes
    check probe[] == default(array[32, byte])

  test "a COPIED X25519StaticSecret also wipes independently at its own scope exit":
    var probeCopy: ptr array[32, byte]
    let original = toX25519StaticSecret(fromHex(tv))
    block:
      var copy = original
      probeCopy = cast[ptr array[32, byte]](addr copy)
      check probeCopy[] == fromHex(tv) # sanity: the copy holds the same bytes
    check probeCopy[] == default(array[32, byte])
    check toBytes(original) == fromHex(tv) # original unaffected by the copy's wipe

  test "wipe(var X25519StaticSecret) zeroes the underlying bytes in place":
    var s = toX25519StaticSecret(fromHex(tv))
    let probe = cast[ptr array[32, byte]](addr s)
    doAssert probe[] != default(array[32, byte]) # sanity: nonzero before wipe
    wipe(s)
    check probe[] == default(array[32, byte])

  test "=destroy wipes X25519Shared's memory at scope exit":
    let secret = toX25519StaticSecret(fromHex(tv))
    let peer = toX25519Public(fromHex(
      "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))
    var probe: ptr array[32, byte]
    block:
      var sh = x25519(secret, peer).get
      probe = cast[ptr array[32, byte]](addr sh)
      check probe[] != default(array[32, byte]) # sanity: nonzero before scope exit
    check probe[] == default(array[32, byte])

  test "a COPIED X25519Shared also wipes independently at its own scope exit":
    let secret = toX25519StaticSecret(fromHex(tv))
    let peer = toX25519Public(fromHex(
      "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))
    let original = x25519(secret, peer).get
    var probeCopy: ptr array[32, byte]
    block:
      var copy = original
      probeCopy = cast[ptr array[32, byte]](addr copy)
      check probeCopy[] == toBytes(original) # sanity
    check probeCopy[] == default(array[32, byte])
    check toBytes(original) != default(array[32, byte]) # original unaffected

  test "wipe(var X25519Shared) zeroes the underlying bytes in place":
    let secret = toX25519StaticSecret(fromHex(tv))
    let peer = toX25519Public(fromHex(
      "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))
    var sh = x25519(secret, peer).get
    let probe = cast[ptr array[32, byte]](addr sh)
    doAssert probe[] != default(array[32, byte]) # sanity: nonzero before wipe
    wipe(sh)
    check probe[] == default(array[32, byte])

suite "X25519 - ephemeral secret (static/ephemeral split)":
  ## `X25519EphemeralSecret` is the consume-on-use counterpart to
  ## `X25519StaticSecret` (x25519-dalek's `EphemeralSecret`/`StaticSecret`
  ## vocabulary, in sello's own naming): freshness-by-construction (no
  ## from-bytes constructor), unpersistable (no `toBytes`), and single-use
  ## by construction (move-only, `x25519` takes it by `sink`). Tracer
  ## bullet first: generation + non-consuming public-key derivation.
  test "x25519EphemeralSecret() generates a usable secret; x25519Base derives its public key":
    let eph = x25519EphemeralSecret()
    let pub = x25519Base(eph)
    check toBytes(pub) != default(array[32, byte])

  test "ephemeral-vs-static handshake agrees in both directions":
    ## The ephemeral side sends its public before consuming the secret in
    ## `x25519` (x25519Base is non-consuming, so this ordering compiles);
    ## the static side's secret is untouched by any of this (X25519StaticSecret
    ## stays copyable/reusable).
    ##
    ## `move(eph)` at the consuming call: empirically required whenever
    ## `x25519Base` (or ANY other reference to `eph`) appears earlier in the
    ## same scope -- see the module doc comment on `x25519(sink
    ## X25519EphemeralSecret, ...)` for the full writeup. Nim's sink-argument
    ## "is this the last read" inference is a simple per-symbol occurrence
    ## count, not an escape analysis, so an earlier borrow (or even a bare
    ## `addr`/field read, confirmed by isolated probes) makes the compiler
    ## require a copy at the LATER sink call unless the caller explicitly
    ## asserts the move is safe via `system.move`.
    let staticSecret = toX25519StaticSecret(fromHex(
      "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
    let staticPublic = x25519Base(staticSecret)

    var eph = x25519EphemeralSecret()
    let ephPublic = x25519Base(eph)              # borrow -- eph still usable below

    let sharedFromEphSide = x25519(move(eph), staticPublic)  # consumes eph
    let sharedFromStaticSide = x25519(staticSecret, ephPublic)
    check sharedFromEphSide.isSome and sharedFromStaticSide.isSome
    check toBytes(sharedFromEphSide.get) == toBytes(sharedFromStaticSide.get)

  test "ephemeral-vs-ephemeral handshake agrees in both directions":
    var ephA = x25519EphemeralSecret()
    var ephB = x25519EphemeralSecret()
    let pubA = x25519Base(ephA)
    let pubB = x25519Base(ephB)
    let sharedA = x25519(move(ephA), pubB)
    let sharedB = x25519(move(ephB), pubA)
    check sharedA.isSome and sharedB.isSome
    check toBytes(sharedA.get) == toBytes(sharedB.get)

suite "X25519 - ephemeral single-use (compile-time, subprocess-verified)":
  ## Neither `compiles()` nor `nim check` can see either violation below --
  ## both are raised by the `injectdestructors` pass, which runs later in
  ## the pipeline than either reaches (established precedent:
  ## `test_signing.nim`'s `Keypair` copy check via
  ## `fixtures/reject_keypair_copy.nim`). Same subprocess-`nim c`
  ## methodology here for both of `X25519EphemeralSecret`'s ownership
  ## guarantees.
  test "reusing a consumed X25519EphemeralSecret is a compile error (subprocess compile)":
    let fixture = currentSourcePath().parentDir / "fixtures" / "reject_ephemeral_reuse.nim"
    let repoRoot = currentSourcePath().parentDir.parentDir.parentDir
    let cmd = "nim c --hints:off --nimcache:" &
      (repoRoot / "build" / "nimcache_reject_ephemeral_reuse") & " " & fixture
    let (output, exitCode) = execCmdEx(cmd, workingDir = repoRoot)
    check exitCode != 0
    check "=copy" in output

  test "copying an X25519EphemeralSecret is a compile error (subprocess compile)":
    let fixture = currentSourcePath().parentDir / "fixtures" / "reject_ephemeral_copy.nim"
    let repoRoot = currentSourcePath().parentDir.parentDir.parentDir
    let cmd = "nim c --hints:off --nimcache:" &
      (repoRoot / "build" / "nimcache_reject_ephemeral_copy") & " " & fixture
    let (output, exitCode) = execCmdEx(cmd, workingDir = repoRoot)
    check exitCode != 0
    check "=copy" in output

  test "a single-use ephemeral consumes cleanly":
    ## `x25519EphemeralSecret.reject_ephemeral_reuse.nim` (this file's own
    ## negative fixture) is the actual proof that a genuinely sole,
    ## un-annotated `x25519(secret, peer)` (no `move()`) compiles via
    ## ordinary last-use inference at plain top-level scope -- its own
    ## FIRST `x25519` call is exactly that shape, and only the SECOND
    ## (the reuse) is rejected. This test cannot demonstrate the same
    ## no-`move()` claim directly: `unittest`'s `test` template wraps every
    ## body in an implicit `try`/`finally` for its own status bookkeeping,
    ## and empirically (isolated scratch probe, confirmed independently of
    ## sello's own types) a `try` block's implicit exception-edge destructor
    ## call means even a SOLE sink-consuming use inside `test: ...` needs
    ## explicit `move()` too -- the compiler must account for the
    ## exceptional control-flow edge where the variable's own destructor
    ## would run instead of the sink transfer. `var`, not `let`, since
    ## `move` requires a `var T`.
    var eph = x25519EphemeralSecret()
    let peer = x25519Base(x25519EphemeralSecret())
    let shared = x25519(move(eph), peer)
    check shared.isSome

  test "x25519Base-then-x25519 sequence compiles (base is not consumption)":
    ## Regression pin for the empirical finding above: this exact sequence
    ## is the one that originally required discovering the `move()`
    ## requirement (RED: plain `x25519(eph, peer)` failed to compile with
    ## the `=copy`/`=dup` error after an earlier `x25519Base(eph)` call).
    var eph = x25519EphemeralSecret()
    let pub = x25519Base(eph)             # borrow, does not consume
    let shared = x25519(move(eph), pub)   # explicit move required (see above)
    check shared.isSome

suite "X25519 - ephemeral secret hygiene (probe pattern)":
  ## Same probe-pattern methodology as the `X25519StaticSecret`/`X25519Shared`
  ## hygiene suite above and `test_signing.nim`'s `Seed` destructor suite:
  ## a raw pointer captured before the event of interest, memory re-read
  ## after. `X25519EphemeralSecret` is a one-field object (same
  ## representation as the other secret-holding types), so a pointer to
  ## the object aliases its sole `bytes` field.
  test "after a consuming x25519 call, the caller's ephemeral memory reads all-zero":
    ## This is the observable half of "the ephemeral is consumed": after
    ## `move(eph)` is handed to `x25519` and the call returns, `eph`'s own
    ## storage reads as all-zero. Confirmed (isolated scratch probe, a
    ## minimal type whose `=destroy` only echoes and never zeroes anything)
    ## that this specific zeroing is Nim's own compiler-generated
    ## `=wasMoved` reset of the moved-from SOURCE, not `ct.wipe` -- the
    ## audited volatile wipe fires separately, on the CALLEE's own copy,
    ## via `X25519EphemeralSecret`'s `=destroy` when the sink parameter
    ## goes out of scope at the end of `x25519` (see that scratch probe's
    ## write-up in this batch's report: the destroy fired inside the
    ## callee, on the real un-zeroed bytes, before this source-side
    ## wasMoved reset became observable here).
    var eph = x25519EphemeralSecret()
    let peer = x25519Base(x25519EphemeralSecret())
    let probe = cast[ptr array[32, byte]](addr eph)
    doAssert probe[] != default(array[32, byte]) # sanity: nonzero before the move
    let shared = x25519(move(eph), peer)
    check shared.isSome
    check probe[] == default(array[32, byte])

  test "=destroy wipes an unused X25519EphemeralSecret at scope exit":
    ## A generated-but-never-consumed ephemeral (e.g. the caller aborted
    ## before completing the exchange) still wipes automatically -- the
    ## same guarantee every other secret-holding type in this codebase
    ## carries, unaffected by the move-only/single-use machinery above.
    var probe: ptr array[32, byte]
    block:
      var eph = x25519EphemeralSecret()
      probe = cast[ptr array[32, byte]](addr eph)
      doAssert probe[] != default(array[32, byte]) # sanity: nonzero before scope exit
    check probe[] == default(array[32, byte])

  test "wipe(var X25519EphemeralSecret) zeroes the underlying bytes in place":
    var eph = x25519EphemeralSecret()
    let probe = cast[ptr array[32, byte]](addr eph)
    doAssert probe[] != default(array[32, byte]) # sanity: nonzero before wipe
    wipe(eph)
    check probe[] == default(array[32, byte])

suite "X25519 - generic array wipe (sello/types, RFC-001 finding 11/28)":
  ## Before finding 11, `private/ct.wipe` -- the one audited volatile-store
  ## primitive -- was reachable only by importing a `private/` module
  ## directly; `sello.wipe` covered `Seed` only. This probe-pattern test
  ## (same methodology as test_signing.nim's Seed destructor suite: a raw
  ## pointer captured before the wipe, memory re-read after) confirms the
  ## generic `array[32, byte]` overload (moved to `sello/types` by round-2
  ## finding 28 -- it wipes any 32-byte secret, not just X25519 material)
  ## actually reaches it. The `X25519StaticSecret`/`X25519Shared`-typed overloads
  ## are covered by the "secret hygiene" suite above.
  test "wipe(var array[32, byte]) [sello/types] zeroes the array in place":
    var raw = fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    let probe = addr raw
    doAssert probe[] != default(array[32, byte]) # sanity: nonzero before wipe
    wipe(raw)
    check probe[] == default(array[32, byte])
