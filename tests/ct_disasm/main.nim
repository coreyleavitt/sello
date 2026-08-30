## tests/ct_disasm/main.nim -- RFC-005 slice 23 (A2): the disasm-gate
## probe binary.
##
## Purpose: reference every {.noinline.} disasm-gate root -- the 9
## RFC-enumerated roots (`signDetached`, `derivePublic`, x25519 `ladder`,
## `geScalarmultBase`, `geScalarmultCT`, `ristrettoEncode`, `` `==` ``,
## `feSqrtRatioM1`, sha512 `compress`) plus the pre-existing trio
## (`feCMove`, `feCSwap`, `cmovCached`) -- so every one of the 12 roots
## survives as a real, reachable C symbol in the built binary, at the
## SAME compiler flags `tests/ct/ct_main.nim` uses (`-d:release`, the
## project's standing CT-build register). This file is built by
## `scripts/disasm-gate.sh`, never run for a verdict of its own (unlike
## `ct_main`, which measures timing) -- `scripts/disasm-gate.sh` builds
## it, then locates each root's mangled symbol via the nimcache C and
## disassembles it with objdump. Running it once (this file's own `main`
## body) is still useful: it is real evidence the built binary executes
## end-to-end without crashing, the same posture `build-smoke`'s
## single-deterministic-input check gives the fuzz target.
##
## Module-private roots (`ladder` in x25519.nim, `compress` in
## sha512.nim) cannot be called directly from outside their own module
## (no `*` -- see CLAUDE.md's own x25519.nim/private/sha512.nim entries);
## this file reaches them the same way `ct_main.nim` does, transitively,
## through their module's public entry points (`x25519Base`/`x25519`,
## `sha512`). `feCMove`/`feCSwap`/`cmovCached` are likewise reached
## transitively (through `geScalarmultBase`/`geScalarmultCT`/
## `feSqrtRatioM1`/`x25519Base`'s own internals) rather than called
## directly -- all three are exported (`*`), so a direct call was
## possible, but the transitive path is simpler and already proven live
## by `ct_main.nim`'s own targets; nothing about the disasm gate's
## resolver cares which call path reached a root, only that the built
## binary's C code for it exists and executes.

import std/os
import sello/private/backend
import sello/private/sha512
import sello/field
import sello/scalar
import sello/x25519
import sello/ristretto

proc fixedSeed(tag: byte): array[32, byte] =
  for i in 0 ..< 32: result[i] = byte((int(tag) * 7 + i * 11) mod 256)

proc fixedScalarBytes(tag: byte): array[32, byte] =
  result = fixedSeed(tag)
  clampScalar(result)

var sink: uint64 = 0
template fold(bytes: openArray[byte]) =
  for b in bytes: sink = (sink shl 1) or uint64(b and 1'u8)

proc main() =
  # Root: derivePublic, signDetached (private/backend.nim)
  let seed = fixedSeed(1)
  let pub = derivePublic(seed)
  let msg = "sello disasm-gate probe fixed message"
  let sig = signDetached(seed, pub, msg.toOpenArrayByte(0, msg.len - 1))
  fold(pub)
  fold(sig)

  # Root: geScalarmultBase (scalar.nim) -- also reaches cmovCached.
  let p1 = geScalarmultBase(toSecretScalar(fixedScalarBytes(2)))
  fold(pointEncode(p1))

  # Root: geScalarmultCT (scalar.nim) -- also reaches feCMove/feCSwap.
  let p2 = geScalarmultCT(toSecretScalar(fixedScalarBytes(3)), p1)
  fold(pointEncode(p2))

  # Root: x25519 ladder, reached via x25519Base (x25519.nim).
  let xpk = x25519Base(toX25519StaticSecret(fixedScalarBytes(4)))
  fold(toBytes(xpk))

  # Root: ristrettoEncode, `==` (ristretto.nim) -- ristrettoScalarmult
  # (static-secret overload) also reaches geScalarmultCT/feCMove/feCSwap
  # a second way, and feSqrtRatioM1 via internal decode-shaped helpers.
  let rsecret = toRistrettoStaticSecretWide(block:
    var b: array[64, byte]
    for i in 0 ..< 64: b[i] = byte((i * 13 + 3) mod 256)
    b)
  let rpoint = ristrettoScalarmult(rsecret, RistrettoBasePoint)
  fold(toBytes(ristrettoEncode(rpoint)))
  let sameVerdict = (rpoint == rpoint)
  let diffVerdict = (rpoint == RistrettoBasePoint)
  sink = sink xor uint64(sameVerdict) xor (uint64(diffVerdict) shl 1)

  # Root: feSqrtRatioM1 (field.nim), called directly.
  let (wasSquare, root) = feSqrtRatioM1(FeOne, feFromBytes(fixedScalarBytes(5)))
  sink = sink xor uint64(wasSquare)
  fold(feToBytes(root))

  # Root: sha512 compress, reached via the one-shot sha512() face
  # (private/sha512.nim) -- 128 bytes forces at least one real compress
  # call beyond the padding block.
  var wide: array[128, byte]
  for i in 0 ..< 128: wide[i] = byte((i * 17 + 5) mod 256)
  fold(sha512(wide))

  if paramCount() > 0 and paramStr(1) == "--print-sink":
    echo sink
  else:
    echo "ct_disasm probe: ok (sink=", sink, ")"

main()
