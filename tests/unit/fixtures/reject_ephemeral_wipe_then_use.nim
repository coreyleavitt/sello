## Negative-compile fixture (round-4 finding R4).
##
## `X25519EphemeralSecret` is move-only and single-use by design, but
## before this fix `wipe(s: var X25519EphemeralSecret)` took `var`, not
## `sink` -- so it did not consume `s`. That let a caller write
## `wipe(eph)` and then still reach a consuming `x25519(move(eph), peer)`,
## which COMPILED and ran the ladder on the just-zeroed bytes (yielding a
## fully-predictable shared secret, since `clampScalar` on an all-zero
## array is the fixed public scalar 2^254 -- neither zero nor small-order,
## so the small-order check does not catch it). This file pins the fixed
## behavior: `wipe` now takes `sink X25519EphemeralSecret`, so it consumes
## `eph` just like `x25519` does, and the later `move(eph)` below is a
## reuse of an already-consumed variable -- the SAME `=copy {.error.}`
## violation `reject_ephemeral_reuse.nim` pins, raised by the
## `injectdestructors` pass during a real `nim c`, later in the pipeline
## than `compiles()`/`nim check` reach (same methodology as every other
## fixture in this directory). Do not "fix" this file; its whole purpose
## is to fail with the `=copy` error.
import sello/x25519

var peer = x25519Base(x25519EphemeralSecret())
var eph = x25519EphemeralSecret()
wipe(eph)
discard x25519(move(eph), peer)
