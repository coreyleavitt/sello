## Negative-compile fixture (round-4 finding R4).
##
## `Seed` is move-only and its whole design point is compiler-enforced
## single use, but before this fix `wipe(s: var Seed)` took `var`, not
## `sink` -- so it did not consume `s`. That let a caller write `wipe(s)`
## and then still reach a consuming `keypair(move(s))`, which COMPILED and
## derived a keypair from the just-zeroed (all-zero) seed. This file pins
## the fixed behavior: `wipe` now takes `sink Seed`, so it consumes `s`
## just like `keypair` does, and the later `move(s)` below is a reuse of
## an already-consumed variable -- the SAME `=copy {.error.}` violation
## `reject_seed_copy.nim` pins, raised by the `injectdestructors` pass
## during a real `nim c`, later in the pipeline than `compiles()`/
## `nim check` reach (same methodology as every other fixture in this
## directory). Do not "fix" this file; its whole purpose is to fail with
## the `=copy` error.
import sello/signing

var seed = toSeed([0'u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
                 30, 31])
wipe(seed)
discard keypair(move(seed))
