## Negative-compile fixture (RFC-002 slice 1).
##
## `Seed` is move-only as of RFC-002 slice 1: `sello/signing` declares
## `=copy` with `{.error.}` (the same `Keypair` pattern, now that
## `toBytes(kp: Keypair)` removes the only copy-requiring API -- the old
## `seed()` accessor -- `Seed`'s copyability used to serve), so a genuine
## copy -- as opposed to a last-use move -- must be a compile error. Same
## subprocess-`nim c` methodology as `reject_keypair_copy.nim`: the
## `=copy` violation Nim raises here is only surfaced by the
## `injectdestructors` pass during a real `nim c`, which runs later in the
## pipeline than either `compiles()` or `nim check` reach -- both report
## this snippet as valid even though a real compile rejects it. Do not
## "fix" this file; its whole purpose is to fail with the `=copy` error.
import sello/signing

let seed = toSeed([0'u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
                 30, 31])
let seed2 = seed              # a real copy: seed is read again below
discard keypair(seed)
discard keypair(seed2)
