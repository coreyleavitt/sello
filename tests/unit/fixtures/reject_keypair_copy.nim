## Negative-compile fixture (RFC-001 slice 5).
##
## `Keypair` is move-only: `sello/signing` declares `=copy` with
## `{.error.}`, so a genuine copy (as opposed to a last-use move) must be
## a compile error. This file is deliberately invalid and is exercised by
## `tests/unit/test_signing.nim` via a subprocess `nim c` rather than the
## builtin `compiles()` (or `nim check`) — Nim's ARC/ORC copy-hook
## violation is raised by the `injectdestructors` pass, which runs later
## in the pipeline than either of those reach, so both report this
## snippet as valid even though a real compile rejects it. Do not "fix"
## this file; its whole purpose is to fail with the `=copy` error.
import sello/signing

let seed = toSeed([0'u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
                 30, 31])
let kp1 = keypair(seed)
let kp2 = kp1              # a real copy: kp1 is read again below
discard kp1.public()
discard kp2.public()
