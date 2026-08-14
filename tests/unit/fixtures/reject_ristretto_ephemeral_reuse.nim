## Negative-compile fixture (RFC-004 slice 7a: ristretto ephemeral secret's
## consuming scalarmult overload).
##
## `RistrettoEphemeralSecret` is move-only and
## `ristrettoScalarmult(sink RistrettoEphemeralSecret, ...)` takes it by
## `sink`, so consuming it twice -- calling that overload a second time
## with the SAME variable, with no explicit `move()` anywhere -- must be a
## compile error, not a runtime footgun. This file is deliberately invalid
## and is exercised by `tests/unit/test_ristretto.nim` via a subprocess
## `nim c` rather than `compiles()`/`nim check` -- same reasoning as
## `x25519.nim`'s `reject_ephemeral_reuse.nim`: the `=copy {.error.}`
## violation Nim raises here (a copy is required for the FIRST
## `ristrettoScalarmult` call, since it is not the variable's last read
## once the second call exists) is only surfaced by the
## `injectdestructors` pass during a real `nim c`, a pass later in the
## pipeline than either `compiles()` or `nim check` reach -- both report
## this snippet as valid even though a real compile rejects it. Do not
## "fix" this file; its whole purpose is to fail with the `=copy` error.
## Contrast `reject_ristretto_ephemeral_copy.nim`, which pins the same
## guarantee via a direct `var b = a` instead of a sink-argument reuse.
import sello/ristretto

let peer = ristrettoScalarmultBase(ristrettoEphemeralSecret())
var eph = ristrettoEphemeralSecret()
discard ristrettoScalarmult(eph, peer)
discard ristrettoScalarmult(eph, peer)  # reuse: eph is read again here, so
                                         # the FIRST call above is not
                                         # eph's last read
