## Negative-compile fixture (X25519 static/ephemeral split).
##
## `X25519EphemeralSecret` is move-only and `x25519` takes it by `sink`, so
## consuming it twice -- calling `x25519` a second time with the SAME
## variable, with no explicit `move()` anywhere -- must be a compile
## error, not a runtime footgun. This file is deliberately invalid and is
## exercised by `tests/unit/test_x25519.nim` via a subprocess `nim c`
## rather than `compiles()`/`nim check` -- same reasoning as
## `reject_keypair_copy.nim`: the `=copy {.error.}` violation Nim raises
## here (a copy is required for the FIRST `x25519` call, since it is not
## the variable's last read once the second call exists) is only surfaced
## by the `injectdestructors` pass during a real `nim c`, a pass later in
## the pipeline than either `compiles()` or `nim check` reach -- both
## report this snippet as valid even though a real compile rejects it.
## Do not "fix" this file; its whole purpose is to fail with the `=copy`
## error. Contrast `reject_ephemeral_copy.nim`, which pins the same
## guarantee via a direct `var b = a` instead of a sink-argument reuse.
import sello/x25519

var peer = x25519Base(x25519EphemeralSecret())
var eph = x25519EphemeralSecret()
discard x25519(eph, peer)
discard x25519(eph, peer)  # reuse: eph is read again here, so the FIRST
                            # call above is not eph's last read
