## Negative-compile fixture (X25519 static/ephemeral split).
##
## `X25519EphemeralSecret` declares `=copy` with `{.error.}` (the same
## `Keypair` pattern), so a genuine copy -- as opposed to a last-use move
## -- must be a compile error. Same subprocess-`nim c` methodology as
## `reject_keypair_copy.nim`/`reject_ephemeral_reuse.nim`: the violation is
## raised by `injectdestructors`, later than `compiles()`/`nim check`
## reach, so this file must be compiled for real to observe the failure.
## Do not "fix" this file; its whole purpose is to fail with the `=copy`
## error.
import sello/x25519

var a = x25519EphemeralSecret()
var b = a                    # a real copy: a is read again below
discard x25519Base(a)
discard x25519Base(b)
