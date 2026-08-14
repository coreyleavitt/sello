## Negative-compile fixture (Ristretto ephemeral secret role, RFC-004 slice
## 5b). `RistrettoEphemeralSecret` declares `=copy` with `{.error.}` (the
## same `Keypair`/`x25519.X25519EphemeralSecret` pattern), so a genuine copy
## -- as opposed to a last-use borrow -- must be a compile error. Same
## subprocess-`nim c` methodology as `reject_ephemeral_copy.nim`: the
## violation is raised by `injectdestructors`, later than `compiles()`/
## `nim check` reach, so this file must be compiled for real to observe the
## failure. Do not "fix" this file; its whole purpose is to fail with the
## `=copy` error.
import sello/ristretto

var a = ristrettoEphemeralSecret()
var b = a                    # a real copy: a is read again below
discard ristrettoScalarmultBase(a)
discard ristrettoScalarmultBase(b)
