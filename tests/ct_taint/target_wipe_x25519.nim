## tests/ct_taint/target_wipe_x25519.nim -- RFC-005 slice 21 (A1). The
## observable-wipe-path targets for `x25519.wipe`'s three overloads
## (`X25519StaticSecret`, `X25519Shared`, `X25519EphemeralSecret`) -- the
## re-specified wipe-paths scope (A1's own text): wiping stores DEFINED
## zeros, so this harness checks the OBSERVABLE subset only --
## caller-owned in-place buffers, via a make-undefined-then-wipe-then-
## check-defined sequence. No `src/sello/` change was needed for this
## target: `wipe` already calls `ct.wipe` (real volatile stores), and
## this file exercises that existing code with no new `declassify` call
## site -- there is no accept/reject verdict or derived value here to
## register a `DeclassId` for (`x25519.wipe`'s own register entries carry
## an empty `declassIds`).
##
## **Harness-side cast route**, same as `target_x25519_ephemeral.nim`:
## `X25519StaticSecret`/`X25519Shared` have a private `bytes` field, so
## this target reaches it via a raw pointer cast to the type's own
## one-field byte representation.
import sello/x25519
import sello/private/taint

# --- X25519StaticSecret (var overload -- checks the SAME memory wipe()
# --- touches directly, no move/copy involved) -----------------------
block:
  var staticBytes: array[32, byte]
  for i in 0 ..< 32: staticBytes[i] = byte(i * 3 + 1)
  var secret = toX25519StaticSecret(staticBytes)
  markUndefined(cast[ptr array[32, byte]](addr secret)[])
  wipe(secret)
  checkDefined(cast[ptr array[32, byte]](addr secret)[])
  echo "target_wipe_x25519: X25519StaticSecret wiped observably clean"

# --- X25519Shared (var overload -- same direct-memory register) -----
block:
  var sh: X25519Shared
    ## Nim zero-initializes locals at declaration, so `sh` starts fully
    ## DEFINED (all zero) -- `markUndefined` below is what makes this a
    ## real taint target rather than testing an already-defined value.
  markUndefined(cast[ptr array[32, byte]](addr sh)[])
  wipe(sh)
  checkDefined(cast[ptr array[32, byte]](addr sh)[])
  echo "target_wipe_x25519: X25519Shared wiped observably clean"

# --- X25519EphemeralSecret (sink overload) ---------------------------
#
# Honest disclosure: `wipe(sink X25519EphemeralSecret)` takes its
# argument BY MOVE into a new, callee-local stack slot -- the caller's
# own variable (`eph` below) is reset by Nim's own `wasMoved` machinery
# (inserted by `injectdestructors` to prevent double-destruction of a
# type with a custom `=destroy`, which this move-only type has via
# `secretHooksMoveOnly`) independent of whatever `wipe`'s own body does
# to ITS copy. So checking `eph`'s memory after the call is confounded --
# it demonstrates the COMPILER's own post-move reset, not `wipe`'s own
# `ct.wipe` call on its own parameter, which this harness has no way to
# observe directly (it operates on a separate, callee-local stack slot
# with no caller-visible handle). This block still runs the real code
# path with genuinely tainted input under valgrind end to end (the sink
# parameter's copy carries the taint across the call boundary; a real
# secret-dependent branch anywhere in that path would still be caught),
# it just does not isolate `wipe`'s own store the way the two `var`
# blocks above cleanly do.
block:
  var eph = x25519EphemeralSecret()
  markUndefined(cast[ptr array[32, byte]](addr eph)[])
  wipe(move(eph))
  checkDefined(cast[ptr array[32, byte]](addr eph)[])
  echo "target_wipe_x25519: X25519EphemeralSecret wipe() path ran clean (caller-slot check confounded by wasMoved, see this file's own comment)"
