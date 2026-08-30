## tests/ct_taint/target_wipe_ristretto.nim -- RFC-005 slice 21 (A1). The
## observable-wipe-path targets for `ristretto.wipe`'s three overloads
## (`RistrettoStaticSecret`, `RistrettoEphemeralSecret`,
## `RistrettoShared`) -- same design and rationale as
## `target_wipe_x25519.nim` (see that file's own header comment for the
## full writeup, not repeated here): no `src/sello/` change needed, no
## `DeclassId` involved, `var`-overload checks are direct and clean,
## `sink`-overload checks are confounded by Nim's own post-move
## `wasMoved` reset.
import std/options
import sello/ristretto
import sello/private/taint

# --- RistrettoStaticSecret (var overload) ----------------------------
block:
  var staticBytes: array[32, byte]
  staticBytes[0] = 3'u8
  var secret = toRistrettoStaticSecret(staticBytes).get()
  markUndefined(cast[ptr array[32, byte]](addr secret)[])
  wipe(secret)
  checkDefined(cast[ptr array[32, byte]](addr secret)[])
  echo "target_wipe_ristretto: RistrettoStaticSecret wiped observably clean"

# --- RistrettoShared (var overload) -----------------------------------
block:
  var sh: RistrettoShared
  markUndefined(cast[ptr array[32, byte]](addr sh)[])
  wipe(sh)
  checkDefined(cast[ptr array[32, byte]](addr sh)[])
  echo "target_wipe_ristretto: RistrettoShared wiped observably clean"

# --- RistrettoEphemeralSecret (sink overload; caller-slot check
# --- confounded by wasMoved, see target_wipe_x25519.nim's header) -----
block:
  var eph = ristrettoEphemeralSecret()
  markUndefined(cast[ptr array[32, byte]](addr eph)[])
  wipe(move(eph))
  checkDefined(cast[ptr array[32, byte]](addr eph)[])
  echo "target_wipe_ristretto: RistrettoEphemeralSecret wipe() path ran clean (caller-slot check confounded by wasMoved)"
