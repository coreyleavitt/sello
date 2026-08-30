## tests/ct_taint/target_wipe_generic.nim -- RFC-005 slice 21 (A1). The
## observable-wipe-path target for `wipe.wipe(bytes: var array[32,
## byte])` -- the generic overload for raw secret material a caller holds
## outside any of sello's own secret-carrying types. No `src/sello/`
## change needed, no `DeclassId` involved -- same make-undefined-then-
## wipe-then-check-defined idiom as every other wipe target in this
## directory, and the simplest of the lot: `bytes` is a plain, caller-
## owned `array[32, byte]`, so no harness-side cast is needed at all.
import sello/wipe
import sello/private/taint

var bytes: array[32, byte]
for i in 0 ..< 32: bytes[i] = byte(i * 17 + 11)
markUndefined(bytes)
wipe(bytes)
checkDefined(bytes)
echo "target_wipe_generic: wipe() cleared observably clean"
