## Negative-compile fixture (RFC-005 slice 19, A1). `taint.nim`'s only
## public door into the taint shim TU is the `declassify` template, which
## forces a compile-time-known, by-construction-registered `DeclassId`
## (the register is `array[DeclassId, DeclassEntry]`, total by the type
## system, so "unregistered" cannot exist as a runtime state). This
## fixture pins the OTHER half of that claim: the raw binding
## (`rawDeclassify`) is unexported, so reaching the shim directly,
## bypassing `declassify` entirely, is an ordinary compile error --
## `compiles()` can already see this (unexported symbol access), so this
## subprocess fixture exists for consistency with this directory's
## established methodology (`fixtures/reject_secretscalar_vartime.nim`'s
## own precedent), not because `compiles()` is blind to this error class.
import sello/private/taint

var buf: array[32, byte]
taint.rawDeclassify(diDerivePublicKey, addr buf[0], csize_t(32))
