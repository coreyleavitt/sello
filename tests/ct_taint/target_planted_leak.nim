## tests/ct_taint/target_planted_leak.nim -- RFC-005 slice 19 (A1). A
## PERMANENT negative fixture, not a one-time demonstration: a deliberately
## planted secret-conditioned branch, always compiled and run by
## `scripts/ct-taint.sh`, always asserted RED (at least one memcheck
## error, resolving to the `if` below). This is the harness's own
## regression pin that the taint mechanism itself still works -- if this
## target ever comes back clean, the harness has silently lost the
## ability to detect a real secret-dependent branch (the exact "taint
## washout" failure mode A1's own text names), which is a far more
## serious finding than any individual target going red, and this fixture
## exists to catch it on every run.
##
## Deliberately never declassified -- there is no sanctioned disclosure
## here to register a `DeclassId` for; this branch is the thing the whole
## harness exists to reject.
import sello/private/taint

var secretBytes: array[32, byte]
for i in 0 ..< 32: secretBytes[i] = byte(i * 11 + 5)
markUndefined(secretBytes)

if (secretBytes[0] and 1'u8) == 0'u8:
  echo "target_planted_leak: took the even path (this line should never be reached error-free)"
else:
  echo "target_planted_leak: took the odd path (this line should never be reached error-free)"
