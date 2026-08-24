## tests/unit/test_scratch_asan_probe.nim -- RFC-005 slice 9 RED DEMO
## (SCRATCH: this file and its scripts/lib/unit-test-files.sh array entry
## are reverted together after the demo push -- not part of the
## maintained suite).
##
## Plants a genuine, ASan-detectable heap-buffer-overflow in raw emitted
## C, proving `--sanitize asan-ubsan`'s `--passC`/`--passL` flags actually
## reach the real C compile+link rather than merely being accepted by
## scripts/test.sh. The overflow is one byte past an 8-byte malloc'd
## buffer -- small enough that a PLAIN (non-sanitized) build almost never
## crashes on it (the write lands in glibc malloc's own chunk-size
## rounding/padding, not in another live allocation), so this test PASSES
## green under unit-linux-amd64-gcc, and FAILS red under
## unit-linux-amd64-gcc-asan-ubsan, whose ASan redzone immediately after
## every heap allocation catches it unconditionally. That contrast --
## same source, same push, opposite verdicts on the two jobs -- is the
## proof `--passC` reached the compile: a script bug that silently
## dropped the sanitizer flags would leave this test green everywhere.

import std/unittest

{.emit: """
#include <stdlib.h>
#include <string.h>
""".}

proc scratchAsanHeapOverflowProbe() {.inline.} =
  {.emit: """
  {
    unsigned char *buf = (unsigned char *)malloc(8);
    /* One byte past the 8-byte allocation -- RFC-005 slice 9 red demo.
       Deliberate, not a real defect: reverted with this whole file. */
    memset(buf, 0xAA, 9);
    free(buf);
  }
  """.}

suite "RFC-005 slice 9 red demo (scratch, reverted after the demo push)":
  test "planted heap-buffer-overflow, ASan-detectable only":
    scratchAsanHeapOverflowProbe()
    check true
