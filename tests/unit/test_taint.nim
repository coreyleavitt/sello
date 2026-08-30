## tests/unit/test_taint.nim -- RFC-005 slice 19 (A1). Compile-time
## coverage of `sello/private/taint`'s access-control invariant: the only
## door into the shim TU is the `declassify` template, which forces a
## compile-time-known, by-construction-registered `DeclassId` (the
## register is `array[DeclassId, DeclassEntry]`, total by the type
## system). This module carries no RUNTIME assertions of its own -- the
## real declassify/exercise-counter behavior is exercised end to end by
## `scripts/ct-taint.sh` under Valgrind, which needs the sello-dev image
## and is not part of this plain `scripts/test.sh` suite (see that
## script's own header comment).
import std/[os, osproc, strutils]
import unittest
import sello/private/taint

suite "taint - raw shim access control (compile-time, subprocess-verified)":
  test "calling the raw shim binding directly (bypassing declassify) is a compile error (subprocess compile, -d:selloTaint)":
    ## Compiled WITH `-d:selloTaint` (unlike a plain build, where
    ## `rawDeclassify` does not exist under any name at all) so this
    ## specifically demonstrates the access-control failure, not merely
    ## the flag being unset. Verified empirically that Nim's semantic
    ## pass rejects this fixture before ever invoking the C compiler on
    ## `taint_shim.c` (no `<valgrind/memcheck.h>` needed to run this
    ## test, so it runs fine in the base image scripts/test.sh already
    ## uses -- no sello-dev dependency).
    let fixture = currentSourcePath().parentDir / "fixtures" / "reject_taint_raw_shim_call.nim"
    let repoRoot = currentSourcePath().parentDir.parentDir.parentDir
    let cmd = "nim c -d:selloTaint --hints:off --nimcache:" &
      (repoRoot / "build" / "nimcache_reject_taint_raw_shim_call") & " " & fixture
    let (output, exitCode) = execCmdEx(cmd, workingDir = repoRoot)
    check exitCode != 0
    check "rawDeclassify" in output

  test "declassify(id, buf) compiles (plain build, expands to a no-op)":
    ## The codegen-unchanged claim (this module's own doc comment) is
    ## verified by a diff of generated C, recorded in the handoff doc --
    ## this test only pins that the call site compiles at all in a plain
    ## build (no `-d:selloTaint`), i.e. the template's `discard` branch is
    ## well-typed against both a buffer and a scalar argument.
    var buf: array[32, byte]
    var verdict: byte = 0
    declassify(diDerivePublicKey, buf)
    declassify(diX25519ZeroVerdict, verdict)
    check true
