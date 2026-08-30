## tests/unit/test_registers.nim -- RFC-005 slice 20 (A7): structural
## sanity checks over `tests/registers/secret_targets.nim`, the secret-
## target register. This is NOT the two-rule completeness check (rule 1:
## every exported proc accepting a secret-role type; rule 2: every
## exported secret-import constructor) -- that check needs `nim jsondoc`
## and runs as its own CI job (`scripts/secret-target-register-check.sh`,
## the "secret-target-register" required check) rather than inside the
## plain unit suite, per this slice's own recorded recommendation (a
## jsondoc-driven scan is a heavier, host-toolchain-shaped check than the
## unit suite's other members, and the register file itself already gets
## completeness "by construction" from `array[SecretTargetId,
## SecretTargetEntry]`'s own total-array requirement -- see that module's
## doc comment). What THIS file pins is the register's own internal
## consistency: coverage-cell invariants a compiler cannot check for free.

import std/[sets, unittest]
import ../registers/secret_targets

suite "secret_targets register":
  test "every entry is indexed under its own id":
    for id in SecretTargetId:
      check secretTargetRegister[id].id == id

  test "coveredBy cells never chain (at most one hop, per instrument)":
    ## A `ckCoveredBy` cell's target entry must itself be `ckDirect` for
    ## that SAME instrument -- a chain (coveredBy -> coveredBy) would mean
    ## no entry in the chain actually has a report, silently defeating
    ## the whole coverage cell's purpose.
    for id in SecretTargetId:
      let e = secretTargetRegister[id]
      if e.dudect.kind == ckCoveredBy:
        check secretTargetRegister[e.dudect.coveredBy].dudect.kind == ckDirect
      if e.taint.kind == ckCoveredBy:
        check secretTargetRegister[e.taint.coveredBy].taint.kind == ckDirect
      if e.disasm.kind == ckCoveredBy:
        check secretTargetRegister[e.disasm.coveredBy].disasm.kind == ckDirect

  test "ckDirect cells never carry an empty name":
    for id in SecretTargetId:
      let e = secretTargetRegister[id]
      if e.dudect.kind == ckDirect: check e.dudect.name.len > 0
      if e.taint.kind == ckDirect: check e.taint.name.len > 0
      if e.disasm.kind == ckDirect: check e.disasm.name.len > 0

  test "ckExempt cells always carry a rationale":
    for id in SecretTargetId:
      let e = secretTargetRegister[id]
      if e.dudect.kind == ckExempt: check e.dudect.rationale.len > 0
      if e.taint.kind == ckExempt: check e.taint.rationale.len > 0
      if e.disasm.kind == ckExempt: check e.disasm.rationale.len > 0

  test "ruleBasis is one of the three documented values":
    for id in SecretTargetId:
      let basis = secretTargetRegister[id].ruleBasis
      check basis == "rule1" or basis == "rule2" or basis == "curated"

  test "qualifiedProc is never empty":
    for id in SecretTargetId:
      check secretTargetRegister[id].qualifiedProc.len > 0

  test "disasmRoots() is the deduplicated union of every direct disasm cell":
    let roots = disasmRoots()
    var expected: HashSet[string]
    for id in SecretTargetId:
      let d = secretTargetRegister[id].disasm
      if d.kind == ckDirect:
        expected.incl(d.name)
    check roots.len == expected.len
    var seen: HashSet[string]
    for r in roots:
      check r notin seen  # no duplicates
      seen.incl(r)
      check r in expected

  test "the dudect-direct target count matches ct_main.nim's own real-target count":
    ## ct_main.nim runs one real (non-positive-control) dudect target per
    ## `ckDirect` dudect register entry -- see that file's own
    ## `dudectTargetIds` compile-time assert-against block, which is the
    ## authoritative bidirectional check; this is a cheap, independent
    ## sanity pin on the count alone (10 as of this slice), so a drift
    ## shows up in the fast unit suite too, not only at ct_main.nim's own
    ## next compile.
    var directDudect = 0
    for id in SecretTargetId:
      if secretTargetRegister[id].dudect.kind == ckDirect: inc directDudect
    check directDudect == 10
