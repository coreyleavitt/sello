## Property-based coverage for sello/private/sha512 (RFC-006 slice 2).
##
## See test_properties_field.nim's module doc comment for the proptest
## wiring notes (optional milpa dep, z3-avoidance) -- not repeated here.
## Imports `sello/private/sha512` directly, the same private-module-reach
## register `test_sha512.nim` and `test_ct.nim` already use for this
## module (it carries no facade export -- see RFC-006's Non-goals).
##
## Three properties, matching the RFC's slice-2 list exactly:
## - determinism (same input, same output, across repeated calls)
## - incremental-vs-one-shot agreement over a random SINGLE split point
## - multi-update associativity: an arbitrary number of update-boundary
##   chunks (here, three, at two independently random split points)
##   still agrees with the one-shot digest
##
## Split points are derived as a proportional fraction of the generated
## message's own length (`(frac * msg.len) div 1000`), rather than a
## dependent integer strategy keyed off `msg.len` -- proptest's `given`
## strategies are independent of each other, so this is the simplest way
## to land a split point that is always in `0 .. msg.len` regardless of
## which length `bytes()` happened to draw.

import std/unittest
import proptest
import sello/private/sha512

proc settingsWithExamples(n: int): Settings =
  ## `defaultSettings()` (fixed seed, reproducible) -- same rationale as
  ## test_properties_scalar.nim's `settingsWithExamples`.
  result = defaultSettings()
  result.maxExamples = n
  result.coverageGuided = true

let propertySettings50 = settingsWithExamples(50)

suite "sha512 property: determinism":
  property "sha512(msg) is deterministic across repeated calls on the same input":
    with propertySettings50
    given msg in bytes(0, 300)
    ensure sha512(msg) == sha512(msg)

suite "sha512 property: incremental/one-shot agreement over a random split point":
  property "init/update/update/finish, split at a random point in 0..msg.len, equals sha512(msg)":
    with propertySettings50
    given msg in bytes(0, 300), splitFrac in integers(0, 1000)
    let splitPoint = if msg.len == 0: 0 else: (splitFrac * msg.len) div 1000
    var ctx: Sha512Context
    ctx.init()
    ctx.update(msg[0 ..< splitPoint])
    ctx.update(msg[splitPoint ..< msg.len])
    var digest: array[64, byte]
    ctx.finish(digest)
    ensure digest == sha512(msg)

suite "sha512 property: multi-update associativity":
  property "hashing via three chunks at two arbitrary update boundaries matches the one-shot digest":
    with propertySettings50
    given msg in bytes(0, 300), f1 in integers(0, 1000), f2 in integers(0, 1000)
    let p1raw = if msg.len == 0: 0 else: (f1 * msg.len) div 1000
    let p2raw = if msg.len == 0: 0 else: (f2 * msg.len) div 1000
    let p1 = min(p1raw, p2raw)
    let p2 = max(p1raw, p2raw)
    var ctx: Sha512Context
    ctx.init()
    ctx.update(msg[0 ..< p1])
    ctx.update(msg[p1 ..< p2])
    ctx.update(msg[p2 ..< msg.len])
    var digest: array[64, byte]
    ctx.finish(digest)
    ensure digest == sha512(msg)
