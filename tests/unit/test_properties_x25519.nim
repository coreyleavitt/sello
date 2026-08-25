## Property-based coverage for sello/x25519 (RFC-003 slice 2 item 3).
##
## The Montgomery-side analog of test_properties_scalar.nim's Edwards-side
## agreement properties: this is the natural home for future X25519
## properties. See test_properties_field.nim's module doc comment for the
## proptest wiring notes (optional milpa dep, z3-avoidance) -- not repeated
## here.
##
## `X25519StaticSecret` values are built directly from random 32-byte
## strategies via `toX25519StaticSecret` -- clamping happens inside
## `x25519.ladder` itself, so the raw (unclamped) byte strategy already
## covers the full input domain the public API accepts.

import std/[unittest, options]
import proptest
import sello/x25519
import ./property_crank

proc randByte(): Strategy[byte] =
  integers(0, 255).map(proc(x: int): byte = byte(x))

proc secretBytes(): Strategy[array[32, byte]] =
  arrays[32, byte](randByte())

proc staticSecrets(): Strategy[X25519StaticSecret] =
  secretBytes().map(proc(b: array[32, byte]): X25519StaticSecret =
    toX25519StaticSecret(b))

proc settingsWithExamples(n: int): Settings =
  ## `defaultSettings()` (fixed seed, reproducible) with `maxExamples`
  ## dialed down for the costlier Montgomery-ladder properties in this
  ## suite -- same rationale as test_properties_scalar.nim's
  ## `settingsWithExamples`. `n` routed through `cranked()` (RFC-005
  ## slice 26) -- see tests/unit/property_crank.nim.
  result = defaultSettings()
  result.maxExamples = cranked(n)
  result.coverageGuided = true

let propertySettings50 = settingsWithExamples(50)

# ---------------------------------------------------------------------------
# DH agreement: x25519(a, x25519Base(b)) == x25519(b, x25519Base(a)).
#
# For random 32-byte secrets, both derived public values are ordinary
# ladder outputs of a full-domain (post-clamping) scalar against the base
# point 9 -- landing on one of the curve's eight small-order points would
# require the clamped scalar to hit one of a handful of specific low-order
# values, astronomically unlikely under random sampling. `x25519` is
# handled honestly regardless: both calls are asserted `isSome` before
# comparing, so a hypothetical small-order hit fails loudly (via the
# `ensure` on `isSome`) rather than silently comparing `none == none`.
# ---------------------------------------------------------------------------

suite "x25519 property: Diffie-Hellman agreement":
  property "x25519(a, x25519Base(b)) == x25519(b, x25519Base(a))":
    with propertySettings50
    given a in staticSecrets(), b in staticSecrets()
    let pubA = x25519Base(a)
    let pubB = x25519Base(b)
    let sharedFromA = x25519(a, pubB)
    let sharedFromB = x25519(b, pubA)
    ensure sharedFromA.isSome
    ensure sharedFromB.isSome
    ensure toBytes(sharedFromA.get) == toBytes(sharedFromB.get)
