## Shared crank-factor helper for the property-suite settings constructors
## (RFC-005 slice 26, Nightly part 3's "cranked properties" job).
##
## proptest exposes no external "run this whole campaign at N times the
## examples" knob of its own -- `Settings.maxExamples` is a plain `int`
## field each `test_properties_*.nim` file's own per-suite settings
## constructor (`covSettings`/`settingsWithExamples`/`settingsForPoints`)
## already sets, tuned per property for its own cost profile (verified by
## reading every one of the six files before writing this helper: field.nim
## and scalar.nim use `defaultSettings()`'s baseline 100 unmodified via
## `covSettings()`; signing/x25519/sha512/ristretto dial `maxExamples` down
## per-suite via `settingsWithExamples(n: int)`, e.g. 50, for costlier
## per-example work). A single multiplicative crank factor, applied at the
## same point every one of those constructors already computes its own
## `maxExamples`, is the smallest surface that lets the nightly job dial
## every suite up UNIFORMLY -- proportional to each suite's own existing
## tuning, not a single hardcoded number that would either overshoot the
## cheap suites or undershoot the expensive ones -- without touching
## `src/` (this is validation-harness tuning, not library behavior) or
## duplicating six independent per-file mechanisms.
##
## `SELLO_PROPERTY_CRANK` (an environment variable, read once via
## `propertyCrankFactor()` at Settings-construction time, i.e. at `let
## propertySettingsNN = settingsWithExamples(NN)` module-init time or at
## each `with covSettings()` call): a positive integer multiplier, default
## **1** -- so every existing caller (a maintainer's plain
## `scripts/test.sh`, the required `property-linux-amd64-{gcc,clang}` /
## `property-linux-arm64-gcc` merge-gate jobs) is byte-for-byte unaffected
## unless this variable is explicitly set. The nightly `cranked-properties`
## job (`.github/workflows/nightly.yml`) sets it to the RECORDED crank
## factor (see that job's own comment for the exact number and the
## measured wall-clock cost at that factor) before invoking
## `scripts/ci-property.sh`, which forwards environment untouched into
## `scripts/test.sh` and the `nim c -r` processes it spawns -- no plumbing
## needed beyond this one process-environment variable, since every
## `test_properties_*.nim` file already reads it independently at its own
## settings-construction call sites.
import std/[os, strutils]

proc propertyCrankFactor*(): int =
  ## Parsed fresh from `SELLO_PROPERTY_CRANK` on every call (cheap; called
  ## a handful of times per test binary, at module-init/settings-
  ## construction time, never per-example) -- a missing, empty, non-numeric,
  ## or non-positive value is treated as 1 (the crank exists to multiply
  ## UP a suite's own tuned example count, never to zero it out or invert
  ## it).
  let raw = getEnv("SELLO_PROPERTY_CRANK", "1")
  try:
    result = parseInt(raw)
    if result < 1:
      result = 1
  except ValueError:
    result = 1

proc cranked*(n: int): int =
  ## `n`, multiplied by the crank factor -- the one call every settings
  ## constructor in `test_properties_*.nim` routes its own base example
  ## count through.
  n * propertyCrankFactor()
