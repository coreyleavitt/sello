<!--
tests/coverage/expected/justifications.md -- RFC-005 slice 17 (the
coverage ratchet, A3): the CURATED (hand-written, never machine-
regenerated) ledger governing accepted coverage-baseline DECREASES.
Distinct from tests/coverage/expected/baseline.txt (a REGENERABLE pin,
scripts/lib/baseline.sh's idiom, rewritten wholesale by `scripts/coverage.sh
--update`) for exactly the reason RFC-005 Part B calls out: "an in-file
justification register inside a wholesale-regenerated file is nuked by
the next --update" -- this file is never touched by that command, only
by a human, and `scripts/coverage.sh --update` reads it but never writes
it.

WHEN AN ENTRY IS NEEDED: `scripts/coverage.sh --update` (see that
script's own header comment and scripts/lib/coverage-down-path.sh) computes
the fresh aggregate + per-file coverage numbers and compares each one,
key by key, against the CURRENTLY COMMITTED tests/coverage/expected/baseline.txt.
Any key whose fresh value is LOWER than committed -- a real coverage drop,
e.g. a refactor deleting covered code, or a test deleted/weakened -- is
refused unless this file's NEWEST entry cites that exact key and exact
new (lower) value. A RAISE, or an unchanged number, needs no entry here
at all -- it is accepted by the ordinary --update flow like any other
baseline change.

ENTRY FORMAT (parsed by scripts/lib/coverage-down-path.sh -- keep it
exact): the NEWEST entry is added at the TOP of this file, directly below
this header comment and the blank line after it. Each entry is:

## YYYY-MM-DD <short title>

<freeform prose: what changed, why the drop is legitimate (e.g. "refactor
X deleted the now-dead branch Y, which was the only thing exercising
those lines"), and what was checked before accepting it -- this is a
human-reviewed record, not a machine-generated one, so write it for the
next reviewer, not for the parser>

Cites: <key>=<new-value>[, <key>=<new-value>...]

`key` is `aggregate` or a per-file key exactly as scripts/coverage.sh's
own baseline.txt prints it (a path relative to src/sello/, e.g.
`field.nim`, `private/sha512.nim`). `value` is the exact one-decimal
percentage the new (post-drop) run computed for that key, e.g. `71.2`.
The `Cites:` line must be a single line (the parser reads only the first
line beginning with the literal text `Cites: `, scanning from the top of
the file -- multiple entries stay valid history, but only the topmost
one's citation is ever checked against a fresh drop). List every dropped
key on one Cites: line, comma-separated; a drop touching keys not listed
here is refused, with the missing citation(s) named in the refusal
message.

No entries exist yet as of this ledger's creation (RFC-005 slice 17) --
the initial tests/coverage/expected/baseline.txt was generated from a
clean suite run with nothing to justify.
-->

## 2026-08-30 RFC-005 slice 23: {.noinline.} attribution shift, private/backend.nim

RFC-005 slice 23 (the disassembly gate, A2) added `{.noinline.}` to nine
secret-path roots, including `private/backend.derivePublic` and
`private/backend.signDetached` -- the deliberate shipped-codegen change
A2's own text calls for (a call boundary the audited-binary-is-the
-shipped-binary property is worth, per that slice's design). Real hosted
CI (`coverage-ratchet`, run 33309085853) caught a small, genuine
coverage drop as a direct, mechanical side effect: `aggregate` 98.7 ->
98.6, `private/backend.nim` 96.7 -> 96.6 (both floored-to-one-decimal
percentages; every other per-file key unchanged).

**Verified directly against the fresh `build/coverage/run1/
extracted.info`, not inferred:** `private/backend.nim` carries exactly
60 instrumented lines in the fresh dump, 58 covered / 2 uncovered
(58/60 = 96.666...%, which floors-to-one-decimal to the committed 96.6
exactly). The 2 uncovered lines (`DA:221,0`/`DA:222,0` in the fresh
dump) trace to `private/backend.signDetached`'s own pre-existing
(RFC-002 slice 2, not new this slice) debug-only re-derivation assert
(`when not defined(release): {.push assertions: on.} assert A ==
pointEncode(geScalarmultBase(a)), "signDetached: publicBytes does not
match derivePublic(seed)" {.pop.}`, source lines 217-221) -- the
assert's CONDITION (source line 219) executes 62963 times (covered);
these two zero-count lines are Nim's own line-attribution for the
synthesized "condition false -> raise" branch, which by construction
never executes in a passing suite (no test in this project deliberately
feeds `signDetached` a mismatched seed/publicBytes pair -- that
negative case is `signing.keypair(seed, expectedPublic)`'s own job,
tested separately, not this lower-layer assert's). **This exact
always-dead branch is NOT new to this slice** -- the assert itself
predates RFC-005 slice 23 entirely; this file has never been at 100%
line coverage because of it. The 0.1-point DROP this slice caused is
therefore a shift in how many TOTAL lines gcov enumerates for this file
(a denominator effect: the committed pre-slice 96.7 is arithmetically
consistent with the same 2-line-uncovered numerator against a
59-or-60-line total, one or two lines more than this file's fresh
60-line total) rather than a newly-uncovered line -- `{.noinline.}`
forcing `signDetached` into exactly one compiled instance (previously
gcc was free to inline it per call site across the ~15 unit-test
binaries that exercise signing) is the direct, mechanical cause of
that denominator shift, consistent with this file's own header
comment's stated refactor-class example ("a refactor... changing which
lines exist"). No test was deleted or weakened this slice;
`scripts/test.sh`'s full unit+property suite (20 files) stayed green
throughout, both locally and on real hosted CI (run 33309085853's
`unit-*`/`property-*` jobs).

Cites: aggregate=98.6, private/backend.nim=96.6
