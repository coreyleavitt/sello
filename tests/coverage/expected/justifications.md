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
