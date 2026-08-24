#!/usr/bin/env python3
"""tests/api/api_surface_gen.py -- RFC-005 slice 18 (API-surface gate, A8).

Generates a deterministic dump of sello's public facade surface
(src/sello.nim's own `export` statements) with full signatures, resolved
via `nim jsondoc` over a small, explicitly curated corpus of source files
(CORPUS below) -- NOT `nim doc`/`jsondoc` run directly against
src/sello.nim itself, which only enumerates a module's OWN declarations,
not symbols it re-exports from elsewhere. Verified empirically during
this slice's spike, before committing to this design: `nim jsondoc
src/sello.nim` emits zero `entries` -- confirming CLAUDE.md's own framing
of the facade as "pure `import`+`export` re-export statements" is also
true of the stock doc tooling's blind spot toward it, not just a design
description. `nim doc` itself (the HTML generator) could not even be
tried against this claim: the pinned base image
(ghcr.io/coreyleavitt/nim:2.2.10) ships no doc/ assets at all
(nimdoc.css missing), so `nim doc` errors outright before reaching the
re-export question. `nim jsondoc` shares the front end but not the CSS
dependency, and was the mechanism actually spiked and proven below.

MECHANISM (spike outcome -- a hybrid of the RFC's two named candidates,
per its own "a hybrid is fine if that's what proves out" allowance):
  1. Parse src/sello.nim's own `export <qualifier>.<symbol>[, ...]` /
     `export <symbol>` statements textually (a plain line-oriented scan,
     not a full Nim parser -- src/sello.nim's own export block is a hand
     -enumerated list by design, matching CLAUDE.md's own description of
     it, so this small direct scan is exact for the real input, not a
     heuristic approximation). A `when defined(selloLibsodium):` guard
     (today, around the one `export signing.SodiumInitError` line) is
     tracked as a libsodium-only entry; every other export line is
     always-active. This is the RFC's candidate (a)'s first half ("parsing
     the facade's export statements").
  2. Resolve each parsed name to its DECLARATION SITE (not merely the
     module sello.nim happens to import it through) by looking it up, by
     bare name, in `nim jsondoc` output run against each of a small
     curated corpus of source files (CORPUS below) -- under the SAME
     `-d:` config being dumped, so a libsodium-only declaration's own
     conditional pragmas (e.g. widened `{.raises.}`) resolve exactly as
     they would for a real `import sello` build under that config. This
     is closer to the RFC's candidate (b) ("nim doc --index over the
     transitive modules ... filtered to re-exported names") than (a)'s
     "compiled probe module" half -- a probe module was prototyped
     mentally and rejected: resolving an OVERLOADED bare identifier's
     full set of signatures generically from inside a macro (bindSym's
     open-symbol-choice machinery) is real complexity jsondoc already
     solves for free, per-module, with no macro gymnastics -- see the
     CORPUS note below for why "transitive" stays a small reviewed list
     rather than a generalized import-graph walk.
  3. Emit one sorted, deterministic line per (qualifier, resolved
     overload) -- no line numbers, no absolute paths, no docstrings, no
     timestamps (see normalize_entry()).

CORPUS, and why it's a curated list, not a directory glob or a "follow
every import" walk: sello.nim itself imports exactly six submodules
(sello/wire, sello/wipe, sello/ed25519, sello/x25519, sello/signing,
sello/ristretto) -- confirmed against its own `import` lines. Every
export line's qualifier names one of these six *except one two-hop case
found during this slice's own spike*: `export signing.SodiumInitError`
names `signing`, but SodiumInitError is not declared in signing.nim
itself -- signing.nim only re-exports it (`export backend.SodiumInitError`,
itself gated behind the same `when defined(selloLibsodium)`, with
`backend` bound via `import ... as backend` to whichever of
sello/private/backend.nim / sello/private/backend_sodium.nim matches the
active config -- CLAUDE.md's own "backend.nim"/"backend_sodium.nim"
entries name this dispatch). Both backend files join CORPUS explicitly
for exactly this reason. This is a FIXED, reviewed list, not a
generalized N-hop import/re-export chaser: resolve() below FAILS LOUD if
a future export's symbol name does not appear anywhere in this corpus,
rather than silently widening the search -- a maintainer must then extend
CORPUS by hand (a small, reviewed edit) alongside whatever new export
motivated it. This is the generator's own documented boundary of "named
work, not a stock tool" (the RFC's own framing for this whole gate).

BLIND SPOTS (recorded here per the RFC's own instruction that the spike's
mechanism AND its blind spots be recorded together -- these are also
copied into CLAUDE.md's A8 entry):
  - Wildcard export forms (`export somemodule` with no `.symbol`, or a
    bare re-export this parser cannot resolve to exactly one corpus
    entry) are NOT silently expanded or ignored -- split_export_list()/
    parse_exports() only ever recognize `export a.b[, c.d, ...]` or a
    bare `export ident[, ...]` shape; anything else (e.g. a hypothetical
    future `export ristretto` with no dot) falls through to producing a
    qualifier=None, symbol="ristretto" entry, which resolve() then either
    fails to find (if no corpus module happens to be named exactly that
    AND declare a symbol of that same name) or resolves WRONGLY as an
    ordinary bare symbol lookup -- this is a genuine, undetected blind
    spot for that specific malformed shape, not a fail-loud one, and is
    recorded here honestly rather than claimed handled. sello.nim carries
    no wildcard export today (verified: every export line matches one of
    the two recognized shapes), so this path is UNTESTED against a real
    wildcard.
  - Converter visibility: a `converter` proc, if ever exported, appears
    in the dump like any other proc (jsondoc tags it `skConverter`,
    distinct from `skProc`, so its ADDITION or REMOVAL is caught as an
    ordinary diff) -- but this dump does not specially flag the elevated
    blast radius a converter carries (implicit call-site conversions
    throughout downstream code) beyond that type-tag difference. No
    `converter` exists anywhere in src/ today (verified via grep), so
    this is an untested, honestly-recorded gap, not a validated case.
  - Corpus-wide bare-name / re-export-chain resolution (resolve()'s
    fallback when a qualifier's own file doesn't declare the name
    directly) trusts that at most one corpus file declares any given bare
    name -- true for every export today (verified: SodiumInitError
    appears in exactly one of the two backend files under either config),
    but a HYPOTHETICAL future name collision across two unrelated corpus
    files hits the "FAILS LOUD on ambiguity" branch rather than silently
    picking one -- a maintainer would then need to disambiguate by hand
    (narrow CORPUS, or qualify the export). Recorded as a design
    boundary, not encountered in practice.
  - `line`/`col`/docstring fields from jsondoc's own JSON are deliberately
    dropped from the dump (normalize_entry()) -- a pure prose or
    line-number-only change (e.g. reordering unrelated declarations
    within a module) does NOT appear as a surface diff, by design: this
    gate pins the SURFACE (names + signatures + effects), not source
    layout or documentation prose.

Usage:
  python3 tests/api/api_surface_gen.py <plain|selloLibsodium>

Requires: a `nim` on PATH (this script shells out to `nim jsondoc`), run
from the repository root with nim.cfg already present (relative paths
below are repo-root-relative; scripts/api-surface-dump.sh, the caller,
guarantees both). Writes nothing itself; the dump goes to stdout, sorted
and newline-terminated -- scripts/api-surface-dump.sh captures it.
"""
import json
import os
import re
import subprocess
import sys
import tempfile

CORPUS = [
    ("wire", "src/sello/wire.nim"),
    ("wipe", "src/sello/wipe.nim"),
    ("ed25519", "src/sello/ed25519.nim"),
    ("x25519", "src/sello/x25519.nim"),
    ("signing", "src/sello/signing.nim"),
    ("ristretto", "src/sello/ristretto.nim"),
    ("private/backend", "src/sello/private/backend.nim"),
    ("private/backend_sodium", "src/sello/private/backend_sodium.nim"),
]

FACADE = "src/sello.nim"


def parse_exports(facade_path):
    """Returns a list of (qualifier_or_None, symbol, libsodium_only)."""
    exports = []
    libsodium_block = False
    block_indent = None
    with open(facade_path) as f:
        for raw_line in f:
            line = raw_line.rstrip("\n")
            stripped = line.strip()

            if libsodium_block:
                # Leave the block on a non-blank, non-comment line at or
                # below the block's own indentation.
                indent = len(line) - len(line.lstrip())
                if stripped and not stripped.startswith("#") and indent <= block_indent:
                    libsodium_block = False
                    block_indent = None

            if re.match(r"^when defined\(selloLibsodium\):\s*$", stripped):
                libsodium_block = True
                block_indent = len(line) - len(line.lstrip())
                continue

            if not stripped.startswith("export "):
                continue

            body = stripped[len("export "):]
            for token in split_export_list(body):
                token = token.strip()
                if not token:
                    continue
                if "." in token and not token.startswith("`"):
                    qualifier, symbol = token.split(".", 1)
                else:
                    qualifier, symbol = None, token
                exports.append((qualifier, symbol, libsodium_block))
    return exports


def split_export_list(body):
    """Split a comma-separated export list. A plain str.split(',') is
    exact for every export line in this codebase today: no backtick
    -quoted operator name in src/sello.nim's export statements contains a
    literal comma (see the module doc's wildcard-forms blind spot for the
    general caveat on shapes this parser does not specially handle)."""
    return body.split(",")


def run_jsondoc(nim_source_path, extra_defines):
    with tempfile.TemporaryDirectory() as tmp:
        out_path = os.path.join(tmp, "out.json")
        cmd = ["nim", "jsondoc", "--hints:off", "--warnings:off"] + extra_defines + [
            f"-o:{out_path}",
            nim_source_path,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            sys.stderr.write(f"api_surface_gen: nim jsondoc failed for {nim_source_path}:\n")
            sys.stderr.write(result.stdout)
            sys.stderr.write(result.stderr)
            sys.exit(1)
        with open(out_path) as f:
            return json.load(f)


def normalize_entry(entry):
    """Drop line/col/docstring (see the module doc's last blind-spot
    note) and collapse jsondoc's own line-wrapped `code` field to
    single-line, whitespace-normalized text."""
    code = entry.get("code", "")
    code = re.sub(r"\s+", " ", code).strip()
    return f"{entry.get('type', '?')} :: {code}"


def build_corpus_index(config):
    extra_defines = ["-d:selloLibsodium"] if config == "selloLibsodium" else []
    index = {}
    for short_name, path in CORPUS:
        doc = run_jsondoc(path, extra_defines)
        by_name = {}
        for entry in doc.get("entries", []):
            by_name.setdefault(entry["name"], []).append(entry)
        index[short_name] = by_name
    return index


def resolve(qualifier, symbol, index):
    if qualifier is not None and qualifier in index and symbol in index[qualifier]:
        return qualifier, index[qualifier][symbol]

    # Fall back to a corpus-wide search (the re-export-chain / bare-name
    # case -- see the module doc's CORPUS and blind-spots sections).
    matches = [(mod, entries[symbol]) for mod, entries in index.items() if symbol in entries]
    label = f"{qualifier + '.' if qualifier else ''}{symbol}"
    if len(matches) == 0:
        sys.stderr.write(
            f"api_surface_gen: FAIL -- export '{label}' not found anywhere in "
            f"the curated CORPUS. Extend CORPUS in tests/api/api_surface_gen.py "
            f"(the generator's documented fail-loud boundary, not a silent gap -- "
            f"see the module doc comment).\n"
        )
        sys.exit(1)
    if len(matches) > 1:
        sys.stderr.write(
            f"api_surface_gen: FAIL -- export '{label}' is AMBIGUOUS: found in "
            f"corpus modules {[m for m, _ in matches]}. Resolve by hand (see the "
            f"module doc comment's corpus-wide-resolution blind spot).\n"
        )
        sys.exit(1)
    return matches[0]


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("plain", "selloLibsodium"):
        sys.stderr.write("usage: api_surface_gen.py <plain|selloLibsodium>\n")
        sys.exit(2)
    config = sys.argv[1]

    exports = parse_exports(FACADE)
    index = build_corpus_index(config)

    lines = []
    for qualifier, symbol, libsodium_only in exports:
        if config == "plain" and libsodium_only:
            continue
        resolved_module, entries = resolve(qualifier, symbol, index)
        for entry in entries:
            lines.append(f"{resolved_module}.{symbol} :: {normalize_entry(entry)}")

    for line in sorted(set(lines)):
        print(line)


if __name__ == "__main__":
    main()
