#!/usr/bin/env python3
"""tests/coverage/coverage_report_gen.py -- RFC-005 slice 17 (the coverage
ratchet, A3): turns a merged-and-extracted lcov `.info` file (already
produced by `scripts/coverage.sh`'s own `lcov --capture`/`lcov -a`/
`lcov --extract '*/src/sello/*'` pipeline) into the stable, sorted text
dump `scripts/coverage.sh` feeds through `scripts/lib/baseline.sh`'s
regenerable-baseline idiom as the pin body.

Why a separate Python step at all, rather than folding this into
`scripts/coverage.sh` as an awk one-liner (the project's usual first
instinct for structured-text munging -- see `scripts/lib/baseline.sh`'s
own header): the pinned image's `/usr/bin/awk` is BusyBox awk (verified
empirically this slice, not assumed), which has no associative-array
sort primitive (`asorti`, a gawk extension) and no reliable arbitrary-
precision integer arithmetic -- both needed for the exact, tie-safe
floor-to-one-decimal computation below. `tests/api/api_surface_gen.py`
is this project's own precedent for "python3 for this class of
structured-text job" (its own module doc comment makes the identical
argument against a shakier alternative); python3 is already a hard
dependency of `scripts/lib/milpa-install.sh` and every gate that sources
it, so this adds no new toolchain requirement.

INPUT: a single positional argument, the path to an lcov `.info` file
already merged (all per-test-binary captures combined via `lcov -a`) and
extracted to `src/sello/*` only (`lcov --extract ... '*/src/sello/*'`).
This script does no merging or extraction of its own -- that stays lcov's
job, invoked directly by `scripts/coverage.sh` (a shell script is the
right place to shell out to `lcov`/`nim c`; this script's only job is the
arithmetic/formatting step lcov itself does badly, per the header
comment above).

PARSING: `.info` (the "tracefile" format geninfo/lcov both read and
write) is a flat, line-oriented format -- this script reads exactly three
record types and ignores everything else (FN/FNDA/BRDA/etc. -- this gate
is LINE coverage only, per RFC-005 Part B's own A3 text, not branch or
function coverage):
  SF:<path>          -- starts a new source-file record
  LF:<n>              -- "lines found" (coverable lines) for the current SF
  LH:<n>              -- "lines hit" for the current SF
  end_of_record       -- closes the current SF record
A file that appears via more than one SF: record in the same input (should
not happen post-merge, since `lcov -a` combines same-path records into
one, but this script does not assume that invariant blindly) has its
LF/LH summed across all its records -- the arithmetically correct
aggregate either way.

KEY: each SF path is reduced to a "key" by taking everything after the
LAST `src/sello/` path segment (e.g. `/workspace/src/sello/field.nim` ->
`field.nim`, `.../src/sello/private/sha512.nim` -> `private/sha512.nim`)
-- stable across host-mode (`$PWD`-rooted absolute paths) and CI-mode
(`/workspace`-rooted) runs alike, and across a future repo relocation,
since only the part below `src/sello/` survives. A path with no
`src/sello/` segment at all is a script bug (the caller's own `--extract
'*/src/sello/*'` pattern should make this unreachable) and is treated as
fatal, not silently dropped -- silently dropping a file from the pinned
set is exactly the kind of quiet coverage-figure drift this whole gate
exists to prevent.

FLOOR-TO-ONE-DECIMAL, done in EXACT integer arithmetic, not float
rounding: RFC-005 Part B's own text ("each floored to one decimal") means
truncation toward zero at the tenths place, not round-half-anything --
`round(71.25, 1)` and a floating-point `math.floor(pct * 10) / 10` both
risk landing on the wrong side of a boundary the pct value sits exactly
on (e.g. a true ratio of exactly 71.2% can be represented as
71.19999999999999 in IEEE double, and `floor(...*10)` would then floor to
71.1 -- a spurious one-tenth-point drop on every regeneration purely from
float noise, exactly the "line-level jitter" the RFC's own A3 text warns
the floor exists to absorb, not reintroduce). Since `pct = lh / lf * 100`,
`floor(pct * 10)` is exactly `floor(lh * 1000 / lf)`, computed with
Python's arbitrary-precision integers via `//` (true floor division, no
float ever constructed) -- exact for any lh/lf this project's line counts
will ever reach.

OUTPUT (stdout, the exact text `scripts/lib/baseline.sh`'s `baseline_check`/
`baseline_update` treat as "the body"): the literal line `aggregate
<pct>`, computed from the SUM of every file's LF/LH (not the mean of the
per-file percentages -- the RFC's own text is "the aggregate percentage",
i.e. a single suite-wide line-coverage ratio, matching what `lcov
--summary` itself reports), followed by one `<key> <pct>` line per file,
KEYS SORTED (Python's default string sort, stable and locale-independent
via `sorted()` on plain str -- no `LC_ALL` dependency, unlike shell
`sort`) so the dump is byte-stable across runs with identical underlying
coverage data regardless of `.info` record order (lcov's own capture
order depends on filesystem directory-listing order, which is NOT
guaranteed stable -- sorting here is what makes the baseline diff
meaningful line-by-line instead of order-noise). `<pct>` is always
printed with exactly one decimal digit (e.g. `71.2`, `100.0`, `0.0`).

A file with LF == 0 (zero coverable lines in the extracted record -- not
expected for any real `src/sello/*.nim` file today, but a defensive
guard rather than a ZeroDivisionError) is treated as 100.0% and a warning
is printed to stderr; it still gets a baseline row like any other file,
since silently excluding it would be the same "quiet drop" risk the KEY
section above already refuses to allow for a missing src/sello/ segment.
"""
from __future__ import annotations

import sys


def parse_info(path: str) -> dict[str, tuple[int, int]]:
    """Returns {key: (lf_sum, lh_sum)}, keys as described in the module
    doc comment above. Raises SystemExit (via _fatal) on a malformed
    record this script cannot make sense of, rather than silently
    producing a partial/wrong dump."""
    per_file: dict[str, tuple[int, int]] = {}
    cur_key: str | None = None
    cur_lf: int | None = None
    cur_lh: int | None = None

    with open(path, "r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, start=1):
            line = raw.rstrip("\n")
            if line.startswith("SF:"):
                if cur_key is not None:
                    _fatal(f"{path}:{lineno}: new SF: record before the previous one's end_of_record")
                sf = line[len("SF:"):]
                cur_key = _key_of(sf, path, lineno)
                cur_lf = None
                cur_lh = None
            elif line.startswith("LF:"):
                if cur_key is None:
                    _fatal(f"{path}:{lineno}: LF: record with no preceding SF:")
                cur_lf = int(line[len("LF:"):])
            elif line.startswith("LH:"):
                if cur_key is None:
                    _fatal(f"{path}:{lineno}: LH: record with no preceding SF:")
                cur_lh = int(line[len("LH:"):])
            elif line == "end_of_record":
                if cur_key is None:
                    _fatal(f"{path}:{lineno}: end_of_record with no preceding SF:")
                if cur_lf is None or cur_lh is None:
                    _fatal(f"{path}:{lineno}: end_of_record for {cur_key!r} missing LF:/LH:")
                prev_lf, prev_lh = per_file.get(cur_key, (0, 0))
                per_file[cur_key] = (prev_lf + cur_lf, prev_lh + cur_lh)
                cur_key = None
                cur_lf = None
                cur_lh = None
            # every other record type (FN:/FNDA:/FNF:/FNH:/BRDA:/BRF:/BRH:/
            # DA:/VER:/TN:) is deliberately ignored -- this gate is line
            # coverage only.
    if cur_key is not None:
        _fatal(f"{path}: file ends mid-record (SF: {cur_key!r} with no closing end_of_record)")
    if not per_file:
        _fatal(f"{path}: no SF: records found at all -- empty or malformed extracted .info")
    return per_file


def _key_of(sf_path: str, path: str, lineno: int) -> str:
    marker = "src/sello/"
    idx = sf_path.rfind(marker)
    if idx == -1:
        _fatal(
            f"{path}:{lineno}: SF: path {sf_path!r} has no 'src/sello/' segment -- "
            "the caller's own lcov --extract pattern should make this unreachable; "
            "investigate rather than silently dropping this file from the pinned set."
        )
    return sf_path[idx + len(marker):]


def _floor_pct_x10(lh: int, lf: int) -> int:
    """floor(lh/lf*1000) via exact integer floor division -- see the
    module doc comment's FLOOR-TO-ONE-DECIMAL section for why this must
    not go through a float at all."""
    if lf == 0:
        return 1000
    return (lh * 1000) // lf


def _fmt_pct(x10: int) -> str:
    return f"{x10 // 10}.{x10 % 10}"


def _fatal(msg: str) -> None:
    print(f"coverage_report_gen: FATAL: {msg}", file=sys.stderr)
    sys.exit(1)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: coverage_report_gen.py <extracted.info>", file=sys.stderr)
        return 2
    info_path = argv[1]
    per_file = parse_info(info_path)

    total_lf = 0
    total_lh = 0
    for key, (lf, lh) in per_file.items():
        if lf == 0:
            print(f"coverage_report_gen: WARNING: {key!r} has LF:0 (no coverable lines extracted) -- treating as 100.0%", file=sys.stderr)
        total_lf += lf
        total_lh += lh

    lines = [f"aggregate {_fmt_pct(_floor_pct_x10(total_lh, total_lf))}"]
    for key in sorted(per_file.keys()):
        lf, lh = per_file[key]
        lines.append(f"{key} {_fmt_pct(_floor_pct_x10(lh, lf))}")

    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
