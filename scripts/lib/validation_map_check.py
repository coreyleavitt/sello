#!/usr/bin/env python3
"""scripts/lib/validation_map_check.py -- RFC-005 slice 31: the actual
parser+assertions behind the "validation-map" CI check
(scripts/validation-map-check.sh is the thin bash entry point that execs
this). Invoked with no arguments from the repo root.

WHAT THIS CHECKS (RFC-005 Part B's evidence-story paragraph, round-2
corrections (i)-(iii), plus this slice's own (b)/(c)/(d) scope):

  (i) The categorized validation-map table in README.md's Validation
      section (between the VALIDATION-MAP:TABLE markers) -- one row per
      CLAUDE.md "validation bar" claim (or claim/mechanism pair, where a
      claim is enforced by more than one category of mechanism -- e.g.
      the dudect harness is BOTH a required-check, compile-smoke-only,
      row AND a manual-ritual, real-verdict, row). Each row carries a
      Category (required-check / nightly / manual-ritual) and the
      per-category assertion the RFC's round-2 correction (i) demands:
        - required-check: the Mechanism cell's job name exists in
          .github/workflows/merge-gate.yml AND scripts/lib/gates.txt.
          (Not re-querying the live GitHub ruleset here too: the
          ruleset's required-check set is GENERATED from gates.txt by
          scripts/ruleset-apply.sh, and scripts/ruleset-sync-check.sh
          already asserts live-ruleset-matches-gates.txt on every push --
          re-deriving that same fact here would duplicate a check that
          already exists rather than add coverage.)
        - nightly: the Mechanism cell's job name exists in
          .github/workflows/nightly.yml.
        - manual-ritual: the Freshness-canary cell names something real
          -- a committed file (existence-checked), a "pending slice N"
          marker validated against the committed
          scripts/lib/validation-map-pending.txt allowlist, or one of
          the small, hardcoded NONE_BY_DESIGN_ROWKEYS below (a ritual
          the RFC never demanded a freshness canary for at all).

  (ii) Badge-URL branch-pin: every "badge.svg" URL in README.md carries
       "?branch=main" (an unpinned badge reflects the latest run on ANY
       branch, not main's own state); the toolchain-canary workflow
       carries NO badge anywhere in README.md (advisory-only, so a red
       canary run must never render as a public-looking failure).

  (iii) Platform-support claim (between the VALIDATION-MAP:PLATFORM
        markers): every backtick-quoted job name inside the block exists
        in scripts/lib/gates.txt AND the merge-gate workflow (the "tie
        the claim to the matrix mechanically where cheap" instruction --
        cheap here because it's the identical existence check the
        required-check table rows already need); the WASM
        unsupported-for-secrets disclosure is present (a plain substring
        check, not a semantic one).

  (iv) CT compiler-scope claim (between the VALIDATION-MAP:CT-SCOPE
       markers): the gcc/clang version strings and image digest named in
       the README prose match what scripts/lib/image-pins.txt's
       production toolchain-versions section actually records -- the pin
       file is the source of truth; this keeps the README's prose COPY
       of those numbers from drifting off it silently. The
       consumer-compiles-their-own-toolchain disclosure sentence is
       checked only for presence (a substring match), not content --
       recorded here as the honest boundary: the disclosure's accuracy
       is hand-maintained, same as every other prose sentence in this
       section.

PARSE METHOD, and its own honesty requirement (matching
gates-manifest-check.sh's "two independent extractions cross-checked"
register, applied here as "any row/cell shape this parser doesn't
recognize is a PARSE SURPRISE, not a silent skip"): the table is ordinary
GitHub markdown between two HTML-comment markers; this is a light,
single-pass split on the table's own `|`-delimited row shape, not a real
markdown-table engine -- cell text is written to avoid literal `|`
characters specifically so this trade-off holds (this project's standing
"hand-written YAML/markdown, no templater with no other customer"
precedent, restated for a markdown table instead of a workflow file).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

README = REPO_ROOT / "README.md"
GATES_TXT = REPO_ROOT / "scripts" / "lib" / "gates.txt"
MERGE_GATE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "merge-gate.yml"
NIGHTLY_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "nightly.yml"
IMAGE_PINS = REPO_ROOT / "scripts" / "lib" / "image-pins.txt"
PENDING_ALLOWLIST = REPO_ROOT / "scripts" / "lib" / "validation-map-pending.txt"

TABLE_START = "<!-- VALIDATION-MAP:TABLE START -->"
TABLE_END = "<!-- VALIDATION-MAP:TABLE END -->"
PLATFORM_START = "<!-- VALIDATION-MAP:PLATFORM START -->"
PLATFORM_END = "<!-- VALIDATION-MAP:PLATFORM END -->"
CTSCOPE_START = "<!-- VALIDATION-MAP:CT-SCOPE START -->"
CTSCOPE_END = "<!-- VALIDATION-MAP:CT-SCOPE END -->"

VALID_CATEGORIES = {"required-check", "nightly", "manual-ritual"}

EXPECTED_COLUMNS = 6  # Claim | Category | Mechanism | Freshness canary | Carve-out doc | Row key

# Manual-ritual rows the RFC never demanded a freshness canary for at all
# (re-read against docs/rfc-005-validation-infra.md's evidence-story text,
# lines 899-929 and the A5/timing-tier paragraphs it cross-references:
# only the fuzz corpus (A5) and the dudect timing tier get an explicit
# freshness-canary requirement). Mutation and the bmc/symex proof register
# are both deterministic GIVEN the source tree -- they either match the
# current code or they don't, with no calendar-staleness concept of their
# own -- and are re-run per the standing escalation rule (CLAUDE.md: "a
# surfaced core-arithmetic bug closes the infra slice red... the full
# affected-gate battery") whenever a change touches their scope, not on a
# schedule. This is a recorded DESIGN decision, not a placeholder for a
# future canary -- a row-key landing here says "no canary is owed," full
# stop.
#
# libsodium-interop LEFT this set in RFC-005 slice 14: that row moved from
# manual-ritual to required-check (unit-linux-amd64-gcc-libsodium), which
# carries no Freshness-canary cell at all (required-check rows are
# asserted "n/a" -- see check_table_rows below), so it no longer needs an
# entry here. mutation-catalog and bmc-symex LEFT this set the same way in
# RFC-005 slice 15: both rows moved from manual-ritual to required-check
# (`mutation` and `bmc-symex` respectively), once each gate's own real
# hosted wall-clock cost was measured and its heavy-gate placement decided
# (see CLAUDE.md's own "Mutation + bmc jobs" CI paragraph).
NONE_BY_DESIGN_ROWKEYS = set()

errors: list[str] = []


def fail(msg: str) -> None:
    errors.append(msg)


def read(path: Path) -> str:
    if not path.is_file():
        fail(f"missing file: {path.relative_to(REPO_ROOT)}")
        return ""
    return path.read_text()


def extract_block(text: str, start: str, end: str, label: str) -> str | None:
    if text.count(start) != 1:
        fail(f"{label}: expected exactly one '{start}' marker in README.md, found {text.count(start)}")
        return None
    if text.count(end) != 1:
        fail(f"{label}: expected exactly one '{end}' marker in README.md, found {text.count(end)}")
        return None
    start_idx = text.index(start) + len(start)
    end_idx = text.index(end)
    if end_idx < start_idx:
        fail(f"{label}: '{end}' marker appears before its '{start}' marker")
        return None
    return text[start_idx:end_idx]


def extract_job_names(path: Path) -> set[str]:
    """Job keys directly under the top-level `jobs:` key, 2-space
    indented -- the same light awk-equivalent scan
    scripts/lib/workflow-job-names.sh's extract_workflow_job_names uses
    for merge-gate.yml (that function's own header has the full
    parse-method writeup; this is its python-side sibling, applied here
    to both merge-gate.yml and nightly.yml rather than shelling out to
    bash for a second file the existing function was never scoped to)."""
    if not path.is_file():
        fail(f"missing workflow file: {path.relative_to(REPO_ROOT)}")
        return set()
    names: set[str] = set()
    in_jobs = False
    for line in path.read_text().splitlines():
        if re.match(r"^jobs:\s*$", line):
            in_jobs = True
            continue
        if in_jobs and re.match(r"^\S", line):
            break
        if in_jobs:
            m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
            if m:
                names.add(m.group(1))
    return names


def gates_check_names(path: Path) -> set[str]:
    if not path.is_file():
        fail(f"missing gates manifest: {path.relative_to(REPO_ROOT)}")
        return set()
    names: set[str] = set()
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        names.add(line.split(maxsplit=1)[0])
    return names


def load_pending_allowlist(path: Path) -> dict[str, str]:
    """row-key -> slice-number, both as committed."""
    if not path.is_file():
        fail(f"missing pending-canary allowlist: {path.relative_to(REPO_ROOT)}")
        return {}
    out: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2:
            fail(f"validation-map-pending.txt: malformed line (want '<row-key> <slice-number>'): {line!r}")
            continue
        out[parts[0]] = parts[1]
    return out


def split_table_row(line: str) -> list[str] | None:
    line = line.strip()
    if not line.startswith("|") or not line.endswith("|"):
        return None
    cells = line[1:-1].split("|")
    return [c.strip() for c in cells]


def is_separator_row(cells: list[str]) -> bool:
    return all(re.fullmatch(r":?-{2,}:?", c) for c in cells)


def parse_table(block: str) -> list[list[str]]:
    rows: list[list[str]] = []
    data_rows_seen = 0
    header_seen = False
    separator_seen = False
    for raw_line in block.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        cells = split_table_row(line)
        if cells is None:
            fail(f"validation-map table: line inside the TABLE markers is not a '|'-delimited row: {line!r}")
            continue
        if not header_seen:
            header_seen = True
            if len(cells) != EXPECTED_COLUMNS:
                fail(f"validation-map table: header row has {len(cells)} column(s), expected {EXPECTED_COLUMNS}: {cells!r}")
            continue
        if not separator_seen:
            separator_seen = True
            if not is_separator_row(cells):
                fail(f"validation-map table: expected a markdown separator row ('---' cells) immediately after the header, got: {cells!r}")
            continue
        if len(cells) != EXPECTED_COLUMNS:
            fail(f"validation-map table: data row has {len(cells)} column(s), expected {EXPECTED_COLUMNS}: {cells!r}")
            continue
        rows.append(cells)
        data_rows_seen += 1
    if data_rows_seen == 0:
        fail("validation-map table: zero data rows found between the TABLE markers")
    return rows


def first_backtick_token(cell: str) -> str | None:
    m = re.search(r"`([^`]+)`", cell)
    return m.group(1) if m else None


def check_table_rows(rows: list[list[str]], gate_names: set[str], mg_job_names: set[str],
                      nightly_job_names: set[str], pending: dict[str, str]) -> None:
    seen_keys: set[str] = set()
    for cells in rows:
        claim, category, mechanism, freshness, carveout, rowkey = cells

        if not rowkey:
            fail(f"validation-map table: row {claim!r} has an empty Row key cell")
            continue
        if rowkey in seen_keys:
            fail(f"validation-map table: duplicate Row key {rowkey!r}")
        seen_keys.add(rowkey)

        if category not in VALID_CATEGORIES:
            fail(f"validation-map table: row {rowkey!r} has Category {category!r}, not one of {sorted(VALID_CATEGORIES)}")
            continue

        # Carve-out doc column: "none", or a backtick-quoted committed path.
        if carveout != "none":
            token = first_backtick_token(carveout)
            if token is None:
                fail(f"validation-map table: row {rowkey!r} Carve-out doc cell is neither 'none' nor backtick-quoted: {carveout!r}")
            elif not (REPO_ROOT / token).is_file():
                fail(f"validation-map table: row {rowkey!r} Carve-out doc references a missing file: {token}")

        if category in ("required-check", "nightly"):
            if freshness != "n/a":
                fail(f"validation-map table: row {rowkey!r} is category {category!r} but Freshness canary cell is {freshness!r}, expected 'n/a' (only manual-ritual rows carry a freshness canary)")
            job = first_backtick_token(mechanism)
            if job is None:
                fail(f"validation-map table: row {rowkey!r} ({category}) Mechanism cell has no backtick-quoted job name: {mechanism!r}")
                continue
            if category == "required-check":
                if job not in gate_names:
                    fail(f"validation-map table: row {rowkey!r} names required-check job {job!r}, not present in scripts/lib/gates.txt")
                if job not in mg_job_names:
                    fail(f"validation-map table: row {rowkey!r} names required-check job {job!r}, not present in {MERGE_GATE_WORKFLOW.relative_to(REPO_ROOT)}")
            else:  # nightly
                if job not in nightly_job_names:
                    fail(f"validation-map table: row {rowkey!r} names nightly job {job!r}, not present in {NIGHTLY_WORKFLOW.relative_to(REPO_ROOT)}")
                if job in gate_names:
                    fail(f"validation-map table: row {rowkey!r} names {job!r} as a nightly job, but it is ALSO a required-check in scripts/lib/gates.txt -- pick the category that matches where it actually gates")
            continue

        # category == "manual-ritual": the Freshness canary cell is the
        # one load-bearing, mechanically-checked field.
        if freshness == "n/a":
            fail(f"validation-map table: row {rowkey!r} is manual-ritual but Freshness canary cell is 'n/a' -- every manual-ritual row must declare a real canary, a committed 'pending slice N' marker, or an explicit 'none (by design)'")
            continue

        m_pending = re.match(r"^pending slice (\d+)\b", freshness)
        if m_pending:
            slice_no = m_pending.group(1)
            allow_slice = pending.get(rowkey)
            if allow_slice is None:
                fail(f"validation-map table: row {rowkey!r} claims {freshness!r}, but has no entry in scripts/lib/validation-map-pending.txt")
            elif allow_slice != slice_no:
                fail(f"validation-map table: row {rowkey!r} claims 'pending slice {slice_no}', but scripts/lib/validation-map-pending.txt records slice {allow_slice} -- table and allowlist disagree")
            continue

        if freshness.startswith("none (by design)"):
            if rowkey not in NONE_BY_DESIGN_ROWKEYS:
                fail(f"validation-map table: row {rowkey!r} claims 'none (by design)', but is not in this script's hardcoded NONE_BY_DESIGN_ROWKEYS set -- either the row-key is wrong, or a genuinely new no-canary-by-design row needs that set updated deliberately")
            continue

        token = first_backtick_token(freshness)
        if token is None:
            fail(f"validation-map table: row {rowkey!r} (manual-ritual) Freshness canary cell is not 'n/a', 'pending slice N', 'none (by design)', or a backtick-quoted path: {freshness!r}")
            continue
        if not (REPO_ROOT / token).is_file():
            fail(f"validation-map table: row {rowkey!r} Freshness canary references a missing file: {token}")

    # Any row-key committed to the pending allowlist that the table no
    # longer references is itself drift (a stale allowlist entry for a
    # row that got renamed, recategorized, or removed).
    unused_pending = set(pending) - seen_keys
    if unused_pending:
        fail(f"validation-map-pending.txt has entr{'y' if len(unused_pending) == 1 else 'ies'} for row-key(s) not present in the README table: {sorted(unused_pending)}")


def check_badges(full_readme: str) -> None:
    for line in full_readme.splitlines():
        if "badge.svg" not in line:
            continue
        if "?branch=main" not in line:
            fail(f"README.md badge line missing '?branch=main': {line.strip()!r}")
        if "toolchain-canary.yml" in line:
            fail(f"README.md carries a badge for toolchain-canary.yml, which must stay unbadged (advisory-only): {line.strip()!r}")


def check_platform_block(full_readme: str, gate_names: set[str], mg_job_names: set[str]) -> None:
    block = extract_block(full_readme, PLATFORM_START, PLATFORM_END, "platform claim")
    if block is None:
        return
    job_tokens = re.findall(r"`([a-zA-Z0-9_-]+)`", block)
    matrix_like = [t for t in job_tokens if t.startswith("unit-") or t.startswith("property-")]
    if not matrix_like:
        fail("validation-map platform block: no backtick-quoted CI-matrix job names found inside the PLATFORM markers")
    for job in matrix_like:
        if job not in gate_names:
            fail(f"validation-map platform block: names job {job!r}, not present in scripts/lib/gates.txt")
        if job not in mg_job_names:
            fail(f"validation-map platform block: names job {job!r}, not present in {MERGE_GATE_WORKFLOW.relative_to(REPO_ROOT)}")
    if "WASM" not in block or "unsupported-for-secrets" not in block:
        fail("validation-map platform block: missing the WASM unsupported-for-secrets disclosure")


def parse_image_pins_toolchain(text: str) -> tuple[str | None, str | None, str | None]:
    """Returns (image_digest_hex, gcc_version, clang_version) as recorded
    in scripts/lib/image-pins.txt's PRODUCTION observation (the first
    occurrence of each -- the file's later 'for comparison' block
    intentionally records DRIFTED values under the same gcc:/clang:
    labels, and re.search's first-match semantics select the production
    line specifically because it appears earlier in the file)."""
    digest_m = re.search(r"ghcr\.io/coreyleavitt/nim@sha256:([0-9a-f]{64})", text)
    gcc_m = re.search(r"^#\s+gcc:\s+gcc \(SUSE Linux\) (\S+)", text, re.MULTILINE)
    clang_m = re.search(r"^#\s+clang:\s+clang version (\S+)", text, re.MULTILINE)
    return (
        digest_m.group(1) if digest_m else None,
        gcc_m.group(1) if gcc_m else None,
        clang_m.group(1) if clang_m else None,
    )


def check_ct_scope_block(full_readme: str, image_pins_text: str) -> None:
    block = extract_block(full_readme, CTSCOPE_START, CTSCOPE_END, "CT compiler-scope claim")
    if block is None:
        return
    digest, gcc_version, clang_version = parse_image_pins_toolchain(image_pins_text)
    if digest is None or gcc_version is None or clang_version is None:
        fail("validation-map CT-scope block: could not parse gcc/clang version or image digest out of scripts/lib/image-pins.txt's production toolchain-versions section")
        return
    if gcc_version not in block:
        fail(f"validation-map CT-scope block: does not mention gcc version {gcc_version!r} (scripts/lib/image-pins.txt's recorded value)")
    if clang_version not in block:
        fail(f"validation-map CT-scope block: does not mention clang version {clang_version!r} (scripts/lib/image-pins.txt's recorded value)")
    if digest not in block:
        fail(f"validation-map CT-scope block: does not mention the pinned image digest {digest!r} (scripts/lib/image-pins.txt's recorded value)")
    if "own" not in block.lower() or "toolchain" not in block.lower():
        fail("validation-map CT-scope block: missing the consumer-compiles-their-own-toolchain disclosure (a plain presence check only -- its accuracy is hand-maintained)")


def main() -> int:
    readme_text = read(README)
    gate_names = gates_check_names(GATES_TXT)
    mg_job_names = extract_job_names(MERGE_GATE_WORKFLOW)
    nightly_job_names = extract_job_names(NIGHTLY_WORKFLOW)
    pending = load_pending_allowlist(PENDING_ALLOWLIST)
    image_pins_text = read(IMAGE_PINS)

    if readme_text:
        table_block = extract_block(readme_text, TABLE_START, TABLE_END, "validation-map table")
        if table_block is not None:
            rows = parse_table(table_block)
            if rows:
                check_table_rows(rows, gate_names, mg_job_names, nightly_job_names, pending)

        check_badges(readme_text)
        check_platform_block(readme_text, gate_names, mg_job_names)
        if image_pins_text:
            check_ct_scope_block(readme_text, image_pins_text)

    if errors:
        print("validation-map-check: FAIL", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        print(f"validation-map-check: {len(errors)} problem(s) found.", file=sys.stderr)
        return 1

    print("validation-map-check: OK -- README.md's validation-map table, badges, platform claim, and CT compiler-scope claim all check out against scripts/lib/gates.txt, the merge-gate/nightly workflows, and scripts/lib/image-pins.txt.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
