#!/usr/bin/env python3
"""scripts/lib/taint_anchor_check.py -- RFC-005 slice 22 (A1 CI wiring):
the taint declassification register's doc-anchor drift check.

`src/sello/private/taint.nim`'s `declassRegister` and every citing module's
own `## Cites: <DeclassId>` doc-comment line are two independently
hand-maintained copies of the same fact ("this DeclassId is sanctioned at
this call site") -- nothing in the Nim compiler enforces they agree, since
`Cites: <id>` is unstructured text inside a `##` doc comment, not real Nim
code a typo'd id would fail to compile. This script is the emitter +
checker A1's own text calls for: a trivial data query over the register,
run standalone or as a step of `scripts/ct-taint.sh`.

ANCHOR SYNTAX (defined precisely here, since slices 19/21 left `anchor`
as a free-form string): `<module>.<name>`, where

  - `<module>` is a source module id resolved against
    `src/sello/<module>.nim` or `src/sello/private/<module>.nim` (e.g.
    "backend" -> `src/sello/private/backend.nim`, "x25519" ->
    `src/sello/x25519.nim`), OR the fixed literal `ct_taint` for the two
    entries whose disclosure has no interior `src/sello/` call site at
    all (`diRistrettoEncodeOutput`, `diSha512DigestKat` -- see those
    entries' own `rationale` fields) -- resolved instead against
    `tests/ct_taint/<name>.nim`, the taint TARGET that declassifies.

  - `<name>` is the proc/func/template/converter identifier as written in
    Nim source, including backtick-operator form verbatim (e.g.
    `` `==` ``).

TWO DIRECTIONS, both checked, each failing loud with the exact missing
id/anchor (never a silent skip):

  (i)  register -> docs. For every `declassRegister` entry whose module
       resolves under `src/sello/`, the named module file must contain a
       `## Cites: <id>` line whose nearest preceding non-blank line is a
       `proc`/`func`/`template`/`converter`/`method` signature containing
       `<name>` as a substring (matches this codebase's own observed
       convention: `Cites:` is always the doc comment's own first line,
       immediately after the signature). For a `ct_taint.<name>` anchor,
       the resolved target file must contain a real
       `declassify(<id>, ...)` call (the anchor names the taint TARGET
       precisely because no `Cites:` convention applies there -- see
       `taint.nim`'s own register-entry rationale for these two ids).

  (ii) docs -> register. Every `## Cites: <token>` line found anywhere
       under `src/sello/` must name a real `DeclassId` (a member of the
       live enum, not a typo), AND that id's own register `anchor` must
       point back at the SAME module the citing line was found in --
       catching both an unknown id and an id cited from the wrong module
       (e.g. a copy-pasted `Cites:` line left over from a different
       proc's disclosure).

Usage:
  python3 scripts/lib/taint_anchor_check.py
    # prints the register as TSV (id, anchor, width, buildCondition) to
    # stdout, then runs both directions; exit 0 with an OK summary on
    # success, exit 1 with every failure named on stderr otherwise.

No Nim compiler needed -- this is a static text scan over
`private/taint.nim`'s own `DeclassId`/`declassRegister` source (the same
"light, single-pass, hand-written-source" register `scripts/ct-taint.sh`'s
own existing `secret_targets.nim` scan already precedents), not a
compiled probe: the register's `DeclassId`/`DeclassEntry` types stay
outside the `when defined(selloTaint)` block in `taint.nim`, so a real
`nim c -r` dump was considered and declined as unnecessary machinery for
a "~10-line emitter" per A1's own text.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TAINT_NIM = REPO_ROOT / "src" / "sello" / "private" / "taint.nim"
SRC_SELLO = REPO_ROOT / "src" / "sello"
CT_TAINT_DIR = REPO_ROOT / "tests" / "ct_taint"

CITES_RE = re.compile(r'^\s*##\s*Cites:\s*(\w+)')
SIGNATURE_KEYWORD_RE = re.compile(r'\b(proc|func|template|converter|method)\b')


def fail(msg: str) -> None:
    sys.stderr.write(f"taint-anchor-check: FAIL -- {msg}\n")
    sys.exit(1)


def load_ids(text: str) -> list[str]:
    m = re.search(
        r'DeclassId\*\s*=\s*enum\b(.*?)\n\s*DeclassWidth\*\s*=\s*enum',
        text, re.S)
    if not m:
        fail("could not locate the 'DeclassId* = enum ... DeclassWidth* = enum' "
             "block in taint.nim -- has the enum's own shape changed?")
    ids = re.findall(r'^\s{4}(di\w+)\s*$', m.group(1), re.M)
    if not ids:
        fail("DeclassId enum block located but no 'di'-prefixed members "
             "extracted from it -- regex/formatting drift?")
    return ids


def load_register(text: str) -> list[dict]:
    m = re.search(
        r'declassRegister\*:\s*array\[DeclassId,\s*DeclassEntry\]\s*=\s*\[(.*?)\n\]\n',
        text, re.S)
    if not m:
        fail("could not locate declassRegister's array literal in taint.nim")
    body = m.group(1)
    parts = re.split(r'\n {2}(di\w+): DeclassEntry\(', body)
    entries = []
    it = iter(parts[1:])
    for name, block in zip(it, it):
        idm = re.search(r'\bid:\s*(di\w+),', block)
        anchorm = re.search(r'\banchor:\s*"([^"]*)"', block)
        widthm = re.search(r'\bwidth:\s*(dw\w+),', block)
        condm = re.search(r'\bbuildCondition:\s*"([^"]*)"', block)
        if not (idm and anchorm and widthm):
            fail(f"could not parse a complete DeclassEntry block for '{name}' "
                 "(missing id:/anchor:/width: field) -- schema drift?")
        entries.append({
            "id": idm.group(1),
            "anchor": anchorm.group(1),
            "width": widthm.group(1),
            "buildCondition": condm.group(1) if condm else "",
        })
    return entries


def resolve_module_files(module: str) -> list[Path]:
    candidates = [
        SRC_SELLO / f"{module}.nim",
        SRC_SELLO / "private" / f"{module}.nim",
    ]
    return [c for c in candidates if c.is_file()]


def cites_id_near_name(text: str, eid: str, name: str) -> bool:
    lines = text.split("\n")
    pattern = re.compile(r'^\s*##\s*Cites:\s*' + re.escape(eid) + r'\b')
    for i, line in enumerate(lines):
        if not pattern.match(line):
            continue
        # Walk backward for the nearest preceding signature-keyword line,
        # within a small bounded window -- a Nim proc/func signature can
        # wrap across two or more lines (e.g. backend.signDetached's own
        # multi-parameter header), so the name may sit on an earlier line
        # than the one immediately above the Cites: line. Every real
        # signature in this codebase is well within 6 lines of its own
        # doc comment's first line.
        j = i - 1
        window = []
        keyword_line_idx = None
        while j >= 0 and (i - j) <= 6:
            window.append(lines[j])
            if SIGNATURE_KEYWORD_RE.search(lines[j]):
                keyword_line_idx = j
                break
            j -= 1
        if keyword_line_idx is not None and any(name in w for w in window):
            return True
    return False


def check_forward(entries: list[dict]) -> list[str]:
    failures = []
    for e in entries:
        eid, anchor = e["id"], e["anchor"]
        if "." not in anchor:
            failures.append(f"{eid}: anchor {anchor!r} is not in <module>.<name> form")
            continue
        module, name = anchor.split(".", 1)
        if module == "ct_taint":
            target_file = CT_TAINT_DIR / f"{name}.nim"
            if not target_file.is_file():
                failures.append(
                    f"{eid}: anchor {anchor!r} names taint target "
                    f"{target_file.relative_to(REPO_ROOT)}, which does not exist")
                continue
            text = target_file.read_text()
            if not re.search(r'declassify\(\s*' + re.escape(eid) + r'\s*,', text):
                failures.append(
                    f"{eid}: anchor {anchor!r} -- no 'declassify({eid}, ...)' call "
                    f"found in {target_file.relative_to(REPO_ROOT)}")
            continue

        files = resolve_module_files(module)
        if not files:
            failures.append(
                f"{eid}: anchor {anchor!r} -- no src/sello module file resolves "
                f"module '{module}' (tried src/sello/{module}.nim, "
                f"src/sello/private/{module}.nim)")
            continue
        if len(files) > 1:
            failures.append(
                f"{eid}: anchor {anchor!r} -- ambiguous module '{module}', "
                f"multiple candidate files: "
                f"{[str(f.relative_to(REPO_ROOT)) for f in files]}")
            continue
        text = files[0].read_text()
        if not cites_id_near_name(text, eid, name):
            failures.append(
                f"{eid}: anchor {anchor!r} -- no '## Cites: {eid}' doc-comment "
                f"line immediately following a proc/func/template/converter/"
                f"method signature containing {name!r} in "
                f"{files[0].relative_to(REPO_ROOT)}")
    return failures


def check_backward(valid_ids: set[str], entries: list[dict]) -> list[str]:
    failures = []
    id_to_anchor = {e["id"]: e["anchor"] for e in entries}
    for path in sorted(SRC_SELLO.rglob("*.nim")):
        module = path.stem
        text = path.read_text()
        for lineno, line in enumerate(text.split("\n"), start=1):
            m = CITES_RE.match(line)
            if not m:
                continue
            token = m.group(1)
            rel = path.relative_to(REPO_ROOT)
            if token not in valid_ids:
                failures.append(
                    f"{rel}:{lineno}: cites unknown DeclassId '{token}' "
                    "(not a member of the live DeclassId enum -- typo, or a "
                    "renamed/removed id left stale?)")
                continue
            anchor = id_to_anchor.get(token, "")
            anchor_module = anchor.split(".", 1)[0] if "." in anchor else ""
            if anchor_module != module:
                failures.append(
                    f"{rel}:{lineno}: cites {token}, but its register anchor "
                    f"is {anchor!r} (module {anchor_module!r}), not this "
                    f"file's own module {module!r}")
    return failures


def main() -> None:
    if not TAINT_NIM.is_file():
        fail(f"{TAINT_NIM} not found")
    text = TAINT_NIM.read_text()

    ids = load_ids(text)
    entries = load_register(text)

    entry_ids = [e["id"] for e in entries]
    if len(entry_ids) != len(set(entry_ids)):
        fail("declassRegister has a duplicate id -- array[DeclassId, ...] "
             "completeness should make this impossible; regex-parse bug?")
    if sorted(entry_ids) != sorted(ids):
        missing = sorted(set(ids) - set(entry_ids))
        extra = sorted(set(entry_ids) - set(ids))
        fail(f"DeclassId enum and declassRegister disagree -- missing entries: "
             f"{missing}, unknown entries: {extra}")

    print("id\tanchor\twidth\tbuildCondition")
    for e in entries:
        print(f"{e['id']}\t{e['anchor']}\t{e['width']}\t{e['buildCondition']}")

    failures = check_forward(entries) + check_backward(set(ids), entries)

    if failures:
        sys.stderr.write(
            f"taint-anchor-check: FAIL -- {len(failures)} anchor/citation "
            "mismatch(es):\n")
        for f in failures:
            sys.stderr.write(f"  - {f}\n")
        sys.exit(1)

    scanned = sum(1 for _ in SRC_SELLO.rglob("*.nim"))
    sys.stderr.write(
        f"taint-anchor-check: OK -- {len(entries)} declassRegister entries all "
        f"anchor-grounded (register -> docs); {scanned} src/sello/*.nim modules "
        "scanned, every 'Cites:' line names a real, correctly-anchored "
        "DeclassId (docs -> register).\n")


if __name__ == "__main__":
    main()
