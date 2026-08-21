#!/usr/bin/env python3
"""sello mutation-testing driver (RFC-002 slice 5).

Runs INSIDE the base Nim toolchain container, invoked by
`scripts/mutation.sh` -- never on the host, and never against the real
working tree. Layout (see also docs/mutation-results.md's methodology
section):

  tests/mutation/mutants/*.mutant            -- the curated, ACTIVE catalog:
                                                 one plain-text file per
                                                 mutant, executed and
                                                 counted toward the gate.
  tests/mutation/mutants/equivalent/*.mutant -- mutants retired as
                                                 confirmed-equivalent (see
                                                 load_equivalent()'s doc
                                                 comment below): NOT
                                                 executed, NOT counted
                                                 toward the gate, listed in
                                                 the report for
                                                 transparency.
  tests/mutation/run_mutation.py             -- this driver.
  scripts/mutation.sh                        -- host-side wrapper (podman
                                                 invocation, milpa
                                                 preflight, forwards the
                                                 unit test file list).

Mutant file format -- exact-string patch, not a unified/context diff:

    id: <short id, unique across the catalog>
    target: <path to the mutated file, relative to the repo root>
    desc: <one-line description of the semantic change, for the report>
    ====OLD====
    <exact source text, one or more lines, indentation preserved>
    ====NEW====
    <replacement text>
    ====END====

`OLD` must appear in `target`'s CURRENT content verbatim, EXACTLY ONCE.
This is deliberate (per the RFC): an exact-string match fails loudly, with
an unambiguous "0 occurrences" or ">1 occurrences" error, the moment the
real source drifts out from under a mutant, rather than silently
mis-applying via a fuzzy context-diff match to the wrong spot (or a stale
one) the way a unified diff with fuzz tolerance can. Every catalog entry is
verified unique against the real source at generation time (see the
catalog's own history) and is re-verified here on every run, since that is
the only way "the source drifted" can be told apart from "the mutant file
is simply wrong".

Method: for each mutant, in isolation --
  1. Reset every file the WHOLE catalog can touch (not just this mutant's
     own target) to its pristine, real-working-tree content, in the
     scratch copy -- this is what stops mutant N+1 from silently
     compounding on top of mutant N's leftover edit in the scratch tree.
  2. Apply exactly this one mutant's OLD -> NEW replacement.
  3. Compile and run the FULL unit suite (the same file list
     `scripts/test.sh` uses, sourced from scripts/lib/unit-test-files.sh
     and forwarded as argv here -- one source of truth, not a second
     hand-typed copy) against the mutated scratch copy.
  4. Classify:
       KILLED (compile-error) -- some test file failed to even compile.
         A compile-error kill proves nothing about the TEST SUITE's
         sensitivity (the mutant never got a chance to run), so the
         report counts it separately and honestly rather than folding it
         into the same bucket as a real red-suite kill.
       KILLED (test) -- all files compiled but at least one test failed
         (red suite): the suite's assertions actually caught the mutant.
       KILLED (timeout) -- the compile+run invocation for one file did not
         finish within PER_FILE_TIMEOUT_SECONDS. A mutant that hangs the
         suite (e.g. one that turns a bounded loop unbounded, or breaks
         termination of a compile-time-evaluated computation like the base
         table) is detected and counted as killed, not silently left to
         stall the whole campaign forever with no diagnostic -- reported
         separately from the other two KILLED buckets, same honesty
         standard as the compile-error/test-red split, since a timeout
         kill proves the mutant is observably wrong (it never produced a
         clean green run) without saying anything about which assertion
         (if any) would have caught it.
       SURVIVED -- every file compiled AND every test passed: the suite
         did not notice this mutant at all. A coverage-gap finding,
         handled in-slice per the RFC (a new test gets added to kill it,
         and this harness gets re-run to confirm).
  Short-circuits on the first failing file (compile or test) once a
  mutant is already provably killed -- for a curated catalog (84 mutants
  as of RFC-006 slice 4) with an otherwise-thorough suite, most mutants
  die early and this matters for wall clock; a SURVIVED verdict still
  requires running every file (nothing short of the whole suite passing
  green earns that verdict).

Never touches the real working tree: everything above operates on a
throwaway copy under /tmp inside the container, made once at startup and
reused (mutate-restore in place) across the whole campaign -- reusing the
scratch copy (rather than re-cloning the repo per mutant) is what lets the
Nim compiler's own nimcache carry unrelated dependencies (proptest and its
own transitive deps, when fetched -- sello resolves no unconditional
dependency at all as of RFC-006) across mutants within the one container
invocation, instead of paying their full compile cost once per mutant.
"""
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import time

REPO_ROOT = pathlib.Path("/workspace")
SCRATCH = pathlib.Path("/tmp/sello-mutation-src")
MUTANTS_DIR = REPO_ROOT / "tests/mutation/mutants"
REPORT_PATH = REPO_ROOT / "docs/mutation-results.md"
NIM_BIN = "nim"

# Per-file `nim c -r` wall-clock bound. A normal compile+run of one unit
# test file, even the heavier property/Wycheproof ones, finishes well
# under a couple of minutes on this project's own measured numbers (see
# scripts/mutation.sh's header comment: ~1.5s-40s per mutant for the WHOLE
# suite, short-circuiting on first failure). 300s is a generous multiple
# of that per-file cost, not a tight bound -- the goal is to catch a
# genuinely non-terminating mutant (a bounded loop turned unbounded, or a
# compile-time-evaluated computation like the base table that stops
# terminating), not to race normal variance. Contrast scripts/bmc.sh,
# which needs `timeout --signal=KILL` for the same reason (its subprocess,
# Z3, can hang indefinitely).
PER_FILE_TIMEOUT_SECONDS = 300


class Mutant:
    def __init__(self, path: pathlib.Path):
        self.path = path
        text = path.read_text()
        lines = text.split("\n")
        header = {}
        i = 0
        while i < len(lines) and lines[i].strip() != "====OLD====":
            line = lines[i]
            if line.strip() == "":
                i += 1
                continue
            if ":" not in line:
                raise ValueError(f"{path}: malformed header line: {line!r}")
            key, _, val = line.partition(":")
            header[key.strip()] = val.strip()
            i += 1
        if i >= len(lines):
            raise ValueError(f"{path}: missing '====OLD====' marker")
        i += 1
        old_lines = []
        while i < len(lines) and lines[i].strip() != "====NEW====":
            old_lines.append(lines[i])
            i += 1
        if i >= len(lines):
            raise ValueError(f"{path}: missing '====NEW====' marker")
        i += 1
        new_lines = []
        while i < len(lines) and lines[i].strip() != "====END====":
            new_lines.append(lines[i])
            i += 1
        if i >= len(lines):
            raise ValueError(f"{path}: missing '====END====' marker")
        for required in ("id", "target", "desc"):
            if required not in header:
                raise ValueError(f"{path}: missing '{required}:' header field")
        self.id = header["id"]
        self.target = header["target"]
        self.desc = header["desc"]
        self.note = header.get("note", "")
        # Re-join with the newlines the split-on-"\n" swallowed; every OLD/NEW
        # block in the catalog ends with its own trailing newline before the
        # next marker, so this reconstructs the exact original text.
        self.old = "\n".join(old_lines) + "\n" if old_lines else ""
        self.new = "\n".join(new_lines) + "\n" if new_lines else ""

    def apply(self, scratch_root: pathlib.Path):
        target_path = scratch_root / self.target
        src = target_path.read_text()
        count = src.count(self.old)
        if count == 0:
            raise RuntimeError(
                f"{self.id}: OLD block not found in {self.target} "
                f"(0 occurrences -- source has drifted out from under this "
                f"mutant; fix or retire {self.path.name})"
            )
        if count > 1:
            raise RuntimeError(
                f"{self.id}: OLD block is not unique in {self.target} "
                f"({count} occurrences -- needs more context to target one "
                f"exact spot; fix {self.path.name})"
            )
        target_path.write_text(src.replace(self.old, self.new, 1))


def load_catalog():
    # Non-recursive glob: tests/mutation/mutants/equivalent/ (retired,
    # confirmed-equivalent mutants -- see load_equivalent() below) is a
    # subdirectory and is deliberately NOT picked up here, so it never
    # counts toward the active gate.
    paths = sorted(MUTANTS_DIR.glob("*.mutant"))
    if not paths:
        sys.exit(f"run_mutation: no *.mutant files found under {MUTANTS_DIR}")
    return [Mutant(p) for p in paths]


def load_equivalent():
    """Mutants retired as confirmed-equivalent (tests/mutation/mutants/equivalent/).

    These are NOT applied or compiled -- they are catalog entries someone
    (a person, or a prior run of this harness's own investigation) proved
    behaviorally indistinguishable from the real source across its whole
    documented input domain, so re-running them would only re-demonstrate
    a SURVIVED verdict that isn't a coverage gap. They stay in the repo,
    with their evidence recorded in their own `note:` header field, and
    are listed in the report for transparency rather than silently
    deleted -- see docs/mutation-results.md's "Retired (equivalent)
    mutants" section.
    """
    equiv_dir = MUTANTS_DIR / "equivalent"
    if not equiv_dir.is_dir():
        return []
    return [Mutant(p) for p in sorted(equiv_dir.glob("*.mutant"))]


def prepare_scratch():
    if SCRATCH.exists():
        shutil.rmtree(SCRATCH)

    def ignore(dirpath, names):
        # build/ is compiler output, irrelevant to the source under test and
        # sizeable; skipping it keeps the initial copy fast. Everything else
        # (including _deps/'s symlinks, copied as symlinks via symlinks=True
        # below) comes along -- see the module doc comment on why relative
        # _deps/ symlinks resolve correctly regardless of scratch depth.
        return {"build"} if pathlib.Path(dirpath) == REPO_ROOT else set()

    shutil.copytree(REPO_ROOT, SCRATCH, symlinks=True, ignore=ignore)


def reset_targets(targets):
    for rel in targets:
        shutil.copyfile(REPO_ROOT / rel, SCRATCH / rel)


def run_one_file(test_file: str, log_path: pathlib.Path) -> tuple[str, bool]:
    """Compile+run one unit test file against the current scratch tree.

    Returns (status, compiled):
      status is "ok" (compiled AND every test passed), "fail" (ran to
        completion but exited nonzero), or "timeout" (did not finish
        within PER_FILE_TIMEOUT_SECONDS and was killed).
      compiled is True iff a binary was produced and executed at all
        (distinguishes a compile-error kill from a red-suite kill when
        status is "fail"; always False for "timeout", since a hang could
        be mid-compile or mid-run and this driver has no reliable way to
        tell which from the outside).

    Runs the child in its own session (`start_new_session=True`) so a
    timeout can kill the whole process group, not just the immediate
    `nim` process -- `nim c -r` shells out to a C compiler/linker and then
    execs the resulting test binary, and killing only the top-level `nim`
    process would leave any of those still-running descendants orphaned
    rather than reaped.
    """
    proc = subprocess.Popen(
        [NIM_BIN, "c", "-r", test_file],
        cwd=SCRATCH,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, _ = proc.communicate(timeout=PER_FILE_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, OSError):
            # The process (and its group) is already gone -- it exited in
            # the race window between the timeout firing and the kill
            # landing. Nothing to signal; fall through to reap it below
            # (round-4 finding R17: this used to be unguarded, so this
            # exact race crashed the whole campaign instead of just
            # scoring one mutant as a timeout).
            pass
        # Reap the now-dying process group and collect whatever partial
        # output it had produced before the kill, for the log.
        stdout, _ = proc.communicate()
        log_path.write_text(
            (stdout or "")
            + f"\n\n[run_mutation: TIMED OUT after {PER_FILE_TIMEOUT_SECONDS}s "
            "-- process group killed]\n"
        )
        return "timeout", False
    log_path.write_text(stdout)
    compiled = "[Exec]" in stdout
    return ("ok" if proc.returncode == 0 else "fail"), compiled


def run_mutant(mutant: Mutant, unit_test_files, log_dir: pathlib.Path):
    log_dir.mkdir(parents=True, exist_ok=True)
    for test_file in unit_test_files:
        status, compiled = run_one_file(test_file, log_dir / (pathlib.Path(test_file).stem + ".log"))
        if status == "timeout":
            return "KILLED (timeout)", test_file
        if status == "fail":
            outcome = "KILLED (test)" if compiled else "KILLED (compile-error)"
            return outcome, test_file
    return "SURVIVED", None


def render_report(catalog, results, elapsed_seconds, unit_test_files, equivalent):
    total = len(catalog)
    killed_test = sum(1 for r in results.values() if r[0] == "KILLED (test)")
    killed_compile = sum(1 for r in results.values() if r[0] == "KILLED (compile-error)")
    killed_timeout = sum(1 for r in results.values() if r[0] == "KILLED (timeout)")
    survived = sum(1 for r in results.values() if r[0] == "SURVIVED")
    killed_total = killed_test + killed_compile + killed_timeout
    kill_rate = (killed_total / total * 100.0) if total else 0.0

    lines = []
    lines.append("# Mutation testing results (RFC-002 slice 5)")
    lines.append("")
    lines.append(
        "Kill-rate report for sello's curated mutation-testing catalog "
        "(`tests/mutation/mutants/`), generated by `scripts/mutation.sh` "
        "(`tests/mutation/run_mutation.py`). Regenerated wholesale on every "
        "run -- this file is a build artifact of that script, not "
        "hand-maintained."
    )
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Mutants:** {total}")
    lines.append(f"- **Killed (test, red suite):** {killed_test}")
    lines.append(f"- **Killed (compile error):** {killed_compile}")
    lines.append(f"- **Killed (timeout):** {killed_timeout}")
    lines.append(f"- **Survived:** {survived}")
    lines.append(f"- **Overall kill rate:** {kill_rate:.1f}% ({killed_total}/{total})")
    lines.append(f"- **Retired (confirmed-equivalent, excluded from the above):** {len(equivalent)}")
    lines.append(f"- **Wall clock:** {elapsed_seconds:.0f}s")
    lines.append("")
    if survived:
        lines.append(
            "**Gate status: NOT clean.** One or more mutants survived -- "
            "per the RFC, each survivor is a coverage-gap finding to be "
            "closed in-slice (a new test added, or reported as a deeper "
            "finding), not silently accepted."
        )
    else:
        lines.append(
            "**Gate status: clean.** Every mutant in the catalog was "
            "killed, either by the unit suite going red, by a compile "
            "error, or by exceeding the per-file timeout."
        )
    lines.append("")
    lines.append("## Methodology")
    lines.append("")
    lines.append(
        "This is a curated, hand-written mutant catalog, not an exhaustive "
        "operator sweep: proptest's own `mutation.nim` v1 is `int -> int` "
        "only and cannot target Nim source directly, so sello builds this "
        "thin patch-based harness in its place (RFC-002 slice 5). Each "
        "mutant is an exact-string OLD -> NEW replacement (see "
        "`tests/mutation/run_mutation.py`'s module doc comment for the "
        "full format and rationale for exact-match over a fuzzy context "
        "diff), applied to a disposable scratch copy of the source tree -- "
        "the real working tree is never touched. Every mutant's OLD block "
        "is verified to occur in the real source EXACTLY ONCE, both when "
        "the catalog was written and again on every run (a 0- or "
        "multiple-occurrence match aborts the run loudly rather than "
        "silently mis-targeting)."
    )
    lines.append("")
    lines.append(
        "For each mutant, the full unit suite (the same "
        f"{len(unit_test_files)} files `scripts/test.sh` runs, from "
        "`scripts/lib/unit-test-files.sh`) is compiled and run against the "
        "mutated tree. A mutant is KILLED if any file fails to compile "
        "(compile-error kill -- reported separately, since a mutant that "
        "never got a chance to run proves nothing about the suite's "
        "sensitivity), if any test fails once compiled (test kill -- a "
        "real red suite), or if any one file's compile+run does not finish "
        "within the per-file timeout (timeout kill -- reported separately "
        "again, since a hang is detected and counted, not left to stall "
        "the campaign silently). A mutant SURVIVES only if every file in "
        "the suite compiles and passes within the timeout. Verdicts "
        "short-circuit on the first failing file for wall-clock reasons; a "
        "SURVIVED verdict still requires the entire suite to pass."
    )
    lines.append("")
    lines.append(
        "Scope, per RFC-002 slice 5: `field.nim`/`scalar.nim`'s "
        "highest-risk spots -- carry-chain operator swaps, shift-amount "
        "off-by-ones, boundary constants (19, 0x7FFFFF, RFC 7748's "
        "121666, clamp masks, ...), comparison flips in "
        "`feBytesCanonical`/`scIsCanonical`, and digit-range constants "
        "in `recodeScalarRadix16`/`cmovCached`. RFC-003 slice 3 extended "
        "the catalog beyond field/scalar to the highest-stakes boundary "
        "logic elsewhere in the verify/decode surface: `challenge.nim`'s "
        "shared sign/verify hash-input ordering (a survivor there would "
        "be forgery-adjacent), `ed25519.pointDecode`'s RFC 8032 §5.1.3 "
        "reject conditions, `field.feSqrtRatioVartime`'s sqrt-ratio "
        "retry/reject branches (that primitive deleted and its two "
        "mutants replaced by RFC-004 slice 1c -- see the catalog "
        "numbering note below), `x25519.nim`'s RFC 7748 §6.1 zero-output "
        "small-order-peer check at both call sites, and "
        "`scalar.pointEncode`'s sign-bit condition (the one "
        "comparison-flip family the original S-series missed). This is "
        "quality-over-exhaustiveness curation throughout, not a claim of "
        "exhaustive operator coverage over every line of any of these "
        "files."
    )
    lines.append("")
    lines.append(
        "**Catalog numbering note:** the `field.nim`/`scalar.nim` "
        "mutant IDs skip F05 (retired to `equivalent/`, see below), and "
        "also skip F12 and F14 outright -- those two were abandoned "
        "during the original RFC-002 slice 5 authoring pass (candidate "
        "mutants that didn't survive the catalog's own curation, before "
        "ever being written to a checked-in `.mutant` file) and are not "
        "missing or lost entries; the surviving F-series simply never "
        "renumbered around the gap. F21 and F22 (originally targeting "
        "`field.feSqrtRatioVartime`'s retry/reject branches) were retired "
        "and REPLACED outright by RFC-004 slice 1c, not re-anchored: that "
        "slice deleted `feSqrtRatioVartime` after migrating "
        "`ed25519.pointDecode` onto the constant-time `feSqrtRatioM1`, so "
        "no `if` survives for either mutant's OLD-string to match. F23 and "
        "F24 replace them, targeting the CT primitive's own defect class "
        "(which candidate `feCMove` selects on `wasSquare`; the final "
        "`feAbs` normalization) instead of the deleted vartime retry/reject "
        "branches -- the F-series numbering continues rather than reusing "
        "F21/F22, so the gap is visible rather than silently overwritten."
    )
    lines.append("")
    lines.append(
        "A mutant that turns out to be behaviorally indistinguishable "
        "from the real source across its whole valid input domain (an "
        "\"equivalent mutant\") is retired to "
        "`tests/mutation/mutants/equivalent/` rather than left SURVIVED "
        "or forced to pass via a test that doesn't actually pin any real "
        "behavioral difference -- per the RFC's own guidance for a "
        "survivor that \"reveals something deeper\". Retired mutants are "
        "excluded from the active catalog this script executes (and thus "
        "from the kill-rate above) but are listed for transparency below, "
        "each with the empirical evidence for equivalence recorded in its "
        "own `note:` header field."
    )
    lines.append("")
    lines.append("## Results")
    lines.append("")
    lines.append("| id | target | description | outcome | first failing file |")
    lines.append("|----|--------|--------------|---------|---------------------|")
    for m in catalog:
        outcome, first_fail = results[m.id]
        target_short = m.target.replace("src/sello/", "")
        desc = m.desc.replace("|", "\\|")
        fail_cell = first_fail if first_fail else "--"
        lines.append(f"| {m.id} | {target_short} | {desc} | {outcome} | {fail_cell} |")
    lines.append("")

    if equivalent:
        lines.append("## Retired (equivalent) mutants")
        lines.append("")
        lines.append(
            "Not executed by this run and not counted in the summary above "
            "-- see the methodology section."
        )
        lines.append("")
        for m in equivalent:
            target_short = m.target.replace("src/sello/", "")
            lines.append(f"### {m.id} ({target_short})")
            lines.append("")
            lines.append(m.desc)
            lines.append("")
            if m.note:
                lines.append(m.note)
                lines.append("")

    REPORT_PATH.write_text("\n".join(lines) + "\n")


def main():
    unit_test_files = sys.argv[1:]
    if not unit_test_files:
        sys.exit("usage: run_mutation.py <unit-test-file> [<unit-test-file> ...]")

    catalog = load_catalog()
    equivalent = load_equivalent()
    all_targets = sorted({m.target for m in catalog})

    print(f"run_mutation: {len(catalog)} mutants, {len(unit_test_files)} unit test files"
          f" ({len(equivalent)} retired-equivalent, not run)")
    print(f"run_mutation: preparing scratch copy at {SCRATCH} ...")
    prepare_scratch()

    results = {}
    start = time.monotonic()
    for idx, mutant in enumerate(catalog, start=1):
        t0 = time.monotonic()
        reset_targets(all_targets)
        mutant.apply(SCRATCH)
        outcome, first_fail = run_mutant(
            mutant, unit_test_files, pathlib.Path(f"/tmp/sello-mutation-logs/{mutant.id}")
        )
        results[mutant.id] = (outcome, first_fail)
        dt = time.monotonic() - t0
        print(f"[{idx}/{len(catalog)}] {mutant.id} ({mutant.target}): {outcome} ({dt:.1f}s)")

    # Leave the scratch copy in a pristine state (courtesy, not load-bearing
    # -- prepare_scratch() wipes it on the next run regardless).
    reset_targets(all_targets)

    elapsed = time.monotonic() - start
    render_report(catalog, results, elapsed, unit_test_files, equivalent)

    survived = [m.id for m in catalog if results[m.id][0] == "SURVIVED"]
    killed_compile = sum(1 for m in catalog if results[m.id][0] == "KILLED (compile-error)")
    killed_test = sum(1 for m in catalog if results[m.id][0] == "KILLED (test)")
    killed_timeout = sum(1 for m in catalog if results[m.id][0] == "KILLED (timeout)")
    print()
    print(f"run_mutation: {len(catalog)} mutants -- {killed_test} killed (test), "
          f"{killed_compile} killed (compile-error), {killed_timeout} killed (timeout), "
          f"{len(survived)} survived")
    if survived:
        print(f"run_mutation: SURVIVORS: {', '.join(survived)}")
        print(f"run_mutation: report written to {REPORT_PATH}")
        sys.exit(1)
    print(f"run_mutation: report written to {REPORT_PATH}")
    sys.exit(0)


if __name__ == "__main__":
    main()
