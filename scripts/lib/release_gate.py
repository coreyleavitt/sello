#!/usr/bin/env python3
"""scripts/lib/release_gate.py -- RFC-005 slice 30: the release gate's
real clause logic. scripts/release-gate.sh is the thin, host-runnable
entry point (mirroring scripts/validation-map-check.sh's own
bash-wrapper-around-python convention); scripts/lib/version-consistency.sh
is a second thin wrapper exposing this file's version-consistency clause
alone, per deliverable (b).

WHAT THIS CHECKS, one independent verdict per RFC clause (RFC-005 Part B's
own release-workflow paragraph, docs/rfc-005-validation-infra.md lines
~868-897; no short-circuit -- every clause is evaluated and reported even
if an earlier one already failed, so each per-clause red demo is visible
on its own):

  (i)   merge-gate: every required-check name in scripts/lib/gates.txt has
        a successful check-run on the tagged SHA.
  (ii)  nightly-qualification: the newest nightly.yml run where the four
        RFC-enumerated jobs (fuzz, s390x, memcheck, cranked-properties)
        ALL succeeded -- DECISION (recorded here, per the task's own
        "decide, record" instruction): qualify on ONE run where all four
        jobs succeeded on the SAME head SHA, not a per-job newest-success
        stitched across different runs/SHAs. Stitching per-job would let
        four different SHAs (e.g. four different nights, one of which
        predates a src/sello/ regression the other three don't) jointly
        satisfy the subset with no single SHA ever having actually seen
        that regression fixed -- a single-run SHA is the only shape that
        makes "no diff under src/sello/ since" mean what it says. That
        SHA must be an ancestor of the tag with no `src/sello/` diff
        since.
  (iii) timing-freshness: a timing-tier run (workflow `timing.yml`, RFC-005
        slice 28, and the durable `evidence` branch record, slice 29) --
        NEITHER EXISTS YET as of this slice, so this clause is red by
        construction today (see the module-level NOTE below) unless
        --timing-fixture or --stale-accept is used. Sub-verdicts:
          - ABSENT: no timing.yml workflow, no evidence branch, or no
            successful timing.yml run at all.
          - WINDOW_EXCEEDED: a candidate run exists, is an ancestor of the
            tag, has no src/sello/ diff since, and cites correctly in
            docs/ct-results.md -- but is older than the 14-day freshness
            window.
          ABSENT and WINDOW_EXCEEDED are the two STALE-class verdicts:
          the ONLY ones --stale-accept can override (see below).
          - NON_ANCESTOR: a candidate exists but is not an ancestor of the
            tag. HARD FAIL -- never overridable by --stale-accept (the
            evidence isn't even about this history).
          - CORE_DIFF: an in-window ancestor candidate exists, but
            src/sello/ changed between it and the tag. HARD FAIL -- never
            overridable (the evidence didn't see the released code).
          - CITATION_MISSING: an in-window ancestor candidate exists, but
            docs/ct-results.md does not cite its run id / SHA. HARD FAIL
            -- never overridable (a documentation-drift finding, not a
            freshness gap; skipped entirely under --timing-fixture, which
            has no real run id to cite -- see that flag's own docstring).
        This ABSENT/WINDOW_EXCEEDED-vs-NON_ANCESTOR/CORE_DIFF/
        CITATION_MISSING split is the load-bearing design decision this
        slice makes explicit: RFC-005 Part B's stale-accept text says "a
        release may proceed on stale timing evidence" -- stale, not
        wrong. An input that machine-checks a notation string cannot also
        adjudicate "is this evidence even about the released code," so
        that class of failure stays a hard, unconditional red.
  (v4)  version-consistency: nimble version == CHANGELOG `## [x.y.z]`
        heading == tag name (with the `scratch/vX.Y.Z[-suffix]` case
        parsed the same way) == milpa.kdl's version field.

--stale-accept: valid ONLY when clause (iii) lands on a STALE-class
verdict (ABSENT or WINDOW_EXCEEDED). It requires the literal string
`timing-evidence: stale` to appear in the release-notes body -- defined
here, precisely, as the CHANGELOG section for the tag's own version
(`## [x.y.z] ... up to the next ## [ heading or EOF`) -- the same text
`--print-body` emits and the same text release.yml's `release-publish`
job uses verbatim as the GitHub release body. This is deliberate, not a
second notes-input mechanism: one body, one place the notation can live,
so the published release always visibly discloses the exact thing the
gate let past (RFC-005 Part B: the notation is machine-checked, not an
unenforced convention). If the notation is present, clause (iii) reports
PASS-VIA-STALE-ACCEPT (still visibly distinct in the table, never plain
PASS). If absent, clause (iii) stays FAIL naming the missing notation.
--stale-accept is a NO-OP (logged, not an error) when clause (iii) is
already PASS, and can never rescue a HARD FAIL (NON_ANCESTOR / CORE_DIFF
/ CITATION_MISSING) -- see the sub-verdict docstring above.

--timing-fixture SHA,DATE: a documented, OFF-BY-DEFAULT test hook that
substitutes a literal (candidate SHA, candidate ISO date) pair for the
real timing.yml/evidence-branch query, so this clause's ancestry/window/
diff logic can be red-demoed today even though no real timing-tier run
exists yet (RFC-005 slices 28/29 are Corey-physical and have not landed --
see CLAUDE.md's Ordering & risks). Fixture mode skips the
docs/ct-results.md citation check entirely (a fixture SHA was never
really adjudicated there, so CITATION_MISSING would be a foregone,
uninformative conclusion) -- this is disclosed loudly in the report, not
silently skipped.

NOTE on clause (iii) being "red by construction": until RFC-005 slices
28 (timing tier) and 29 (evidence-branch publication) land, a REAL
(non-fixture) invocation of this gate will always report clause (iii) as
STALE/ABSENT ("no timing.yml workflow exists yet"). This is not a defect
in this slice -- it is the honestly-disclosed, degraded-mode path RFC-005
Part B specifies for exactly this situation: a release may still proceed
via --stale-accept with the notation present. Once 28/29 land, clause
(iii) starts evaluating for real and --stale-accept becomes unnecessary
on a release cut soon after a fresh quiet-box battery.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

GATES_TXT = REPO_ROOT / "scripts" / "lib" / "gates.txt"
NIGHTLY_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "nightly.yml"
TIMING_WORKFLOW_PATH = ".github/workflows/timing.yml"  # RFC-005 slice 28, not yet landed
CT_RESULTS = REPO_ROOT / "docs" / "ct-results.md"
NIMBLE_FILE = REPO_ROOT / "sello.nimble"
MILPA_KDL = REPO_ROOT / "milpa.kdl"
CHANGELOG = REPO_ROOT / "CHANGELOG.md"

NIGHTLY_QUALIFICATION_JOBS = ["fuzz", "s390x", "memcheck", "cranked-properties"]
FRESHNESS_WINDOW_DAYS = 14
STALE_NOTATION = "timing-evidence: stale"


# --------------------------------------------------------------------------
# small utilities
# --------------------------------------------------------------------------

def die(msg: str) -> "None":
    print(f"release-gate: FATAL: {msg}", file=sys.stderr)
    sys.exit(2)


def run(cmd: list[str], check: bool = True) -> str:
    result = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    if check and result.returncode != 0:
        die(f"command failed ({' '.join(cmd)}): {result.stderr.strip()}")
    return result.stdout.strip()


def repo_slug() -> str:
    """Owner/repo, from the origin remote (works in CI too -- see
    scripts/ruleset-sync-check.sh's own identical rationale: no hardcoded
    string to drift from the actual remote)."""
    url = run(["git", "config", "--get", "remote.origin.url"], check=False)
    m = re.match(r"^(?:git@github\.com:|https://github\.com/)(.+?)(?:\.git)?$", url)
    if not m:
        die(f"could not determine owner/repo from remote.origin.url ({url!r})")
    return m.group(1)


def gh_api_json(path: str, params: dict[str, str] | None = None) -> dict:
    # `gh api` silently switches its HTTP method from GET to POST the
    # moment any `-f`/`-F` flag is present (verified empirically while
    # writing this function: a plain `-f per_page=100` against a
    # check-runs GET endpoint came back 404, not the paginated list) --
    # so query parameters are appended to the URL directly and `-X GET`
    # is always passed explicitly, rather than relying on gh's own
    # method-inference default.
    url = path
    if params:
        url = path + "?" + "&".join(f"{k}={v}" for k, v in params.items())
    args = ["gh", "api", "-X", "GET", url]
    result = subprocess.run(args, cwd=REPO_ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        return {"_error": result.stderr.strip(), "_status": result.returncode}
    return json.loads(result.stdout)


def gh_api_paginated(path: str, list_key: str, per_page: int = 100, max_pages: int = 10) -> list[dict]:
    """Collects `list_key` across pages until a short/empty page. Used for
    both check-runs and workflow-runs listings, whose shapes both carry
    the real list under a named key (`check_runs`, `workflow_runs`) rather
    than being a bare top-level array -- gh api --paginate's own array
    -flattening mode assumes the latter, so this function does the
    pagination loop by hand instead."""
    items: list[dict] = []
    page = 1
    while page <= max_pages:
        data = gh_api_json(path, {"per_page": str(per_page), "page": str(page)})
        if "_error" in data:
            return items if items else []
        chunk = data.get(list_key, [])
        items.extend(chunk)
        if len(chunk) < per_page:
            break
        page += 1
    return items


# --------------------------------------------------------------------------
# clause (i): merge-gate green on the tagged SHA
# --------------------------------------------------------------------------

@dataclass
class ClauseResult:
    name: str
    verdict: str  # PASS / STALE / FAIL / PASS-VIA-STALE-ACCEPT
    detail: str
    hard_fail: bool = False  # True: never overridable by --stale-accept


def gates_check_names() -> list[str]:
    if not GATES_TXT.is_file():
        die(f"missing {GATES_TXT}")
    names = []
    for raw in GATES_TXT.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        names.append(line.split(maxsplit=1)[0])
    return names


def resolve_tag_sha(tag: str) -> str:
    sha = run(["git", "rev-parse", f"refs/tags/{tag}^{{commit}}"], check=False)
    if not sha:
        die(f"tag {tag!r} does not resolve to a commit locally (fetch it first -- 'git fetch --tags')")
    return sha


def clause_merge_gate(tag_sha: str, slug: str) -> ClauseResult:
    required = gates_check_names()
    runs = gh_api_paginated(f"repos/{slug}/commits/{tag_sha}/check-runs", "check_runs")
    latest_by_name: dict[str, dict] = {}
    for r in runs:
        name = r.get("name")
        if name is None:
            continue
        prev = latest_by_name.get(name)
        if prev is None or (r.get("started_at") or "") >= (prev.get("started_at") or ""):
            latest_by_name[name] = r

    missing = [n for n in required if n not in latest_by_name]
    not_success = [
        n for n in required
        if n in latest_by_name and latest_by_name[n].get("conclusion") != "success"
    ]

    if not missing and not not_success:
        return ClauseResult("merge-gate", "PASS", f"all {len(required)} required checks green on {tag_sha[:12]}")

    parts = []
    if missing:
        parts.append(f"missing: {', '.join(missing)}")
    if not_success:
        detail = ", ".join(f"{n}={latest_by_name[n].get('conclusion')}" for n in not_success)
        parts.append(f"not green: {detail}")
    return ClauseResult("merge-gate", "FAIL", "; ".join(parts), hard_fail=True)


# --------------------------------------------------------------------------
# clause (ii): nightly qualification subset, ancestry, no src/sello/ diff
# --------------------------------------------------------------------------

def is_ancestor(candidate_sha: str, tag: str) -> bool:
    # Make sure the candidate object is even known locally before asking
    # merge-base about it -- an unknown object must read as "not an
    # ancestor we can verify," not crash the whole gate with a git error.
    check = subprocess.run(
        ["git", "cat-file", "-e", candidate_sha + "^{commit}"],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    if check.returncode != 0:
        return False
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", candidate_sha, f"refs/tags/{tag}"],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    return result.returncode == 0


def has_core_diff(candidate_sha: str, tag: str) -> bool:
    result = subprocess.run(
        ["git", "diff", "--quiet", candidate_sha, f"refs/tags/{tag}", "--", "src/sello/"],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    return result.returncode != 0


def clause_nightly_qualification(tag: str, slug: str) -> ClauseResult:
    runs = gh_api_paginated(
        f"repos/{slug}/actions/workflows/nightly.yml/runs", "workflow_runs", per_page=50, max_pages=4,
    )
    runs = [r for r in runs if r.get("status") == "completed"]
    runs.sort(key=lambda r: r.get("created_at", ""), reverse=True)

    for r in runs:
        run_id = r["id"]
        sha = r["head_sha"]
        jobs = gh_api_paginated(f"repos/{slug}/actions/runs/{run_id}/jobs", "jobs")
        by_name = {j.get("name"): j for j in jobs}
        ok = all(
            by_name.get(j, {}).get("conclusion") == "success"
            for j in NIGHTLY_QUALIFICATION_JOBS
        )
        if not ok:
            continue

        if not is_ancestor(sha, tag):
            return ClauseResult(
                "nightly-qualification", "FAIL",
                f"newest fully-qualifying nightly run ({run_id}, sha {sha[:12]}) is NOT an ancestor of {tag}",
                hard_fail=True,
            )
        if has_core_diff(sha, tag):
            return ClauseResult(
                "nightly-qualification", "FAIL",
                f"newest fully-qualifying nightly run ({run_id}, sha {sha[:12]}) is an ancestor, "
                f"but src/sello/ changed between it and {tag}",
                hard_fail=True,
            )
        return ClauseResult(
            "nightly-qualification", "PASS",
            f"run {run_id} (sha {sha[:12]}) -- {', '.join(NIGHTLY_QUALIFICATION_JOBS)} all green, "
            f"ancestor of {tag}, no src/sello/ diff since",
        )

    return ClauseResult(
        "nightly-qualification", "FAIL",
        f"no nightly.yml run found where all of {', '.join(NIGHTLY_QUALIFICATION_JOBS)} succeeded "
        f"on the same SHA (searched the {len(runs)} most recent completed runs)",
        hard_fail=True,
    )


# --------------------------------------------------------------------------
# clause (iii): timing-tier freshness
# --------------------------------------------------------------------------

def workflow_exists(slug: str, path_suffix: str) -> bool:
    workflows = gh_api_paginated(f"repos/{slug}/actions/workflows", "workflows")
    return any(w.get("path") == path_suffix for w in workflows)


def branch_exists(slug: str, branch: str) -> bool:
    data = gh_api_json(f"repos/{slug}/branches/{branch}")
    return "_error" not in data


def clause_timing(tag: str, slug: str, fixture: str | None) -> ClauseResult:
    if fixture:
        try:
            sha, date_str = fixture.split(",", 1)
            sha = sha.strip()
            candidate_date = datetime.fromisoformat(date_str.strip()).replace(tzinfo=timezone.utc)
        except ValueError:
            die(f"--timing-fixture must be 'SHA,ISO-DATE', got {fixture!r}")
        source = f"FIXTURE (test hook, not a real timing-tier run) sha={sha[:12]} date={candidate_date.date()}"
        run_id = None
    else:
        if not workflow_exists(slug, TIMING_WORKFLOW_PATH):
            return ClauseResult(
                "timing-freshness", "STALE",
                "timing workflow (.github/workflows/timing.yml) does not exist yet -- RFC-005 slice 28 "
                "is Corey-physical and has not landed",
            )
        if not branch_exists(slug, "evidence"):
            return ClauseResult(
                "timing-freshness", "STALE",
                "the durable 'evidence' branch does not exist yet -- RFC-005 slice 29 has not landed",
            )
        runs = gh_api_paginated(
            f"repos/{slug}/actions/workflows/timing.yml/runs", "workflow_runs", per_page=20, max_pages=3,
        )
        successes = [r for r in runs if r.get("conclusion") == "success"]
        successes.sort(key=lambda r: r.get("created_at", ""), reverse=True)
        if not successes:
            return ClauseResult(
                "timing-freshness", "STALE",
                "no successful timing.yml run found",
            )
        newest = successes[0]
        sha = newest["head_sha"]
        run_id = newest["id"]
        candidate_date = datetime.fromisoformat(newest["created_at"].replace("Z", "+00:00"))
        source = f"run {run_id} (sha {sha[:12]}, {candidate_date.date()})"

    if not is_ancestor(sha, tag):
        return ClauseResult(
            "timing-freshness", "FAIL",
            f"{source} is NOT an ancestor of {tag}",
            hard_fail=True,
        )
    if has_core_diff(sha, tag):
        return ClauseResult(
            "timing-freshness", "FAIL",
            f"{source} is an ancestor, but src/sello/ changed between it and {tag}",
            hard_fail=True,
        )

    if fixture:
        citation_note = " (fixture mode -- citation check skipped, see this script's own docstring)"
    else:
        ct_text = CT_RESULTS.read_text() if CT_RESULTS.is_file() else ""
        cited = str(run_id) in ct_text or sha[:12] in ct_text or sha in ct_text
        if not cited:
            return ClauseResult(
                "timing-freshness", "FAIL",
                f"{source} is a fresh in-window ancestor with no src/sello/ diff, but "
                f"docs/ct-results.md does not cite this run id / SHA",
                hard_fail=True,
            )
        citation_note = " (cited in docs/ct-results.md)"

    age = datetime.now(timezone.utc) - candidate_date
    if age > timedelta(days=FRESHNESS_WINDOW_DAYS):
        return ClauseResult(
            "timing-freshness", "STALE",
            f"{source} is an ancestor with no src/sello/ diff{citation_note}, "
            f"but is {age.days}d old (window: {FRESHNESS_WINDOW_DAYS}d)",
        )

    return ClauseResult(
        "timing-freshness", "PASS",
        f"{source} is an ancestor with no src/sello/ diff, {age.days}d old (within {FRESHNESS_WINDOW_DAYS}d window){citation_note}",
    )


# --------------------------------------------------------------------------
# version-consistency (nimble == CHANGELOG heading == tag == milpa.kdl)
# --------------------------------------------------------------------------

def parse_tag_version(tag: str) -> str | None:
    m = re.match(r"^v(\d+\.\d+\.\d+)$", tag)
    if m:
        return m.group(1)
    m = re.match(r"^scratch/v(\d+\.\d+\.\d+)(?:-[A-Za-z0-9._-]+)?$", tag)
    if m:
        return m.group(1)
    return None


def nimble_version() -> str | None:
    if not NIMBLE_FILE.is_file():
        return None
    m = re.search(r'^version\s*=\s*"([^"]+)"', NIMBLE_FILE.read_text(), re.MULTILINE)
    return m.group(1) if m else None


def milpa_version() -> str | None:
    if not MILPA_KDL.is_file():
        return None
    m = re.search(r'^version\s+"([^"]+)"', MILPA_KDL.read_text(), re.MULTILINE)
    return m.group(1) if m else None


def changelog_heading_version(version: str) -> tuple[bool, int | None]:
    """Returns (heading exists for `version`, its line index) -- callers
    needing the version-heading-matches-tag boolean check just the first
    element; find_changelog_section (below) reuses the line index."""
    if not CHANGELOG.is_file():
        return (False, None)
    lines = CHANGELOG.read_text().splitlines()
    pattern = re.compile(r"^## \[" + re.escape(version) + r"\]")
    for i, line in enumerate(lines):
        if pattern.match(line):
            return (True, i)
    return (False, None)


def find_changelog_section(version: str) -> str | None:
    exists, idx = changelog_heading_version(version)
    if not exists:
        return None
    lines = CHANGELOG.read_text().splitlines()
    body_lines = []
    for line in lines[idx + 1:]:
        if re.match(r"^## \[", line):
            break
        body_lines.append(line)
    return "\n".join(body_lines).strip("\n")


def clause_version_consistency(tag: str) -> ClauseResult:
    tag_version = parse_tag_version(tag)
    if tag_version is None:
        return ClauseResult(
            "version-consistency", "FAIL",
            f"tag {tag!r} does not match 'vX.Y.Z' or 'scratch/vX.Y.Z[-suffix]'",
            hard_fail=True,
        )

    nv = nimble_version()
    mv = milpa_version()
    ch_exists, _ = changelog_heading_version(tag_version)

    mismatches = []
    if nv != tag_version:
        mismatches.append(f"sello.nimble version={nv!r} != tag version={tag_version!r}")
    if mv != tag_version:
        mismatches.append(f"milpa.kdl version={mv!r} != tag version={tag_version!r}")
    if not ch_exists:
        mismatches.append(f"CHANGELOG.md has no '## [{tag_version}]' heading")

    if mismatches:
        return ClauseResult("version-consistency", "FAIL", "; ".join(mismatches), hard_fail=True)
    return ClauseResult(
        "version-consistency", "PASS",
        f"nimble == CHANGELOG heading == tag == milpa.kdl == {tag_version!r}",
    )


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def print_table(results: list[ClauseResult]) -> None:
    print("")
    print(f"{'clause':<22} {'verdict':<22} detail")
    print(f"{'-'*22} {'-'*22} {'-'*40}")
    for r in results:
        print(f"{r.name:<22} {r.verdict:<22} {r.detail}")
    print("")


def main() -> int:
    argv = sys.argv[1:]
    if not argv:
        die("usage: release_gate.py <tag> [--stale-accept] [--timing-fixture SHA,DATE] [--print-body] [--version-only]")

    tag = argv[0]
    rest = argv[1:]
    stale_accept = "--stale-accept" in rest
    print_body = "--print-body" in rest
    version_only = "--version-only" in rest
    fixture = None
    if "--timing-fixture" in rest:
        fixture = rest[rest.index("--timing-fixture") + 1]

    if print_body:
        version = parse_tag_version(tag)
        if version is None:
            die(f"tag {tag!r} does not parse to a version")
        body = find_changelog_section(version)
        if body is None:
            die(f"no CHANGELOG.md section for version {version!r}")
        print(body)
        return 0

    if version_only:
        r = clause_version_consistency(tag)
        print_table([r])
        return 0 if r.verdict == "PASS" else 1

    slug = repo_slug()
    tag_sha = resolve_tag_sha(tag)

    results: list[ClauseResult] = []
    results.append(clause_merge_gate(tag_sha, slug))
    results.append(clause_nightly_qualification(tag, slug))
    timing = clause_timing(tag, slug, fixture)
    results.append(clause_version_consistency(tag))

    stale_accept_applied = False
    if timing.verdict == "STALE":
        if stale_accept:
            version = parse_tag_version(tag)
            body = find_changelog_section(version) if version else None
            if body is not None and STALE_NOTATION in body:
                timing = ClauseResult(
                    timing.name, "PASS-VIA-STALE-ACCEPT",
                    timing.detail + f" -- overridden: '{STALE_NOTATION}' present in the release-notes body",
                )
                stale_accept_applied = True
            else:
                timing = ClauseResult(
                    timing.name, "FAIL",
                    timing.detail + f" -- --stale-accept was set, but the release-notes body "
                    f"(CHANGELOG.md's version section) does not contain the literal notation "
                    f"'{STALE_NOTATION}'",
                    hard_fail=True,
                )
        # else: leave as STALE -- overall FAIL below, per the "the only path
        # past a red freshness gate" rule.
    results.insert(2, timing)

    print_table(results)

    if stale_accept and timing.verdict == "PASS" and not stale_accept_applied:
        print("release-gate: NOTE -- --stale-accept was set but clause (iii) already PASSed for real; the flag was a no-op.")

    overall_pass = all(r.verdict in ("PASS", "PASS-VIA-STALE-ACCEPT") for r in results)
    print(f"release-gate: OVERALL {'PASS' if overall_pass else 'FAIL'} for tag {tag!r}")
    return 0 if overall_pass else 1


if __name__ == "__main__":
    sys.exit(main())
