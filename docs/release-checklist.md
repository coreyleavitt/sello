# Release checklist

This is deliverable (e) of RFC-005 slice 32 (Registry + close-out): the
exact, step-by-step first-release ritual, transcribed from
`docs/rfc-005-validation-infra.handoff.md`'s slice 30 record ("What
slice 32 inherits") plus the nimble-registry PR steps that follow a
passed release gate. **This document does not cut a release or open a
PR** — slice 32 part 1 (this closeout) prepares the ritual; part 2
(actually running it) is a maintainer decision, recorded as an open fork
in the handoff doc.

## Today's release-gate reading (2026-08-30, dry-run, not a real tag)

Run against a local-only, unpushed scratch tag
(`scratch/v0.5.0-slice32-dryrun`) pointed at `main`'s then-latest content
commit `d48fa8d` (the commit whose own real merge-gate run, `33320824230`,
is 27/27 green) — created, evaluated, and deleted within this audit
session, never pushed, no release created:

```
clause                 verdict                detail
---------------------- ---------------------- ----------------------------------------
merge-gate             PASS                   all 27 required checks green on d48fa8d8cc9c
nightly-qualification  PASS                   run 33316911555 (sha 55aeb41dccf9) -- fuzz, s390x, memcheck, cranked-properties all green, ancestor of scratch/v0.5.0-slice32-dryrun, no src/sello/ diff since
timing-freshness       STALE                  timing workflow (.github/workflows/timing.yml) does not exist yet -- RFC-005 slice 28 is Corey-physical and has not landed
version-consistency    PASS                   nimble == CHANGELOG heading == tag == milpa.kdl == '0.5.0'

release-gate: OVERALL FAIL for tag 'scratch/v0.5.0-slice32-dryrun'
```

This is exactly the reading `docs/rfc-005-validation-infra.md`'s
"Ordering & risks" section anticipates for the current state (slices
27-29 open, physical-hardware-blocked): three clauses genuinely PASS,
clause (iii) reads STALE/ABSENT (no `.github/workflows/timing.yml` exists
yet, confirmed: `ls .github/workflows/`), and the overall verdict is FAIL
only because no `--stale-accept` was passed on this dry run (the whole
point of the dry run was to see the clean, unforced clause table first).
A real release cut today would need either (a) slices 28/29 to land
first (closing clause (iii) for real), or (b) the `--stale-accept`
override path, which slice 30 built and demonstrated for exactly this
case — see the "Ritual" section below, step 5.

## The exact first-release ritual (from slice 30's own record)

1. Bump `sello.nimble`'s `version`, `milpa.kdl`'s `version`, and add a
   new `## [x.y.z] - YYYY-MM-DD` `CHANGELOG.md` heading with real release
   notes (this text becomes the GitHub release body verbatim — the
   release-notes body IS `CHANGELOG.md`'s `## [x.y.z]` section, full
   stop, per slice 30's own design decision). This is also the moment to
   fold this slice's own `## [Unreleased]` section's content into that
   new dated heading (see "Version decision," below, for whether the
   version is `0.5.0` or `0.6.0`).
2. `scripts/lib/version-consistency.sh vX.Y.Z` locally to confirm all
   four copies of the version agree before tagging anything.
3. Land that version-bump commit on `main` via the normal branch ->
   merge-gate-green -> fast-forward flow (this repo's standing branch
   model) -- do NOT tag until this commit's own merge-gate check-runs are
   green on the exact SHA that will be tagged.
4. `git tag -s -m "..." vX.Y.Z <sha>` (or `-m` alone, since
   `tag.gpgsign=true` is already set locally — confirmed this session:
   an un-annotated `git tag <name> <sha>` with no `-m` fails outright
   under this config with "fatal: no tag message?", so always pass `-m`
   or `-a`/`-s` with a message) on that exact green SHA.
5. `scripts/release-gate.sh vX.Y.Z` locally FIRST (no `--stale-accept`)
   to see the real clause table before pushing the tag -- if clause (iii)
   is genuinely fresh (slices 28/29 landed and a timing run is inside the
   window), this should read all-PASS with no flag needed; if clause
   (iii) reads STALE and a maintainer judgment call is made to ship
   anyway, add the `timing-evidence: stale` sentence to this version's
   own `CHANGELOG.md` section BEFORE tagging (so the tag's own commit
   carries the notation the release body will show), and re-tag if the
   commit changed.
6. `git push origin vX.Y.Z` -- this alone triggers `release.yml` for real
   (the `push: tags: v*` trigger), `stale_accept` hardcoded false on that
   path. If step 5 required a stale-accept ship, the push-triggered run
   will correctly FAIL clause (iii) even with the notation present (push
   runs never carry `stale_accept=true` by design) -- in that case, use
   `gh workflow run release.yml --ref main -f tag=vX.Y.Z -f
   stale_accept=true` as the actual release-cutting dispatch instead of
   relying on the tag push alone; the tag itself is already pushed and
   immutable (the `tags` ruleset), only the EVALUATION needs the dispatch
   route for the override to apply.
7. Confirm all three jobs (`release-gate`, `release-consumer`,
   `release-publish`) green, confirm the GitHub release was created (NOT
   `--prerelease` this time -- `release-publish`'s own `prerelease`
   output is `false` for any non-`scratch/*` tag, automatic).
8. Proceed to the nimble registry PR below, which references this
   now-published, gate-passed release.

**Operational note carried forward from slice 30, worth restating here:**
cutting (or gate-checking) a release within moments of a fast-forward-to-
`main` push can transiently under-report clause (i), because the
fast-forward itself re-triggers an independent merge-gate run on the
identical SHA. Let that second run settle (or wait ~30s and re-check)
before trusting a red clause (i) verdict on a SHA that was JUST
fast-forwarded to `main`.

## The nimble registry PR (after the first release passes, not before)

sello is not yet listed in `nim-lang/packages`'s `packages.json` — a
`nimble install sello` from an unmodified nimble installation cannot
resolve it today (only `requires "sello"` against an explicit git URL, or
milpa, work without this). The registry entry references a real,
already-published, gate-passed GitHub release (or at minimum a real tag
— the registry format itself has no notion of "gate-passed," but this
project's own standing shouldn't-publish-unchecked-claims posture says
wait for one).

**Steps (not performed by this document — slice 32 part 2, a maintainer
decision):**

1. Fork `github.com/nim-lang/packages`.
2. Add one JSON object to `packages.json` (the file is a flat JSON array;
   entries are conventionally kept alphabetically sorted by `name`,
   though the registry's own tooling does not strictly enforce this).
3. Open a PR against `nim-lang/packages` with just that one addition —
   the registry's own contribution norm is one package per PR, no
   unrelated changes.
4. The registry's own CI (`nimble_packages_test` or equivalent, run by
   that repo, not this one) validates the entry resolves and the
   referenced repository is reachable; address any feedback from that
   repo's own maintainers, not this project's.
5. Once merged, `nimble install sello` resolves for every downstream
   consumer with no `--path`/git-URL workaround needed.

### Drafted `packages.json` entry (exact JSON, not opened as a PR)

```json
{
  "name": "sello",
  "url": "https://github.com/coreyleavitt/sello",
  "method": "git",
  "tags": [
    "crypto",
    "cryptography",
    "ed25519",
    "x25519",
    "curve25519",
    "eddsa",
    "ecdh",
    "ristretto255",
    "signature",
    "pure-nim"
  ],
  "description": "Pure-Nim ed25519 + X25519 (Curve25519). No FFI in the core; optional libsodium signer adapter. RFC 8032, RFC 7748.",
  "license": "Apache-2.0",
  "web": "https://github.com/coreyleavitt/sello"
}
```

Notes on the drafted fields, so a future session (or Corey) does not have
to re-derive them:

- `description` is copied verbatim from `sello.nimble`'s own
  `description` field — the two are expected to agree, and nimble's own
  tooling surfaces this string in `nimble search`/`nimble list` output.
- `tags` is a superset of `sello.nimble`'s own "Keywords for
  discoverability" comment (`pure-Nim ed25519 X25519 Curve25519 EdDSA RFC
  8032 RFC 7748`), normalized to the registry's own lowercase-single-word
  convention and extended with `ristretto255`/`ecdh`/`signature` (which
  the nimble comment omits but which are genuine, searchable
  capabilities of this library as of RFC-004).
- `method` is `"git"` (not `"hg"` — irrelevant here, but the registry
  schema has historically supported both).
- No `alias` field — sello has never published under a different name.
- The registry format has no field for a specific version/tag pin; it
  always points at the repository's default branch and lets the
  consumer's own `requires "sello >= x.y.z"` (or bare `requires "sello"`)
  do version selection against whatever tags exist.

## Version decision (see the handoff doc's Open forks for the full case)

`sello.nimble` and `milpa.kdl` both currently read `0.5.0`, and
`CHANGELOG.md` has an `## [0.5.0] - 2026-08-21` heading — but that
version was never tagged (`git tag -l 'v*'` on this repository returns no
real, non-scratch `v0.5.0` tag) and is not on the nimble registry. The
`## [Unreleased]` section this slice added contains one genuine,
user-visible fix (the clang CT hardening) atop that untagged 0.5.0
baseline. Whether the first real release is `v0.5.0` (folding
`Unreleased` into the existing `0.5.0` heading, since it was never
actually shipped) or `v0.6.0` (bumping again because a real security-
relevant fix landed since that heading was written) is recorded as an
open fork for Corey in the handoff doc, not decided here.
