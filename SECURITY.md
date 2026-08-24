# Security policy

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting** on this repository
(Security tab -> "Report a vulnerability") -- it is enabled and is the
preferred intake path: the report stays private between you and the
maintainer until a fix and coordinated disclosure. If you cannot use it,
email the author directly (Corey Leavitt, `corey@leavitt.dev`). Please do
NOT open a public issue for a suspected vulnerability in the
signing/keygen/DH paths (the secret-holding half of the library);
`verify`-path correctness issues carry no secrecy concern and a public
issue is fine there. There is no dedicated security-report address or PGP
key at this time.

## What to expect

sello is a solo-maintained, unaudited project. Reports are handled
best-effort: there is no SLA, no CVE-issuing process, and no paid
disclosure program. A credible report against the signing/keygen path
(the constant-time, secret-holding half of the library) will be prioritized
over one against `verify` (which touches no secret and has a much larger
built-in safety margin -- see below).

## Scope

See the "Threat model" section of [`README.md`](README.md#threat-model--when-not-to-use-this)
for what sello's validation bar does and does not cover (statistical
timing evidence, no defense against memory-dumping attackers beyond
destructor-driven wipes, signature malleability, an unaudited pure-Nim
signer). If your threat model requires an audited implementation rather
than a statistically-validated one, compile with `-d:selloLibsodium` to
dispatch `sign`/`keypair` to libsodium's audited C implementation instead
of sello's own signer -- `verify` is pure-Nim on both backends and is not
affected by the flag.

## Trust root / security posture

Everything upstream of the merge-gate ruleset -- ruleset edits, `ghcr.io`
image pushes, and every other repository setting -- resolves to one
account: the repository owner, `coreyleavitt` (a personal GitHub account,
not an organization). There is no second admin, no bot account with
elevated repo permissions, and (verified live, `gh api
repos/coreyleavitt/sello/actions/runners` -> `total_count: 0`) no
self-hosted Actions runner registered against this repository -- every CI
job currently runs on GitHub-hosted runners, so there is no
runner-registration credential to custody yet. That changes once RFC-005's
Phase 4 timing-tier work provisions a physical runner (tracked as its own
slice); this paragraph will be revisited then.

The items below are recorded as of 2026-08-24, split by how they were
established:

**Independently verified from this environment:**
- Repository visibility is public, owned by the `coreyleavitt` user
  account (`gh api repos/coreyleavitt/sello` -> `visibility: "public"`,
  `owner.type: "User"`).
- No self-hosted Actions runners are registered (above).
- The fork-PR workflow-run approval policy requires maintainer approval
  for all outside contributors (`gh api
  repos/coreyleavitt/sello/actions/permissions/fork-pr-contributor-approval`
  -> `approval_policy: "all_external_contributors"`).

**Owner-attested (cannot be verified from an API session; recorded as
stated by the maintainer, not independently confirmed):**
- The owner account's GitHub sign-in is protected by hardware-key
  two-factor authentication. (Note: GitHub's REST API no longer exposes a
  usable two-factor-authentication status field for privacy reasons --
  `gh api user`'s `two_factor_authentication` field returns `null`
  unconditionally on this account as of this writing, so this cannot be
  checked programmatically from here.)
- The personal access token(s) used to push to `ghcr.io/coreyleavitt/*`
  are scoped minimally (package write only, not a broad/classic token)
  and are periodically reviewed/rotated.
- No other long-lived credential with write access to this repository,
  its packages, or its Actions configuration exists outside the owner's
  own custody.

See the handoff doc's "Open forks (awaiting Corey)" entry for a standing
request to confirm or correct the owner-attested items above.
