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
