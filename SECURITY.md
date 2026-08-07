# Security policy

## Reporting a vulnerability

Open a GitHub issue on this repository, or email the author directly
(Corey Leavitt, `corey@leavitt.dev`) if you would rather not disclose
details in public first. There is no dedicated security-report address or
PGP key at this time -- for a solo, pre-1.0 project, a plain issue or
email is the whole intake process.

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
