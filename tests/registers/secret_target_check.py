#!/usr/bin/env python3
"""tests/registers/secret_target_check.py -- RFC-005 slice 20 (A7): the
two-rule completeness check.

Rule 1: every exported proc accepting an enumerated secret-role type
(`Seed`, `Keypair`, `X25519StaticSecret`, `X25519EphemeralSecret`,
`X25519Shared`, `RistrettoStaticSecret`, `RistrettoEphemeralSecret`,
`RistrettoShared` -- `Keypair` explicitly included, closing the round-1
gap where a check scoped to `distinct array` role types alone made
`sign`'s own `Keypair` parameter invisible) must appear in
`tests/registers/secret_targets.nim`.

Rule 2: every exported secret-IMPORT constructor (a `to*Secret*`/
`toSeed*`-pattern proc whose first parameter is a bare `array[...]`, the
boundary where bytes *become* a secret, which no role type can
type-match) must appear in the register too.

Both rules are scoped to `src/sello.nim`'s FACADE surface (matching
`tests/api/api_surface_gen.py`'s own scope, and this slice's own
instruction to reuse that generator's jsondoc-based signature resolution
"rather than writing a second signature scanner" -- a naive grep over
signatures was tried and rejected by the RFC's own round-2 note; a
jsondoc-resolved signature set is not naive). Raw-byte intakes OUTSIDE
both patterns (`ristrettoFromUniformBytes`, SHA-512's message) are
register-curated with review as the control -- **stated as such, not
claimed mechanical**, per A7's own text
(docs/rfc-005-validation-infra.md lines 444-497). This checker does not
attempt to detect that annex mechanically; it is reviewed by hand at
register-authoring time, same as `api_surface_gen.py`'s own documented
blind spots.

Both build configs (`plain`, `selloLibsodium`) are checked: the facade
widens under `-d:selloLibsodium` (an extra export, widened `{.raises.}`
on the sign/keygen path -- see `tests/api/api_surface_gen.py`'s own doc
comment), so a secret-role-typed export gated behind that flag would be
invisible to a plain-only scan.

Usage:
  python3 tests/registers/secret_target_check.py

Requires: a `nim` on PATH (shells out to `nim jsondoc` via the imported
`api_surface_gen` module), run from the repository root with `nim.cfg`
already present -- identical prerequisite to `api_surface_gen.py` itself.
Exit 0 and a summary line per config on success; exit 1 with a named
diff (missing register entries, by rule and by config) on failure.
"""
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "api"))
import api_surface_gen as asg  # noqa: E402

SECRET_ROLE_TYPES = [
    "Seed",
    "Keypair",
    "X25519StaticSecret",
    "X25519EphemeralSecret",
    "X25519Shared",
    "RistrettoStaticSecret",
    "RistrettoEphemeralSecret",
    "RistrettoShared",
]
SECRET_ROLE_RE = re.compile(r"\b(" + "|".join(SECRET_ROLE_TYPES) + r")\b")

# to*Secret*-pattern or toSeed*-pattern -- the two secret-IMPORT-
# constructor naming shapes this codebase actually uses (verified against
# every export in src/sello.nim at this slice's authoring time: exactly
# toX25519StaticSecret, toSeed, toRistrettoStaticSecret,
# toRistrettoStaticSecretWide match; toPublicKey/toSignature/
# toX25519Public/toRistrettoEncoded/toBytes do not, correctly, since none
# of them constructs a secret).
IMPORT_CTOR_RE = re.compile(r"^(to\w*Secret\w*|toSeed\w*)$")

REGISTER_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "secret_targets.nim")


def param_section(code):
    """Isolate a jsondoc `code` string's parameter list -- the text
    between the proc's own opening paren and its MATCHING closing paren
    (a depth-counted scan, not a `\\((.*?)\\):` regex, since a void proc's
    code has no `):  ReturnType` after its param list at all -- e.g.
    `proc wipe(s: var X25519StaticSecret) {.raises: [], ...}` -- and a
    regex anchored on a trailing `:` silently produced an EMPTY match for
    every void-returning secret-role wipe overload, undercounting rule 1
    by exactly the three `wipe` entries until this was caught against a
    real jsondoc run and fixed before this slice's first push)."""
    start = code.find("(")
    if start == -1:
        return ""
    depth = 0
    for i in range(start, len(code)):
        if code[i] == "(":
            depth += 1
        elif code[i] == ")":
            depth -= 1
            if depth == 0:
                return code[start + 1 : i]
    return ""


def first_param_type(params):
    if not params.strip():
        return ""
    first = params.split(";")[0]
    if ":" not in first:
        return ""
    return first.split(":", 1)[1].strip()


def compute_required(config):
    """Returns (rule1_tokens, rule2_tokens) -- sets of "<resolved-module>.
    <symbol>" strings, the exact token shape `secret_targets.nim`'s own
    `qualifiedProc` field uses for a facade-exported entry."""
    exports = asg.parse_exports(asg.FACADE)
    index = asg.build_corpus_index(config)
    rule1 = set()
    rule2 = set()
    for qualifier, symbol, libsodium_only in exports:
        if config == "plain" and libsodium_only:
            continue
        resolved_module, entries = asg.resolve(qualifier, symbol, index)
        token = f"{resolved_module}.{symbol}"
        for entry in entries:
            params = param_section(entry.get("code", ""))
            if SECRET_ROLE_RE.search(params):
                rule1.add(token)
            if IMPORT_CTOR_RE.match(symbol) and first_param_type(params).startswith("array["):
                rule2.add(token)
    return rule1, rule2


def parse_register():
    """Light, single-pass text scan over secret_targets.nim -- the same
    register-shaped precedent scripts/ct-taint.sh's own taint-column
    check and scripts/gates-manifest-check.sh's awk scan already
    establish for a hand-written, reviewed source file, rather than
    compiling and running a probe binary just to enumerate string
    fields. Returns the set of `qualifiedProc` tokens for every entry
    with `facadeExported: true`."""
    text = open(REGISTER_PATH).read()
    blocks = re.split(r"\n  st\w+: SecretTargetEntry\(", text)[1:]
    registered = set()
    for block in blocks:
        fe = re.search(r"facadeExported:\s*(true|false)", block)
        qp = re.search(r'qualifiedProc:\s*"([^"]*)"', block)
        if fe and qp and fe.group(1) == "true":
            registered.add(qp.group(1))
    return registered


def main():
    ok = True
    registered = parse_register()
    for config in ("plain", "selloLibsodium"):
        rule1, rule2 = compute_required(config)
        missing1 = sorted(rule1 - registered)
        missing2 = sorted(rule2 - registered)
        if missing1:
            sys.stderr.write(
                f"secret_target_check [{config}]: FAIL -- rule 1 (exported "
                f"proc accepting a secret-role type) has no register "
                f"entry for: {missing1}\n"
            )
            ok = False
        if missing2:
            sys.stderr.write(
                f"secret_target_check [{config}]: FAIL -- rule 2 (exported "
                f"secret-import constructor) has no register entry for: "
                f"{missing2}\n"
            )
            ok = False
        print(
            f"secret_target_check [{config}]: rule1 required={len(rule1)} "
            f"rule2 required={len(rule2)}, all present in register: "
            f"{not (missing1 or missing2)}"
        )
    if not ok:
        sys.exit(1)
    print(
        "secret_target_check: PASS -- every rule-1/rule-2 required facade "
        "export (both build configs) has a tests/registers/secret_targets.nim entry."
    )


if __name__ == "__main__":
    main()
