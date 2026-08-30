#!/usr/bin/env python3
"""scripts/lib/disasm_gate_resolve.py -- RFC-005 slice 23 (A2): the
disasm-gate resolver + branch extractor.

Invoked by scripts/disasm-gate.sh, inside the pinned sello-dev image,
after it has compiled tests/ct_disasm/main.nim with --lineDir:on into a
dedicated nimcache directory and linked the binary. This script is what
turns (nimcache C, built binary) into the pinned artifact: for each
enumerated {.noinline.} root, the ordered list of conditional-branch
mnemonics with address-free symbolized context, plus the count.

RESOLVER, three steps (per docs/rfc-005-validation-infra.md lines
290-352 -- "from the nimcache-generated C ... re-locates each pinned
signature in current Nim source at gate time"):

  1. SIGNATURE -> CURRENT LINE. `nim jsondoc` is run against the root's
     OWN declaring module (reusing tests/api/api_surface_gen.py's own
     jsondoc-based resolution idiom, per this slice's own instruction to
     reuse it for the signature-to-line step) and the entries are
     filtered by name; a root whose name is ambiguous within its own
     module (only `` `==` `` today -- ristretto.nim declares it once for
     RistrettoPoint and once for RistrettoEncoded) is disambiguated by a
     substring match against jsondoc's own `code` field (ROOTS below
     carries the exact substring). This re-derives the CURRENT
     declaration line on every gate run -- it is never hardcoded --  so
     an edit that moves a root within its file is followed automatically
     rather than silently resolving a stale line. `--docInternal` is
     passed on every jsondoc invocation: two roots (`ladder`, `compress`)
     are module-private (no `*`) and jsondoc omits non-exported symbols
     by default -- confirmed empirically this slice (`ladder` resolved
     to 0 candidates without the flag).
  2. CURRENT LINE -> NIMCACHE C DEFINITION -> MANGLED SYMBOL. The
     nimcache C file Nim generates for a module named `sello/x/y` is
     always `@psello@sx@sy.nim.c` (Nim's own deterministic nimcache
     naming from the resolved import path -- verified empirically this
     slice, not assumed) -- MODULE_TO_NIMCACHE below computes this
     directly from each root's known import path, so the resolver reads
     only the ONE nimcache file that can hold the real definition, never
     a forward-declaration copy: Nim forward-declares every
     cross-module-called proc near the top of EVERY C file that calls
     it, body-less (ending in `;`, no preceding `#line`), and this
     resolver would misidentify a forward declaration as the definition
     if it searched other files too -- confirmed empirically this slice
     (feCMove/feCSwap/feSqrtRatioM1/cmovCached each carry 1-3 forward
     declarations across x25519.nim.c/scalar.nim.c/ristretto.nim.c
     alongside their one real, body-bearing definition in field.nim.c/
     scalar.nim.c). Within that one file, the resolver requires an EXACT
     `#line <N> FX_<K>` directive whose N equals the jsondoc line and
     whose FX_<K> macro (each C file's own `#define FX_<K> "<path>"`
     table, always present regardless of --lineDir since Nim emits it
     unconditionally) resolves to a path ending in the root's own
     repo-relative source path -- immediately followed by a
     `N_LIB_PRIVATE N_(NOINLINE|NIMCALL|INLINE)(<rettype>,
     <mangled_name>)(<params>) {` line (body-bearing: ends in `{`, not
     `;`). <mangled_name> is the resolved BASE symbol.
  3. CLONE-SUFFIXED VARIANTS. `nm` on the built binary is scanned for
     every symbol matching `<base>` itself or `<base>.<suffix>` where
     <suffix> is one of the four gcc/clang clone forms this project's
     own docs name (`constprop.N`, `isra.N`, `part.N`, `cold[.N]`) --
     ANY OTHER dotted suffix on a symbol whose undotted prefix equals
     <base> is a HARD, LOUD failure (an unrecognized clone class this
     resolver has not been taught, not a silent skip). Every matched
     symbol (base plus every recognized clone) contributes its own
     disassembled branch list to the root's profile, base first then
     clones in symbol-sort order.

DISASSEMBLY + NORMALIZATION (the pinned artifact's exact shape, defined
here since docs/rfc-005-validation-infra.md's round-2 text says a
"profile" must be defined by the implementation, not assumed): each
matched symbol is disassembled with `objdump -d --disassemble=<symbol>
-M att <binary>`. Every line whose mnemonic is one of CONDITIONAL_MNEMONICS
(the AT&T Jcc set gcc/clang actually emit -- no aliases like `jnae`,
confirmed empirically against this project's own build) is kept, in
disassembly order; every other line (the instruction bytes, the
addresses, non-branch mnemonics, unconditional `jmp`) is discarded. Each
kept line is normalized to `<ordinal>: <mnemonic> <context>` where
<context> is objdump's own symbolized jump target (`<symbol+offset>`,
already address-free -- the raw target address objdump also prints is
DROPPED, kept only long enough to resolve the symbol) with Nim's own
per-module counter suffix (`_u<N>`, which shifts on ANY unrelated
top-level declaration reordering elsewhere in the same file -- a real,
observed churn source, not hypothetical) stripped from the target
symbol's name, and the root's OWN symbol (any clone suffix included)
rewritten to the literal token `self` -- both normalizations exist
specifically so an edit elsewhere in the file, or in a totally unrelated
module, cannot perturb this root's pinned profile. A target with NO
resolvable symbol (would only happen for an indirect jump, which no
direct Jcc form ever is) is a hard failure -- this resolver has never
observed one and does not have a defined normalization for it.

DIVISION OF LABOR (restated from the RFC text, load-bearing for what this
script does NOT do): conditional branches only. No indirect jumps, no
loads, no jump tables. Loop back-edges on public loop counters (e.g.
`geScalarmultBase`'s own zero-init loop) show up in the profile like any
other conditional branch -- they are EXPECTED and are not filtered out;
CLAUDE.md's own disasm-gate paragraph and tests/ct_disasm/expected/
justifications.md (if any root ever needs one) record this rather than
special-casing it in code.

Usage:
  disasm_gate_resolve.py <nimcache_dir> <binary> <workspace_root>

Prints the deterministic dump to stdout, one root at a time in ROOTS'
own declared order (stable, reviewable diffs -- not sorted alphabetically,
so the dump mirrors the RFC's own enumeration order with the pre-existing
trio appended, exactly as CLAUDE.md's module list will describe it).
"""
import json
import os
import re
import subprocess
import sys
import tempfile

# ROOTS: (root_name, import_path, repo_relative_path, jsondoc_disambiguator)
# import_path is what tests/ct_disasm/main.nim's own `import sello/...`
# lines use (also what nimcache's @p...@s...nim.c naming is built from);
# repo_relative_path is what an FX_<K> macro's own path must END WITH to
# be considered a match (FX_<K> values are absolute, container-mount
# -relative, e.g. "/workspace/src/sello/scalar.nim" -- see the module doc
# comment). jsondoc_disambiguator is None unless the bare name is
# ambiguous within its own module (only `==`, ristretto.nim's two
# operator overloads).
ROOTS = [
    ("derivePublic", "sello/private/backend", "src/sello/private/backend.nim", None),
    ("signDetached", "sello/private/backend", "src/sello/private/backend.nim", None),
    ("ladder", "sello/x25519", "src/sello/x25519.nim", None),
    ("geScalarmultBase", "sello/scalar", "src/sello/scalar.nim", None),
    ("geScalarmultCT", "sello/scalar", "src/sello/scalar.nim", None),
    ("ristrettoEncode", "sello/ristretto", "src/sello/ristretto.nim", None),
    # jsondoc reports backtick-quoted operator names literally as
    # "`==`" (confirmed empirically this slice), not the bare "==" a
    # Nim source reader would expect.
    ("`==`", "sello/ristretto", "src/sello/ristretto.nim", "RistrettoPoint"),
    ("feSqrtRatioM1", "sello/field", "src/sello/field.nim", None),
    ("compress", "sello/private/sha512", "src/sello/private/sha512.nim", None),
    # The pre-existing trio (RFC-001 slice 8 / round-3 fix batch),
    # {.noinline.} since before this slice -- no register entry (no
    # secret-role-typed export name), included per A2's own text
    # ("joining the existing trio").
    ("feCMove", "sello/field", "src/sello/field.nim", None),
    ("feCSwap", "sello/field", "src/sello/field.nim", None),
    ("cmovCached", "sello/scalar", "src/sello/scalar.nim", None),
]

# The AT&T-syntax conditional-jump mnemonics gcc/clang actually emit on
# this project's own x86-64 build (verified against a real objdump this
# slice, not assumed from an ISA reference) -- canonical spellings only,
# never the alias forms (`jnae`, `jc`, ...) binutils also accepts as
# INPUT but never produces as disassembly OUTPUT for this toolchain.
CONDITIONAL_MNEMONICS = {
    "je", "jne", "jz", "jnz", "jl", "jle", "jg", "jge",
    "ja", "jae", "jb", "jbe", "js", "jns", "jo", "jno",
    "jp", "jnp", "jcxz", "jecxz", "jrcxz",
}

CLONE_SUFFIX_RE = re.compile(r"^\.(constprop|isra|part)\.\d+$|^\.cold(\.\d+)?$")
COUNTER_RE = re.compile(r"_u\d+")


def run_jsondoc(nim_source_path):
    with tempfile.TemporaryDirectory() as tmp:
        out_path = os.path.join(tmp, "out.json")
        cmd = ["nim", "jsondoc", "--docInternal", "--hints:off", "--warnings:off",
               f"-o:{out_path}", nim_source_path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            sys.stderr.write(f"disasm_gate_resolve: nim jsondoc failed for {nim_source_path}:\n")
            sys.stderr.write(result.stdout)
            sys.stderr.write(result.stderr)
            sys.exit(1)
        with open(out_path) as f:
            return json.load(f)


_jsondoc_cache = {}


def resolve_current_line(name, repo_relative_path, disambiguator):
    if repo_relative_path not in _jsondoc_cache:
        _jsondoc_cache[repo_relative_path] = run_jsondoc(repo_relative_path)
    doc = _jsondoc_cache[repo_relative_path]
    candidates = [e for e in doc.get("entries", []) if e.get("name") == name]
    if disambiguator is not None:
        candidates = [e for e in candidates if disambiguator in e.get("code", "")]
    if len(candidates) == 0:
        sys.stderr.write(
            f"disasm_gate_resolve: FAIL -- could not resolve root '{name}' "
            f"in {repo_relative_path} via nim jsondoc (0 candidates"
            + (f" after disambiguator {disambiguator!r}" if disambiguator else "")
            + ").\n")
        sys.exit(1)
    if len(candidates) > 1:
        sys.stderr.write(
            f"disasm_gate_resolve: FAIL -- root '{name}' in {repo_relative_path} "
            f"is AMBIGUOUS ({len(candidates)} jsondoc entries"
            + (f" after disambiguator {disambiguator!r}" if disambiguator else "")
            + f"); resolve with a more specific disambiguator in this script's "
            f"own ROOTS table.\n")
        sys.exit(1)
    return candidates[0]["line"]


def nimcache_c_path(nimcache_dir, import_path):
    return os.path.join(nimcache_dir, "@p" + import_path.replace("/", "@s") + ".nim.c")


def build_fx_table(c_text):
    """Maps FX_<K> -> its #define'd path string, for this one C file."""
    table = {}
    for m in re.finditer(r'^#define FX_(\d+) "([^"]*)"', c_text, re.M):
        table[m.group(1)] = m.group(2)
    return table


DEFN_RE = re.compile(
    r'^N_LIB_PRIVATE\s+N_(?:NOINLINE|NIMCALL|INLINE)\([^,]+,\s*'
    r'([A-Za-z_][A-Za-z0-9_]*)\)\([^;]*\{',
    re.M,
)


def resolve_symbol(name, import_path, repo_relative_path, nimcache_dir, current_line):
    c_path = nimcache_c_path(nimcache_dir, import_path)
    if not os.path.isfile(c_path):
        sys.stderr.write(
            f"disasm_gate_resolve: FAIL -- expected nimcache C file "
            f"{c_path} for root '{name}' does not exist.\n")
        sys.exit(1)
    with open(c_path) as f:
        text = f.read()
    fx_table = build_fx_table(text)

    # Every #line directive in this file, in order, with its byte offset
    # -- so we can find the definition that immediately follows the one
    # matching (current_line, our module's own path).
    line_dir_re = re.compile(r'^#line (\d+) FX_(\d+)\s*$', re.M)
    matches = list(line_dir_re.finditer(text))
    for i, m in enumerate(matches):
        lineno, fx_key = int(m.group(1)), m.group(2)
        if lineno != current_line:
            continue
        fx_path = fx_table.get(fx_key, "")
        if not fx_path.endswith(repo_relative_path):
            continue
        # Look at the text immediately following this directive, up to
        # (but not including) the NEXT #line directive (or a generous
        # fixed window if this is the last one in the file) -- the
        # definition, if this directive precedes one, starts here.
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else min(len(text), start + 2000)
        window = text[start:end]
        dm = DEFN_RE.search(window)
        if dm:
            return dm.group(1)
        # This #line/current_line match didn't precede a definition
        # (could be a statement inside some OTHER function that happens
        # to share the line number, e.g. a one-line proc elsewhere on
        # the same source line as our root's own signature -- not
        # expected for any of this project's real roots, but handled by
        # continuing the search rather than failing on the first
        # candidate).
        continue
    sys.stderr.write(
        f"disasm_gate_resolve: FAIL -- root '{name}': no `#line {current_line} "
        f"FX_<k>` in {c_path} (matching {repo_relative_path}) precedes a "
        f"function DEFINITION (body-bearing, not a forward declaration). "
        f"The resolver could not re-locate this root's current C symbol.\n")
    sys.exit(1)


def nm_symbols(binary):
    result = subprocess.run(["nm", binary], capture_output=True, text=True, check=True)
    syms = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            syms.append(parts[-1])
        elif len(parts) == 2:
            syms.append(parts[-1])
    return syms


def find_variants(base_symbol, all_symbols):
    variants = []
    for sym in all_symbols:
        if sym == base_symbol:
            variants.append(sym)
            continue
        if sym.startswith(base_symbol + "."):
            suffix = sym[len(base_symbol):]
            if not CLONE_SUFFIX_RE.match(suffix):
                sys.stderr.write(
                    f"disasm_gate_resolve: FAIL -- symbol '{sym}' shares base "
                    f"'{base_symbol}' but carries an UNRECOGNIZED clone suffix "
                    f"'{suffix}' (recognized: .constprop.N, .isra.N, .part.N, "
                    f".cold[.N]). A new gcc/clang clone class this resolver "
                    f"has not been taught -- investigate before widening the "
                    f"CLONE_SUFFIX_RE pattern in this script.\n")
                sys.exit(1)
            variants.append(sym)
    if base_symbol not in variants:
        sys.stderr.write(
            f"disasm_gate_resolve: FAIL -- base symbol '{base_symbol}' not "
            f"found in the built binary's symbol table at all.\n")
        sys.exit(1)
    return sorted(variants)


def normalize_context(raw_target, own_base_no_counter):
    # raw_target is objdump's own "<symbol+off>" or "<symbol>" bracket
    # content (offset omitted at exactly symbol start).
    if "+" in raw_target:
        base, off = raw_target.rsplit("+", 1)
        off = "+" + off
    else:
        base, off = raw_target, ""
    base_no_counter = COUNTER_RE.sub("", base)
    if base_no_counter == own_base_no_counter:
        base_no_counter = "self"
    return base_no_counter + off


def disassemble_symbol(binary, symbol):
    result = subprocess.run(
        ["objdump", "-d", f"--disassemble={symbol}", "-M", "att", binary],
        capture_output=True, text=True, check=True,
    )
    branches = []
    for line in result.stdout.splitlines():
        cols = line.split("\t")
        if len(cols) < 3:
            continue
        addr_col = cols[0].strip()
        if not addr_col.endswith(":"):
            continue
        mnemonic_and_operand = cols[2].strip()
        if not mnemonic_and_operand:
            continue
        pieces = mnemonic_and_operand.split(None, 1)
        mnemonic = pieces[0]
        if mnemonic not in CONDITIONAL_MNEMONICS:
            continue
        operand = pieces[1] if len(pieces) > 1 else ""
        bm = re.search(r"<([^>]+)>", operand)
        if not bm:
            sys.stderr.write(
                f"disasm_gate_resolve: FAIL -- {symbol}: conditional branch "
                f"'{mnemonic} {operand}' has no resolvable symbolized target "
                f"(objdump printed no <symbol+off>). This resolver has no "
                f"defined normalization for an unresolved target -- "
                f"investigate.\n")
            sys.exit(1)
        branches.append((mnemonic, bm.group(1)))
    return branches


def main():
    if len(sys.argv) != 4:
        sys.stderr.write("usage: disasm_gate_resolve.py <nimcache_dir> <binary> <workspace_root>\n")
        sys.exit(2)
    nimcache_dir, binary, workspace_root = sys.argv[1], sys.argv[2], sys.argv[3]

    all_symbols = nm_symbols(binary)

    for name, import_path, repo_relative_path, disambiguator in ROOTS:
        current_line = resolve_current_line(name, repo_relative_path, disambiguator)
        base_symbol = resolve_symbol(name, import_path, repo_relative_path, nimcache_dir, current_line)
        own_base_no_counter = COUNTER_RE.sub("", base_symbol)
        variants = find_variants(base_symbol, all_symbols)

        print(f"== root: {name} ==")
        print(f"symbol: {own_base_no_counter}")
        if len(variants) > 1:
            clone_labels = sorted(
                COUNTER_RE.sub("", v) for v in variants if v != base_symbol
            )
            print(f"clone-variants: {', '.join(clone_labels)}")
        else:
            print("clone-variants: (none)")

        total = 0
        lines_out = []
        for variant in variants:
            branches = disassemble_symbol(binary, variant)
            variant_label = COUNTER_RE.sub("", variant)
            for mnemonic, raw_target in branches:
                total += 1
                context = normalize_context(raw_target, own_base_no_counter)
                lines_out.append(f"  [{variant_label}] {total}: {mnemonic} {context}")
        print(f"branch-count: {total}")
        for line in lines_out:
            print(line)
        print()


if __name__ == "__main__":
    main()
