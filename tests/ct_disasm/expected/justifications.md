# tests/ct_disasm/expected/justifications.md

RFC-005 slice 23 (A2). The disasm gate's own curated sibling to its two
per-backend baselines (`gcc.txt`/`clang.txt`), per this project's
standing rule: **a branch finding is never suppressed by widening a
baseline without a written rationale here.** Both baselines pin every
conditional branch the resolver finds, unfiltered -- this file records
*why* the branches that are NOT a secret-dependent leak are expected,
so a reviewer reading a baseline diff has the same context the original
gate author did.

## Two expected-branch classes, confirmed present in every root

**1. Stack-protector canaries.** The pinned image's gcc/clang both ship
with `-fstack-protector-strong` on by default (openSUSE Tumbleweed's own
distro default, not a flag this project's build passes). Every root
whose C function frame carries a large-enough local buffer gets one
`cmpb $0x0,%fs:(%rax); jne <fail>` canary check inserted near its
epilogue -- and, for a root that inlines several `{.inline.}` field-
arithmetic helpers (`feSqrtRatioM1` inlines `feMul`/`feSquare` multiple
times, `derivePublic`/`signDetached` inline SHA-512's own arithmetic),
ONE canary check per inlined call site whose own locals cross the
protector's threshold, not one per root -- this is why `feSqrtRatioM1`
shows 8 branches under gcc (one per inlined multiply/square call) rather
than the single check a reader might expect from source alone. Confirmed
non-secret-dependent by direct inspection: the compared value is
`%fs:(%rax)` (a fixed thread-local canary, `%rax` computed from a
constant stack offset) against the canary's own on-stack copy -- never a
function parameter, never a value derived from `b`/`swap`/`digit`/`s`
(the mask/scalar/digit inputs every disasm-gate root's own CT contract
protects). See `field.feCMove`'s own worked example in
`scripts/lib/disasm_gate_resolve.py`'s module doc comment and this
slice's handoff entry for the full byte-level trace.

**2. Pointer-distance vectorization dispatch.** `feCMove`/`feCSwap`
(gcc profile) each carry one additional branch of the shape
`cmp $0x8,%rax; jbe <scalar-fallback>` -- gcc's auto-vectorizer inserting
a runtime check of the DISTANCE BETWEEN THE TWO POINTER ARGUMENTS (`r`/`a`
vs. `b`, i.e. `rdi - rsi`) to decide whether a 16-byte SSE `movdqu`/`pxor`
/`pand` sequence is safe (the two `Fe` operands could alias too closely
for that width) or whether the scalar 4-byte fallback path must run
instead. This is a real conditional branch and it IS present in the
pinned profile -- but its condition is PUBLIC ADDRESS ARITHMETIC (where
the caller placed its `Fe` locals on the stack), never `b` (the CT
selection mask) or any field-limb VALUE. Confirmed by direct inspection:
`%edx`/`%xmm1` (the mask, broadcast via `pshufd`) appears only in the
masked `pxor`/`pand`/`pxor` sequence on both the vectorized and scalar
sides identically -- never in a `cmp`/`test` of its own.

## Loop back-edges

A.2's own text ("loop back-edges on public counters are expected
branches") applies here too, though no root in this slice's probe
happens to compile down to a visible back-edge distinct from the two
classes above (`geScalarmultBase`'s public zero-init loop over a
compile-time-bounded 0..0x80 range got fully unrolled at -O3 in both
backends' profiles observed this slice) -- recorded as a standing,
pre-authorized rationale for if/when a future compiler bump reintroduces
one, rather than something this file only covers after the fact.

## What would NOT get a rationale here

A branch whose condition traces to a disasm-gate root's own secret
parameter (`b`/`swap`/`digit` for the trio; `s`/`p` for the
scalarmult pair; `seed`/`msg` for the signing pair; the ristretto/field
CT primitives' own operands) is never justified away -- it is the
class this gate exists to catch (Stage-4 finding 1, `feSqrtRatioM1`'s
secret-dependent jump surviving `-O3`, is the precedent). Stage 3's red
demo reintroduces exactly that class deliberately, to confirm the gate
still catches it.
