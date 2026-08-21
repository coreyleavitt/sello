## sello/private/ct.nim — constant-time secret-hygiene primitives (RFC-001
## slice 8).
##
## DANGER: same social-contract treatment as `sello/private/backend.nim` —
## this module exists to be called FROM the secret-handling code
## (`backend.nim`, `x25519.nim`, `signing.nim`), not imported by
## application code. It has no `Keypair`/`Seed` knowledge of its own.
##
## ## Why a volatile store, not a plain loop
##
## A plain `for i in 0 ..< n: a[i] = 0` loop over memory that is dead after
## the loop (the secret has already been used for its one job) is exactly
## the pattern a C compiler is entitled to delete as a dead store once it
## can prove nothing reads `a` again — and it does: confirmed by
## disassembly at `-d:release` for `x25519.nim`'s ladder scrub (RFC-001
## slice 8 finding), the scrub loop is entirely absent from the emitted
## machine code. `volatileStoreByte` below compiles to a store through a
## `volatile`-qualified C pointer (the same idiom the standard library's
## own `std/volatile` uses), which the C standard forbids the compiler from
## proving dead — there is no "nothing reads this again" argument available
## against a volatile access. `wipe` additionally emits an
## `asm volatile("" ::: "memory")` compiler barrier immediately after the
## store loop, so the optimizer also can't reorder the wipe to before the
## secret's last real use, or otherwise hoist/reschedule it across that
## boundary. Confirmed by disassembly that this shape survives `-d:release`
## as literal store instructions (see the handoff doc for the exact check).
##
## `volatileStoreByte`'s body is a raw `{.emit.}` block, which Nim's effect
## analyzer does not look inside (verified empirically in the architect
## rounds: `{.emit.}` asm barriers compile fine inside `func` with no
## effect-checker complaint) — so `wipe` can be a `func`, matching the
## `func`-only shape of the rest of the secret-handling call sites
## (`backend.nim`, `private/sha512.nim`'s own one-shot API) with no
## `{.noSideEffect.}` friction, despite doing a raw pointer write under the
## hood.
##
## `wipe` is generic over any stack-only value type `T`, not just
## `array[N, byte]`: it wipes `sizeof(T)` bytes by raw reinterpretation, so
## the same audited primitive covers fixed secret byte arrays (`h`, `a`,
## `prefix`, `r` in `backend.nim`; `e` in `x25519.nim`; `Seed.bytes` in
## `signing.nim`) AND stack-only secret-bearing objects such as
## `private/sha512`'s `Sha512Context` (verified free of `seq`/`ref`/
## `string` — fixed arrays and scalars only), which buffers a
## secret-containing block internally and must be wiped after `finish()`
## at every call site that hashes secret input (in production, the
## one-shot `sha512` funcs do this internally before returning; the
## streaming register is test-estate only, see that module's own doc
## comment). Do not call `wipe` on a type containing a `seq`/`ref`/`string`
## field — it would zero the pointer/length header, not the heap payload,
## silently leaving the real secret bytes alive on the heap.

## Compiler-enforced effect contract (janus consumer finding 3) -- see
## `signing.nim`'s module doc for the surface-wide policy. A wipe
## primitive that could raise or touch global state would defeat its own
## every-exit-path guarantee.
{.push raises: [], gcsafe.}
{.push checks: off.}

func volatileStoreByte(dest: ptr byte; val: byte) {.inline.} =
  ## Store `val` through `dest` as a volatile write, so the C compiler
  ## cannot prove the store dead and elide it (see module doc). Same emit
  ## shape as the standard library's `std/volatile.volatileStore`,
  ## specialized to `byte` and reimplemented here (rather than imported)
  ## so it is a `func` — `std/volatile`'s version is a `proc`, which a
  ## `func` caller may not invoke directly.
  {.emit: ["*((volatile unsigned char*)(", dest, ")) = ", val, ";"].}

func wipe*[T](data: var T) {.noinline.} =
  ## Zero every byte of `data` via `volatileStoreByte`, then a compiler
  ## memory barrier (`asm volatile("" ::: "memory")`). `{.noinline.}` so
  ## the call site itself can't be inlined away in a context where the
  ## optimizer decides the (apparently unobserved) result is dead —
  ## belt-and-suspenders alongside the per-byte volatile stores. One
  ## audited wipe primitive for every secret shape in the codebase, in
  ## place of a hand-rolled scrub loop at each call site.
  let base = cast[ptr UncheckedArray[byte]](addr data)
  for i in 0 ..< sizeof(T):
    volatileStoreByte(addr base[i], 0'u8)
  {.emit: "asm volatile(\"\" ::: \"memory\");".}

func volatileStoreWord(dest: ptr uint64; val: uint64) {.inline.} =
  ## Word-granular sibling of `volatileStoreByte`: stores `val` through
  ## `dest` as a volatile 64-bit write, same reasoning as the byte
  ## primitive above (the C standard forbids the compiler from proving a
  ## volatile store dead).
  {.emit: ["*((volatile unsigned long long*)(", dest, ")) = ", val, ";"].}

func wipe*[N: static int](data: var array[N, uint64]) {.noinline.} =
  ## Word-granular sibling of the byte-generic `wipe[T]` above (RFC-006
  ## slice-1b amendment, see `docs/rfc-006-sha512.md`'s Hygiene section
  ## and `docs/rfc-006-sha512.handoff.md`'s slice-1b finding): `N`
  ## volatile per-`uint64` stores instead of `8*N` per-byte stores, then
  ## the identical `asm volatile("" ::: "memory")` barrier. Exists because
  ## `sha512.compress`'s per-call wipe of its message schedule and working
  ## variables, measured against a 704-byte scratch region wiped one byte
  ## at a time, cost roughly 50% overhead — far past the RFC's
  ## single-digit-percent expectation. Overload resolution routes any
  ## `array[N, uint64]` argument to THIS overload automatically (Nim
  ## prefers the more specific signature over the generic `T` one) — no
  ## call site chooses a register by name, so a secret-holding
  ## `array[N, uint64]` cannot accidentally take the slower byte-generic
  ## path, or vice versa. The byte-generic `wipe[T]` above is untouched
  ## and stays the primitive for every non-`array[N, uint64]` secret shape
  ## in the codebase (fixed byte arrays, `Sha2Context`-shaped objects,
  ## ...). Like the byte-generic wipe, this joins the slice-4 disassembly
  ## obligation (RFC-006): confirming the wipe survives as genuine store
  ## instructions at `-d:release`, not eliminated as a dead store to
  ## locals with no further read.
  let base = cast[ptr UncheckedArray[uint64]](addr data)
  for i in 0 ..< N:
    volatileStoreWord(addr base[i], 0'u64)
  {.emit: "asm volatile(\"\" ::: \"memory\");".}

{.pop.}
{.pop.}
