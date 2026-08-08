## sello/private/secret_hooks.nim — shared secret-lifecycle hook templates
## (round-3 finding A5; simplified to a two-argument signature by round-4
## finding R10).
##
## The `=destroy` (plus, for the move-only types, `=copy {.error.}`) is
## hand-copied, identically shaped, five times today: `signing.Seed`, and
## `x25519.X25519StaticSecret`/`X25519EphemeralSecret`/`X25519Shared`. Every
## copy is the same one-line skeleton -- an `=destroy` that routes the
## type's one `bytes` field through `ct.wipe`, and (for the move-only
## types) a `=copy {.error.}`. This module gives that skeleton one
## definition, instantiated at each type's declaration site instead of
## retyped.
##
## **R10 (round-4): no more `zeroizeProc` name parameter.** The templates
## used to take a THIRD argument -- a per-type proc name
## (`zeroizeSeed`, `zeroizeX25519StaticSecret`, ...) -- purely so each
## instantiation could emit a same-shaped-but-uniquely-named
## `zeroize<Type>(s: var T)` proc that `=destroy` called. That name existed
## only to work around dirty-template hygiene at the call site; the design
## itself needs no separately-named zeroize proc. `=destroy` now inlines
## `ct.wipe(x.field)` directly. Callers that used to reach the wipe via
## `zeroize<Type>(s)` (the public `wipe*` procs in `signing.nim`/
## `x25519.nim`) now call `ct.wipe(s.bytes)` directly instead -- they are in
## the same module as the type, have field access, and already import
## `sello/private/ct` for exactly this. They deliberately do NOT call
## `` `=destroy`(s) `` (that invites double-destroy questions); calling
## `ct.wipe` directly is the same pattern the generic `array[32, byte]`
## overload in `wipe.nim` already uses.
##
## `Keypair` (`signing.nim`) deliberately does NOT go through this module:
## it has no `bytes` field of its own to wipe -- it relies on the
## compiler-synthesized field-wise destructor to call its `Seed` field's
## own `=destroy` -- so it doesn't fit the "wipe this one field" shape the
## templates below capture. Only its `=copy {.error.}` is move-only
## boilerplate, and forcing that one line through a type-parameter
## abstraction (for a single call site) would obscure more than it saves.
## `Keypair`'s hooks stay hand-written.
##
## Lives under `private/` (not `wire.nim`, which holds no-secret wire types
## entirely out of scope for a wipe-hook facility; not `wipe.nim`, whose
## whole contract is the one generic `array[32, byte]` wipe overload, not a
## hook-generation facility) alongside `private/ct.nim`, since both
## `signing.nim` and `x25519.nim` already import `sello/private/ct` and are
## exactly the two modules that need this.
##
## ## Why `{.dirty.}`
##
## Both templates emit `proc \`=destroy\`` (and, for the move-only variant,
## `proc \`=copy\`` too) as genuine top-level declarations at the
## instantiation site -- Nim's ARC/ORC type-bound-operator lookup finds a
## type's destructor/copy-hook by the EXACT literal name `=destroy`/`=copy`
## bound to that type by signature, not by some hygiene-mangled alias. A
## template's default hygiene renames symbols it introduces that are not
## template parameters (which `=destroy`/`=copy` are not -- they are fixed
## names written directly in the template body), which would silently
## produce a proc ARC/ORC does not recognize as the hook at all -- not a
## compile error, a silently-inert destructor. `{.dirty.}` disables hygiene
## for the whole template body, so expansion is textually equivalent to
## hand-writing the same code at the call site -- the same guarantee the
## former hand-copied boilerplate had, preserved exactly, which is the
## whole point of a "zero behavior change" consolidation.
##
## ## `ct.wipe` resolution: the caller MUST `import sello/private/ct`
##
## `{.dirty.}` defers ALL symbol resolution to the instantiation site,
## including the `ct.wipe` call the expanded `=destroy` body makes -- so
## this module's own `import sello/private/ct` below is NOT what makes
## `ct.wipe` resolve inside an expanded `secretHooks`/`secretHooksMoveOnly`
## call; the CALLER'S OWN `import sello/private/ct` is (both `signing.nim`
## and `x25519.nim` already have one, for their own other direct `ct.wipe`
## uses). **Any future module instantiating either template must import
## `sello/private/ct` itself**, or the expansion fails to compile with an
## undeclared-identifier error pointing at `ct.wipe` inside what looks like
## someone else's template body -- worth knowing up front rather than
## puzzling out from that error alone. This module's own import is flagged
## by the compiler as unused (`Warning: imported and not used: 'ct'`)
## precisely because of this -- harmless, and kept anyway as documentation
## of the real dependency.

import sello/private/ct

template secretHooks*(T: typedesc; field: untyped) {.dirty.} =
  ## Emits `=destroy` for `T`, wiping `s.field` via the one audited
  ## `ct.wipe` primitive. Does NOT emit `=copy` -- see `secretHooksMoveOnly`
  ## below for the move-only variant. Use this for a COPYABLE secret type
  ## (`X25519StaticSecret`/`X25519Shared` today): every copy gets its own
  ## destructor and self-wipes independently at its own scope exit, which
  ## is correct for a type with no paired invariant a second live copy
  ## could violate.
  proc `=destroy`(s: var T) =
    ct.wipe(s.field)

template secretHooksMoveOnly*(T: typedesc; field: untyped) {.dirty.} =
  ## `secretHooks` plus a move-only `=copy {.error.}`: a second live copy
  ## of this type's secret is a compile error, not a runtime hygiene
  ## footnote (RFC-002 slice 1 / RFC-001 slice 5's `Keypair` pattern). Use
  ## for `Seed`/`X25519EphemeralSecret` today.
  secretHooks(T, field)
  proc `=copy`(dst: var T; src: T) {.error.}
