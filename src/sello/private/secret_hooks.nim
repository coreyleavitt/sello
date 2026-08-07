## sello/private/secret_hooks.nim — shared secret-lifecycle hook templates
## (round-3 finding A5).
##
## The `=destroy`/wipe pair (plus, for the move-only types, `=copy
## {.error.}`) is hand-copied, identically shaped, five times today:
## `signing.Seed`, and `x25519.X25519StaticSecret`/`X25519EphemeralSecret`/
## `X25519Shared`. Every copy is the same three-line skeleton -- a named
## `zeroize<Type>` proc that routes the type's one `bytes` field through
## `ct.wipe`, an `=destroy` bound to it, and (for the move-only types) a
## `=copy {.error.}`. This module gives that skeleton one definition,
## instantiated at each type's declaration site instead of retyped.
##
## `Keypair` (`signing.nim`) deliberately does NOT go through this module:
## it has no `bytes` field of its own to wipe -- it relies on the
## compiler-synthesized field-wise destructor to call its `Seed` field's
## own `=destroy` -- so it doesn't fit the "wipe this one field" shape the
## templates below capture. Only its `=copy {.error.}` is move-only
## boilerplate, and forcing that one line through a two-type-parameter
## abstraction (one for the wipe, a no-op for the field it doesn't have)
## would obscure more than it saves for a single call site. `Keypair`'s
## hooks stay hand-written.
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
## One observable consequence of `{.dirty.}`, worth recording so it isn't
## mistaken for a bug later: `{.dirty.}` defers ALL symbol resolution to
## the instantiation site, including the `ct.wipe` call below -- so this
## module's own `import sello/private/ct` is not actually what makes
## `ct.wipe` resolve inside an expanded `secretHooks`/`secretHooksMoveOnly`
## call; the CALLER'S `import sello/private/ct` is (both `signing.nim` and
## `x25519.nim` already have one, for their own other direct `ct.wipe`
## uses). The compiler flags this import itself as unused (`Warning:
## imported and not used: 'ct'`) precisely because of that -- harmless,
## and kept anyway as documentation of this module's real dependency,
## should a future caller not already import `ct` on its own.

import sello/private/ct

template secretHooks*(T: typedesc; zeroizeProc, field: untyped) {.dirty.} =
  ## Emits `zeroizeProc(s: var T)` (wipes `s.field` via the one audited
  ## `ct.wipe` primitive) and `=destroy` bound to it. Does NOT emit `=copy`
  ## -- see `secretHooksMoveOnly` below for the move-only variant. Use this
  ## for a COPYABLE secret type (`X25519StaticSecret`/`X25519Shared`
  ## today): every copy gets its own destructor and self-wipes
  ## independently at its own scope exit, which is correct for a type with
  ## no paired invariant a second live copy could violate.
  proc zeroizeProc(s: var T) {.inline.} =
    ct.wipe(s.field)
  proc `=destroy`(s: var T) =
    zeroizeProc(s)

template secretHooksMoveOnly*(T: typedesc; zeroizeProc, field: untyped) {.dirty.} =
  ## `secretHooks` plus a move-only `=copy {.error.}`: a second live copy
  ## of this type's secret is a compile error, not a runtime hygiene
  ## footnote (RFC-002 slice 1 / RFC-001 slice 5's `Keypair` pattern). Use
  ## for `Seed`/`X25519EphemeralSecret` today.
  secretHooks(T, zeroizeProc, field)
  proc `=copy`(dst: var T; src: T) {.error.}
