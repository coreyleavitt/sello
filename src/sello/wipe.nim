## sello/wipe.nim — the generic secret-array wipe (RFC-001 finding 11,
## relocated to `types.nim` by finding 28, split out on its own by RFC-002
## slice 2 item 5).
##
## Leaf module, one export: `wipe*(var array[32, byte])`, delegating to the
## one audited primitive, `private/ct.wipe`. Previously homed in
## `x25519.nim` alongside the X25519-specific `wipe` overloads
## (`X25519StaticSecret`/`X25519Shared` today, `X25519Key` at the time of
## that move), despite covering any 32-byte secret shape, not just X25519
## material (e.g. a raw `Seed`-shaped buffer a caller manages by hand
## outside `signing.Seed`); then folded into the combined `types.nim`
## alongside the unrelated `PublicKey`/`Signature` wire types, sharing that
## module's leaf position but nothing else -- an admitted cohesion gap
## (`types.nim`'s own "two leftover leaf concerns, one roof" doc comment).
## This module resolves that by giving the wipe its own single-purpose
## roof: `sello/wire` keeps the wire types (and needs no `private/ct`
## import at all now, since it never did); this module keeps the wipe (and
## needs nothing else). A future secret-holding module gains the generic
## primitive from this shared leaf rather than reaching sideways into
## X25519's module or duplicating the wrapper.

import sello/private/ct

## Compiler-enforced effect contract (janus consumer finding 3) -- see
## `signing.nim`'s module doc for the surface-wide policy.
{.push raises: [], gcsafe.}

proc wipe*(bytes: var array[32, byte]) =
  ## Audited wipe (volatile stores + compiler barrier, see
  ## `private/ct.nim`) of raw 32-byte secret material a caller is holding
  ## outside of any of sello's own secret-carrying types -- `Seed`
  ## (`signing.wipe`) and `X25519StaticSecret`/`X25519Shared` (`x25519.wipe`)
  ## each get their own typed overload that delegates to this same
  ## audited primitive.
  ct.wipe(bytes)

{.pop.}
