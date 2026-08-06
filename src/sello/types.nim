## sello/types.nim — nominal public wire types (RFC-001 findings 9/11,
## relocated here by round-2 findings 27/28).
##
## Leaf module: nominal wire types, their conversions, and the one audited
## generic secret-wipe wrapper -- no crypto logic. Sits below both
## `ed25519.nim` (verify) and `signing.nim` (sign) so they can share these
## definitions on a common downward dependency instead of one importing
## the other's module just to borrow two type names. May import
## `sello/private/ct` (a leaf itself, no crypto logic of its own either)
## for `wipe`; nothing here reaches into `field.nim`/`scalar.nim` group-ops
## machinery -- these types never touch that arithmetic, which is exactly
## why they no longer live in `scalar.nim` (finding 27: `scalar.nim`'s
## mandate is Curve25519 group operations, not wire-format bookkeeping).
##
## Honesty note on cohesion: the wire types and the generic wipe share
## this module for import-graph position (both must sit on a leaf below
## every consumer), not for a common purpose — the wipe never operates on
## this module's own PUBLIC types. Two leftover leaf concerns, one roof.
##
## ---------------------------------------------------------------------
## PublicKey, Signature (RFC-001 finding 9)
## ---------------------------------------------------------------------
##
## `distinct array[N, byte]`, not a plain alias: a plain alias let
## `verify(x25519Key, msg, sig)` or transposed same-size arguments compile
## silently, since every 32/64-byte value in the codebase was structurally
## the same type. Contrast with `Seed` (signing.nim): `Seed` also went
## nominal, but for a different reason (attaching a wipe-on-destroy hook to
## a secret) and paid a real price for it (its RFC-specified `distinct`
## form silently drops `=destroy` for a bare local — see signing.nim's
## module doc comment — forcing the one-field-object fallback). Neither
## pitfall applies here: `PublicKey`/`Signature` hold PUBLIC values (a
## compressed point, a signature) with no secret to protect, so there is no
## destructor to attach and therefore nothing for `distinct`'s `=destroy`
## gap to break. Plain `distinct array` is the right tool for this job.
##
## Construction is the free `Type(bytes)` cast every distinct type gets
## (see `toPublicKey`/`toSignature` below, added for symmetry with
## `signing.toSeed` and for grep-discoverability, not because the cast
## needs a wrapper to work); `toBytes` is the reverse, for serialization.
## `==`/`$` are borrowed from the underlying array — comparing two PUBLIC
## values (public keys, signatures) carries no constant-time requirement,
## so plain equality is correct here. Contrast `signing.Seed`, which holds
## secret material and (RFC-002 slice 1) has no `==` at all.
##
## ---------------------------------------------------------------------
## Generic array wipe (RFC-001 finding 11, relocated here by finding 28)
## ---------------------------------------------------------------------
##
## `wipe*(var array[32, byte])` delegates to the one audited primitive,
## `private/ct.wipe`. Previously homed in `x25519.nim` alongside the
## X25519-specific `wipe` overloads (`X25519StaticSecret`/`X25519Shared`
## today, `X25519Key` at the time of this move), despite covering any 32-byte
## secret shape, not just X25519 material (e.g. a raw `Seed`-shaped buffer
## a caller manages by hand outside `signing.Seed`). Living here instead
## means `x25519.nim` keeps only the X25519-specific overloads it actually
## has business owning, and a future secret-holding module gains the
## generic primitive from this shared leaf rather than reaching sideways
## into X25519's module or duplicating the wrapper.

import std/hashes
import sello/private/ct

type
  PublicKey* = distinct array[32, byte]
    ## ed25519 compressed public point (RFC 8032 §5.1.5), 32 bytes.
  Signature* = distinct array[64, byte]
    ## ed25519 detached signature R || S (RFC 8032 §5.1.6), 64 bytes.

func toPublicKey*(bytes: array[32, byte]): PublicKey {.inline.} =
  ## Explicit construction from raw bytes (e.g. a decoded wire value).
  PublicKey(bytes)

func toSignature*(bytes: array[64, byte]): Signature {.inline.} =
  ## Explicit construction from raw bytes (e.g. a decoded wire value).
  Signature(bytes)

func toBytes*(pk: PublicKey): array[32, byte] {.inline.} =
  ## Raw bytes back out, e.g. for serialization.
  array[32, byte](pk)

func toBytes*(sig: Signature): array[64, byte] {.inline.} =
  ## Raw bytes back out, e.g. for serialization.
  array[64, byte](sig)

func `==`*(a, b: PublicKey): bool {.borrow.}
  ## Comparing two PUBLIC values — no constant-time requirement.
func `==`*(a, b: Signature): bool {.borrow.}
  ## Comparing two PUBLIC values — no constant-time requirement.
func `$`*(pk: PublicKey): string {.borrow.}
func `$`*(sig: Signature): string {.borrow.}

func hash*(pk: PublicKey): Hash {.inline.} =
  ## Hash of the underlying bytes (RFC-002 slice 1) -- unblocks
  ## Table/HashSet keying (peer registries, session caches). No
  ## constant-time requirement, same reasoning as `==` above.
  hash(array[32, byte](pk))

func hash*(sig: Signature): Hash {.inline.} =
  ## Hash of the underlying bytes (RFC-002 slice 1). No constant-time
  ## requirement, same reasoning as `==` above.
  hash(array[64, byte](sig))

proc wipe*(bytes: var array[32, byte]) =
  ## Audited wipe (volatile stores + compiler barrier, see
  ## `private/ct.nim`) of raw 32-byte secret material a caller is holding
  ## outside of any of sello's own secret-carrying types -- `Seed`
  ## (`signing.wipe`) and `X25519StaticSecret`/`X25519Shared` (`x25519.wipe`)
  ## each get their own typed overload that delegates to this same
  ## audited primitive.
  ct.wipe(bytes)
