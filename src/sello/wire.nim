## sello/wire.nim — nominal public wire types (RFC-001 findings 9/11,
## relocated here by round-2 findings 27/28, split out of the combined
## `types.nim` by RFC-002 slice 2 item 5).
##
## Leaf module: `PublicKey`/`Signature`, their conversions, and `==`/`$`/
## `hash` -- no crypto logic, and (unlike the generic secret wipe that used
## to share this module as `types.nim`) no `private/ct` import either, since
## these types hold no secret to wipe. Sits below both `ed25519.nim`
## (verify) and `signing.nim` (sign) so they can share these definitions on
## a common downward dependency instead of one importing the other's
## module just to borrow two type names.
##
## `types.nim` used to hold this module's contents plus the unrelated
## generic `wipe*(var array[32, byte])` -- sharing a roof for import-graph
## position only, a "two leftover leaf concerns, one roof" cohesion gap its
## own doc comment admitted. RFC-002 slice 2 resolves that by splitting the
## roof itself: this module keeps the wire types (and needs no
## `private/ct` import at all, since it never did), `sello/wipe` gets the
## generic wipe. Both are leaves; nothing here reaches into
## `field.nim`/`scalar.nim` group-ops machinery -- these types never touch
## that arithmetic, which is exactly why they don't live in `scalar.nim`
## (finding 27: `scalar.nim`'s mandate is Curve25519 group operations, not
## wire-format bookkeeping).
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

import std/hashes

type
  PublicKey* = distinct array[32, byte]
    ## ed25519 compressed public point (RFC 8032 §5.1.5), 32 bytes.
  Signature* = distinct array[64, byte]
    ## ed25519 detached signature R || S (RFC 8032 §5.1.6), 64 bytes.
    ##
    ## **Malleability (RFC-003 slice 1 item 4, condensed from
    ## `ed25519.verify`'s full writeup):** RFC 8032's cofactorless
    ## verification equation admits a second, distinct, ALSO-valid
    ## signature for the same `(msg, pk)` pair -- so signature bytes are
    ## NOT a unique identifier for what was signed. This matters here
    ## specifically because `hash`/`==` below make `Signature` usable as a
    ## `Table`/`HashSet` key, and a signature-keyed replay/dedup cache is
    ## exactly the natural use those operators invite -- do not build one
    ## keyed on the signature bytes; key on `(msg, pk)` instead. Full
    ## explanation: `ed25519.verify`'s doc comment.

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
  ## Comparing two PUBLIC values — no constant-time requirement. **Byte
  ## equality is not "same signing event"**: RFC 8032's cofactorless
  ## verify equation admits a second, distinct signature that also
  ## verifies for the same `(msg, pk)` — see `Signature`'s own doc
  ## comment above and `ed25519.verify`'s full writeup. Do not use this to
  ## decide whether two signatures represent the same signed message.
func `$`*(pk: PublicKey): string {.borrow.}
func `$`*(sig: Signature): string {.borrow.}

func hash*(pk: PublicKey): Hash {.inline.} =
  ## Hash of the underlying bytes (RFC-002 slice 1) -- unblocks
  ## Table/HashSet keying (peer registries, session caches). No
  ## constant-time requirement, same reasoning as `==` above.
  hash(array[32, byte](pk))

func hash*(sig: Signature): Hash {.inline.} =
  ## Hash of the underlying bytes (RFC-002 slice 1). No constant-time
  ## requirement, same reasoning as `==` above. **Do not key a
  ## replay/dedup cache on this hash**: RFC 8032's cofactorless verify
  ## equation admits a second, distinct signature for the same `(msg,
  ## pk)`, which hashes differently despite representing the same signing
  ## event — see `Signature`'s own doc comment and `ed25519.verify`'s full
  ## writeup. Key such a cache on `(msg, pk)` instead.
  hash(array[64, byte](sig))
