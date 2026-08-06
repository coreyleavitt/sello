## sello/challenge.nim — the ed25519 challenge hash (RFC 8032 §5.1.6 step 4
## / §5.1.7 step 2).
##
## k = SHA-512(R || A || msg) mod L, the one audited copy of the formula
## shared by verify (`ed25519.verify`) and signing (`private/backend.
## signDetached`) -- two hand-maintained copies would be a latent
## sign/verify self-consistency break with no compiler signal. R, A, msg,
## and k are all public in both protocols, so this carries no
## constant-time requirement of its own.
##
## Relocated out of `scalar.nim` (RFC-002 slice 2 item 1): `challenge` was
## the one thing in that file pulling in nimcrypto's SHA-512, sitting on
## top of the SHA-512-free field-and-curve math that is the rest of
## `scalar.nim`'s actual mandate -- the same "one import serving a single
## unrelated corner of the file" disease round-2 finding 27 evicted the
## wire types for. Pulling it out here leaves `scalar.nim` with no
## nimcrypto import at all: a true field-plus-curve-math leaf. Sits above
## `scalar.nim` (for `scReduce`), consumed by `ed25519.nim` (verify) and
## `private/backend.nim` (sign) -- the same two-upward-consumer shape that
## made the wire types worth a shared leaf, though this module shares no
## other kinship with that split: it is one algorithm both sides must
## compute byte-for-byte identically, not a wire-format/hygiene concern.

import nimcrypto/sha2
import sello/scalar

func challenge*(R, A: array[32, byte]; msg: openArray[byte]): array[32, byte] =
  ## k = SHA-512(R || A || msg) mod L (RFC 8032 §5.1.6 step 4 / §5.1.7 step
  ## 2) -- the challenge hash shared by verify and signDetached. One
  ## audited copy of the formula: two hand-maintained copies would be a
  ## latent sign/verify self-consistency break with no compiler signal.
  ## R, A, msg, and k are all public in both protocols, so this carries no
  ## CT requirement of its own.
  var sha: sha512
  sha.init()
  sha.update(R)
  sha.update(A)
  sha.update(msg)
  var k64: array[64, byte]
  sha.finish(k64)
  scReduce(result, k64)
