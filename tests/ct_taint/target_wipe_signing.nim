## tests/ct_taint/target_wipe_signing.nim -- RFC-005 slice 21 (A1). The
## observable-wipe-path targets for `signing.wipe`'s two overloads (`sink
## Seed`, `var Keypair`) -- the re-specified wipe-paths scope (A1's own
## text): caller-owned in-place buffers, via a make-undefined-then-wipe-
## then-check-defined sequence. No `src/sello/` change needed: both
## overloads already call `ct.wipe` (real volatile stores); this file
## exercises that existing code with no new `declassify` call site (no
## accept/reject verdict or derived value here to register).
##
## **`Keypair` needs no harness-side cast at all**, unlike every other
## wipe target in this directory: `Seed`/`Keypair`'s fields are private
## with no exported raw-bytes accessor on `Seed` itself, but
## `signing.toSeedBytes(kp: Keypair)` -- a real, public, already-shipped
## API -- reads exactly the sub-field `wipe(var Keypair)` touches
## (`kp.seed.bytes`), so this target tests through the LEGITIMATE PUBLIC
## SURFACE rather than an offset-based cast: a fresh `Keypair`'s `seed`
## copy stays tainted from its own construction (only `kp.public` gets
## declassified, via the real `diDerivePublicKey` call site inside
## `keypair(seed)`'s own `backend.derivePublic` call -- `kp.seed` is a
## plain move of the caller's own still-tainted `Seed`, untouched by
## that declassify), so no extra `markUndefined` is needed before
## `wipe(kp)`.
##
## `Seed`'s own `wipe(sink Seed)` DOES need the harness-side cast (no
## public accessor exists at all for a standalone `Seed`), with the same
## sink-move confound `target_wipe_x25519.nim`'s own header comment
## discloses for `X25519EphemeralSecret`'s wipe -- see that file for the
## full writeup, not repeated here.
import sello/signing
import sello/private/taint

# --- Seed (sink overload) --------------------------------------------
block:
  var seedBytes: array[32, byte]
  for i in 0 ..< 32: seedBytes[i] = byte(i * 5 + 2)
  var s = toSeed(seedBytes)
  markUndefined(cast[ptr array[32, byte]](addr s)[])
  wipe(move(s))
  checkDefined(cast[ptr array[32, byte]](addr s)[])
  echo "target_wipe_signing: Seed wipe() path ran clean (caller-slot check confounded by wasMoved, see this file's own header comment)"

# --- Keypair (var overload) -- through the public toSeedBytes surface -
block:
  var seedBytes2: array[32, byte]
  for i in 0 ..< 32: seedBytes2[i] = byte(i * 7 + 3)
  markUndefined(seedBytes2)
  var kp = keypair(toSeed(seedBytes2))
    ## Calls the real, shipped `declassify(diDerivePublicKey, result)`
    ## call site (GREEN state only) for `kp.public`; `kp.seed` remains a
    ## tainted copy of `seedBytes2` at this point -- see this file's own
    ## header comment.
  wipe(kp)
  checkDefined(toSeedBytes(kp))
  echo "target_wipe_signing: Keypair wipe() cleared its seed observably (via toSeedBytes)"

  echo "target_wipe_signing: diDerivePublicKey exercises = ", exerciseCount(diDerivePublicKey)
