## sello/private/backend_sodium.nim — libsodium FFI adapter (RFC-001 slice
## 10). Compiled in only under `-d:selloLibsodium`; `signing.nim` selects
## this module in place of `sello/private/backend` (the pure-Nim
## backend), unchanged `Keypair` on both sides.
##
## DANGER: same social-contract treatment as `sello/private/backend.nim` —
## every export here operates on unwrapped seed bytes and bypasses every
## `Keypair` guarantee. It lives under `private/` for the same reason;
## application code should never import it directly, and it carries no
## `Keypair`/`Seed` knowledge of its own. `sello/ed25519.verify` is never
## affected by this module or the flag that selects it — it stays the one
## pure-Nim verifier, always.
##
## ## ABI surface
##
## Dynamically linked against distro `libsodium-devel` (tested against
## 1.0.22, openSUSE Tumbleweed's zypper package as of this slice; the four
## functions below are part of libsodium's original `crypto_sign` ed25519
## API and have been ABI-stable since 1.0.x, so any modern libsodium
## resolves):
##
## ```c
## int sodium_init(void);
## int crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
##                               const unsigned char *seed);
## int crypto_sign_detached(unsigned char *sig, unsigned long long *siglen_p,
##                           const unsigned char *m, unsigned long long mlen,
##                           const unsigned char *sk);
## int crypto_sign_verify_detached(const unsigned char *sig,
##                                  const unsigned char *m,
##                                  unsigned long long mlen,
##                                  const unsigned char *pk);
## ```
##
## `crypto_sign_seed_keypair` backs `derivePublic`; `signDetached` below
## does NOT call it (see the RFC-001 ledger finding 13 note on
## `signDetached` itself) -- both match `backend.nim`'s seed-level contract
## exactly (same argument/result shapes, plain `array[32/64, byte]`, no
## `PublicKey`/`Signature`/`Keypair` knowledge) so `signing.nim`'s dispatch
## is a one-line import swap. `crypto_sign_verify_detached` is exposed too,
## as `sodiumVerifyDetached` — beyond `backend.nim`'s two-function
## contract, and never used by `signing.nim`'s dispatch (verification is
## always `sello/ed25519.verify`) — because the bidirectional interop
## tests need libsodium's OWN verifier as the independent oracle for
## "does libsodium accept what our pure signer produced"; that is the
## actual point of having a swappable, audited backend.
##
## ## sodium_init and the atomic once-guard
##
## libsodium requires `sodium_init()` before any `crypto_sign_*` call. Its
## tri-state return is checked, never silently ignored: 0 (first caller to
## initialize), 1 (already initialized) both mean "safe to proceed"; < 0 is
## a hard error. The once-guard uses an atomic tri-state CAS
## (`std/atomics`), not a plain check-then-set boolean — a plain flag set
## to "done" strictly after the real init call would still let a second
## thread observe "not done yet" and race into its own concurrent
## `sodium_init()` call, and a flag set to "done" strictly before the call
## completes would let a second thread proceed while init is still
## in-flight; either is a data race under `--threads:on`. This guard is
## the feature's only shared mutable state. The three states:
## not-started -> in-progress (exactly one thread wins this CAS and runs
## the real `sodium_init()`) -> done. Losers of the CAS spin until the
## winner publishes `done` (or, on the winner's hard-error path, until it
## resets to not-started and a fresh caller may retry).

import std/atomics
import sello/private/ct

{.passL: "-lsodium".}

type
  SodiumInitError* = object of CatchableError
    ## Raised when `sodium_init()` itself returns < 0 -- a hard failure of
    ## the libsodium runtime (e.g. its internal self-tests), not something
    ## a retry at this layer can paper over.

const
  CryptoSignPublicKeyBytes = 32
  CryptoSignSecretKeyBytes = 64
  CryptoSignBytes = 64

  StateNotStarted = 0
  StateInProgress = 1
  StateDone = 2

proc c_sodium_init(): cint
  {.importc: "sodium_init", header: "<sodium.h>".}

proc c_crypto_sign_seed_keypair(pk, sk, seed: ptr UncheckedArray[byte]): cint
  {.importc: "crypto_sign_seed_keypair", header: "<sodium.h>".}

proc c_crypto_sign_detached(sig: ptr UncheckedArray[byte]; siglenP: ptr culonglong;
                             m: ptr UncheckedArray[byte]; mlen: culonglong;
                             sk: ptr UncheckedArray[byte]): cint
  {.importc: "crypto_sign_detached", header: "<sodium.h>".}

proc c_crypto_sign_verify_detached(sig: ptr UncheckedArray[byte];
                                    m: ptr UncheckedArray[byte]; mlen: culonglong;
                                    pk: ptr UncheckedArray[byte]): cint
  {.importc: "crypto_sign_verify_detached", header: "<sodium.h>".}

var sodiumInitState: Atomic[int]
  ## 0 = not started, 1 = in progress, 2 = done. See module doc comment.

proc ensureSodiumInit() =
  while true:
    var expected = StateNotStarted
    if sodiumInitState.compareExchange(expected, StateInProgress):
      # Won the race: we are the one thread that calls the real init.
      let rc = c_sodium_init()
      if rc < 0:
        sodiumInitState.store(StateNotStarted) # allow a later retry
        raise newException(SodiumInitError, "sodium_init() failed with rc=" & $rc)
      sodiumInitState.store(StateDone)
      return
    elif expected == StateDone:
      return
    else:
      # StateInProgress: another thread is initializing (or just failed
      # and is about to reset) -- spin until it publishes Done, then
      # re-check from the top (handles the reset-and-retry path too).
      while sodiumInitState.load() == StateInProgress:
        discard

func toPtr(a: openArray[byte]): ptr UncheckedArray[byte] =
  ## `nil` for an empty view (never take `unsafeAddr` of a zero-length
  ## array's element 0), a real pointer otherwise. Both `crypto_sign_*`
  ## functions treat `mlen == 0` with `m == NULL` as the empty message,
  ## matching RFC 8032's empty-message vector (TEST 1).
  if a.len > 0: cast[ptr UncheckedArray[byte]](unsafeAddr a[0]) else: nil

func derivePublic*(seed: array[32, byte]): array[32, byte] =
  ## Same contract as `backend.derivePublic`: RFC 8032 §5.1.5 public-key
  ## derivation, via `crypto_sign_seed_keypair`. The returned libsodium
  ## secret key (`seed ‖ pk`, 64 bytes) is a copy of the secret seed and is
  ## wiped via `ct.wipe` before returning.
  var pk: array[CryptoSignPublicKeyBytes, byte]
  var sk: array[CryptoSignSecretKeyBytes, byte]
  {.cast(noSideEffect).}:
    ensureSodiumInit()
    let rc = c_crypto_sign_seed_keypair(
      cast[ptr UncheckedArray[byte]](addr pk[0]),
      cast[ptr UncheckedArray[byte]](addr sk[0]),
      cast[ptr UncheckedArray[byte]](unsafeAddr seed[0]))
    doAssert rc == 0, "crypto_sign_seed_keypair failed with rc=" & $rc
  result = pk
  ct.wipe(sk)

func signDetached*(seed: array[32, byte]; publicBytes: array[32, byte];
                    msg: openArray[byte]): array[64, byte] =
  ## Same contract as `backend.signDetached` (RFC-001 ledger finding 13:
  ## both backends take the caller-supplied public key as a parameter
  ## instead of re-deriving it). RFC 8032 §5.1.6 detached signature, via
  ## `crypto_sign_detached` alone -- NOT `crypto_sign_seed_keypair` --
  ## because libsodium's 64-byte ed25519 secret key is documented to be
  ## exactly `seed(32) || publicKey(32)`: the public API's own
  ## `crypto_sign_ed25519_sk_to_seed`/`crypto_sign_ed25519_sk_to_pk`
  ## accessor functions extract the seed from `sk[0..31]` and the public
  ## key from `sk[32..63]` respectively, which only makes sense if that
  ## layout is a guaranteed contract, not an implementation detail this
  ## code would otherwise be relying on undocumented behavior for.
  ## Constructing `sk` by concatenating `seed` and `publicBytes` directly
  ## therefore reproduces exactly what `crypto_sign_seed_keypair` would
  ## have written into `sk`, without paying for the FFI round trip (or,
  ## before RFC-001's finding-13 fix, computing it twice per `Keypair`:
  ## once in `derivePublic` at construction, again here on every `sign`
  ## call). The rebuilt secret key is wiped via `ct.wipe` before returning.
  var sk: array[CryptoSignSecretKeyBytes, byte]
  for i in 0 ..< 32: sk[i] = seed[i]
  for i in 0 ..< 32: sk[32 + i] = publicBytes[i]
  var sig: array[CryptoSignBytes, byte]
  var siglen: culonglong
  {.cast(noSideEffect).}:
    ensureSodiumInit()
    let rcSign = c_crypto_sign_detached(
      cast[ptr UncheckedArray[byte]](addr sig[0]),
      addr siglen,
      toPtr(msg),
      culonglong(msg.len),
      cast[ptr UncheckedArray[byte]](addr sk[0]))
    doAssert rcSign == 0, "crypto_sign_detached failed with rc=" & $rcSign
  # RFC-001 ledger finding 20: self-checking FFI boundary -- confirm
  # libsodium actually wrote a full 64-byte signature rather than trusting
  # rcSign == 0 alone to mean "and siglen was what we expected."
  doAssert siglen == CryptoSignBytes.culonglong,
    "crypto_sign_detached returned unexpected siglen=" & $siglen
  result = sig
  ct.wipe(sk)

func sodiumVerifyDetached*(sig: array[64, byte]; msg: openArray[byte]; pk: array[32, byte]): bool =
  ## Exposed for the bidirectional interop tests only (RFC-001 slice 10):
  ## calls libsodium's OWN `crypto_sign_verify_detached`, independent of
  ## `sello/ed25519.verify`, so the interop suite can confirm libsodium
  ## itself accepts signatures produced by sello's pure-Nim signer. Not
  ## part of the `derivePublic`/`signDetached` dispatch contract
  ## `signing.nim` uses -- `signing.nim` never calls this; verification is
  ## always `sello/ed25519.verify`, on both backends.
  var rc: cint
  {.cast(noSideEffect).}:
    ensureSodiumInit()
    rc = c_crypto_sign_verify_detached(
      cast[ptr UncheckedArray[byte]](unsafeAddr sig[0]),
      toPtr(msg),
      culonglong(msg.len),
      cast[ptr UncheckedArray[byte]](unsafeAddr pk[0]))
  result = rc == 0
