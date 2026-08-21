## sello/private/backend.nim — pure-Nim secret-math backend (RFC-001).
##
## DANGER: every export here operates on unwrapped seed bytes and bypasses
## every `Keypair` guarantee — no derive-once invariant, no auto-wipe on
## scope exit. Application code should never import this module; use
## `sello.keypair` / `sello.sign` (via `sello/signing`) instead. It lives
## under `private/` for exactly that reason, the same social-contract
## treatment `ct.nim` gets.
##
## Seed-level primitives only, no `Keypair` knowledge. Builds strictly on
## `sello/field` + `sello/scalar` + `sello/challenge` (the shared
## `challenge` hash, RFC-002 slice 2) + `sello/private/sha512` (the
## in-house SHA-512, RFC-006 slice 3 -- nimcrypto's `sha2` is gone from
## this file and from the dependency tree entirely) — deliberately
## never `sello/ed25519`, which stays a verify-only module that never
## touches a secret. `derivePublic`/`signDetached` below return raw
## `array[32/64, byte]`, not `PublicKey`/`Signature` (RFC-001 finding 9):
## even though those nominal types are one leaf import away
## (`sello/wire`), the public wrapping is deliberately NOT applied here. This module is `private/`
## precisely because its seed-level contract bypasses every `Keypair`
## guarantee; adding the public nominal types here would blur that
## boundary rather than sharpen it. `signing.nim` is where seed bytes
## cross into the public API, so that is where `toPublicKey`/`toSignature`
## get called (one call site each, not sprinkled through this file).
##
## The libsodium adapter is the sibling `private/backend_sodium.nim`
## (RFC-001 slice 10); `signing.nim` dispatches between the two.
##
## ## `derivePublic`/`signDetached` contract (RFC-001 ledger finding 13)
##
## `derivePublic(seed)` is the one place a public key gets derived from
## scratch (`keypair(seed)`'s constructor call). `signDetached(seed,
## publicBytes, msg)` takes the already-derived public key as a parameter
## instead of re-deriving it internally -- `signing.sign` always has one on
## hand (`kp.public`, guaranteed by the `Keypair` invariant to already
## equal `derivePublic(kp.seed.bytes)`), so recomputing it inside
## `signDetached` on every call would be a second secret-scalar fixed-base
## scalarmult purely to reconstruct a value the caller already has. Both
## backends (this module and `private/backend_sodium.nim`) share the exact
## same two-secret/one-public three-argument `signDetached` signature so
## `signing.nim`'s dispatch stays a one-line import swap.

import sello/field
import sello/scalar
import sello/challenge
import sello/private/ct
import sello/private/sha512

## Compiler-enforced effect contract (janus consumer finding 3) -- see
## `signing.nim`'s module doc for the surface-wide policy. The pure-Nim
## secret-math backend never raises: `signing.sign`/`keypair(seed)`'s
## totality claim rests on these two functions being total too.
{.push raises: [], gcsafe.}
{.push checks: off.}

proc derivePublic*(seed: array[32, byte]): array[32, byte] =
  ## RFC 8032 §5.1.5 public-key derivation: A = clamp(SHA-512(seed)[0..31])
  ## * B, canonically encoded. `seed` and the intermediate hash/scalar are
  ## secret; both live in fixed-size stack arrays with zero heap
  ## allocation and are wiped via `ct.wipe` (volatile stores + compiler
  ## barrier — RFC-001 slice 8) once no longer needed. The one-shot
  ## `sha512(seed)` call (RFC-006 slice 3) wipes its own internal context
  ## before returning -- no context is caller-visible here at all, so
  ## there is no separate context to wipe on this side.
  ##
  ## `proc`, not `func` (round-3 finding A4): this and `signDetached` below
  ## were already effect-free in practice and compiled fine as `func`, but
  ## `signing.nim`'s callers must be able to call either this pure backend
  ## OR `private/backend_sodium.nim`'s FFI-backed adapter through the same
  ## one-line-import-swap dispatch (see `signing.nim`'s module doc) -- and
  ## the sodium adapter's equivalents have real, un-hideable side effects
  ## (global `sodium_init` state, FFI calls) once A4 removes the false
  ## `{.cast(noSideEffect).}` that used to paper over that. Both backends'
  ## contract must match exactly, so both are `proc`.
  ##
  ## `a`, the clamped secret key scalar, is `SecretScalar`-typed (round-3
  ## finding A3) from the point it is fully assembled -- built up in the
  ## explicitly-named `aBytes` scratch array first (clamping mutates bytes
  ## in place, which `SecretScalar` does not expose), then wrapped via
  ## `toSecretScalar` for its one consuming call into `geScalarmultBase`.
  ## Both `aBytes` and `a` are secret and both get wiped below.
  ##
  ## The whole body runs under one `try`/`finally` (RFC-001 ledger finding
  ## 18, defensive, currently unreachable): every secret declared below is
  ## re-wiped in `finally` regardless of how the function exits, so an
  ## unwind between a secret's creation and its explicit wipe call below
  ## cannot leave it live in this stack frame. The explicit wipes on the
  ## happy path are not redundant with this net -- they still fire as soon
  ## as each secret is no longer needed rather than waiting for function
  ## exit; `finally`'s re-wipe of already-zeroed memory is a harmless
  ## no-op there.
  var h: array[64, byte]
  var aBytes: array[32, byte]
  var a: SecretScalar
  try:
    h = sha512(seed)

    for i in 0 ..< 32: aBytes[i] = h[i]
    clampScalar(aBytes)
    a = toSecretScalar(aBytes)

    result = pointEncode(geScalarmultBase(a))

    ct.wipe(h)
    ct.wipe(aBytes)
    ct.wipe(a)
  finally:
    ct.wipe(h)
    ct.wipe(aBytes)
    ct.wipe(a)

proc signDetached*(seed: array[32, byte]; publicBytes: array[32, byte];
                    msg: openArray[byte]): array[64, byte] =
  ## RFC 8032 §5.1.6 detached signature (Ed25519: no context, no prehash):
  ##   h = SHA-512(seed); a = clamp(h[0..31]); prefix = h[32..63]
  ##   A = publicBytes                      -- see below, not re-derived
  ##   r = scReduce(SHA-512(prefix || msg))
  ##   R = [r]B
  ##   k = challenge(R, A, msg)     -- the same audited formula verify() uses
  ##   S = scMulAdd(k, a, r)
  ##   signature = R || S
  ## `seed`, `a`, `prefix`, `r`, and `h` are all secret; every one lives in a
  ## fixed-size stack array with zero heap allocation. `a` and `r` are
  ## `SecretScalar`-typed once fully assembled (round-3 finding A3, same
  ## `<x>Bytes` scratch-then-wrap register as `derivePublic` above) --
  ## `scMulAdd`'s and `geScalarmultBase`'s secret-scalar parameters accept
  ## only `SecretScalar`, not a bare `array[32, byte]`, so this function
  ## and `scalarmultVartime` (the verify-only vartime path, never called
  ## from here) cannot be confused for each other at a type-checker level,
  ## not merely by naming convention.
  ##
  ## `publicBytes` (RFC-001 ledger finding 13): the caller-supplied public
  ## key, used as `A` directly instead of re-deriving
  ## `pointEncode(geScalarmultBase(a))` here. `signing.nim`'s `Keypair`
  ## invariant (`kp.public == derive(kp.seed)`, enforced by `keypair(seed)`
  ## being the only constructor) exists precisely so `sign` can pass the
  ## already-cached public key instead of paying a second secret-scalar
  ## fixed-base scalarmult per signature -- this function does not
  ## re-verify that `publicBytes` actually matches `a`'s derived public
  ## key, the same way it does not re-verify that `seed` is the caller's
  ## real secret; both trust the seed-level caller (`signing.sign`, which
  ## reaches into `Keypair`'s own already-validated fields). `A` is public
  ## data either way, so accepting it as a parameter changes no secrecy
  ## boundary. Every secret intermediate below is wiped via `ct.wipe`
  ## (volatile stores + compiler barrier — RFC-001 slice 8) once no longer
  ## needed. The two one-shot calls (RFC-006 slice 3), `sha512(seed)` and
  ## `sha512(prefix, msg)`, each wipe their own internal context before
  ## returning -- no context is caller-visible here at all, so there is no
  ## separate context to wipe on this side.
  ##
  ## The whole body runs under one `try`/`finally` (RFC-001 ledger finding
  ## 18, defensive, currently unreachable) covering every secret declared
  ## below -- see `derivePublic`'s doc comment for why this is not
  ## redundant with the explicit wipe-as-soon-as-unneeded calls on the
  ## happy path.
  var h: array[64, byte]
  var aBytes: array[32, byte]
  var a: SecretScalar
  var prefix: array[32, byte]
  var nonceHash: array[64, byte]
  var rBytes: array[32, byte]
  var r: SecretScalar
  try:
    h = sha512(seed)

    for i in 0 ..< 32: aBytes[i] = h[i]
    clampScalar(aBytes)
    a = toSecretScalar(aBytes)

    for i in 0 ..< 32: prefix[i] = h[32 + i]
    ct.wipe(h)

    let A = publicBytes

    # Debug-only consistency check (RFC-002 slice 2 item 3b): plain
    # `assert`, meant to be entirely absent from the dudect-measured
    # `-d:release` build (and every downstream consumer's release build).
    # Expensive ON PURPOSE -- a second secret-scalar fixed-base scalarmult
    # purely to confirm the caller's `publicBytes` really is
    # `derivePublic`'s output for this `seed` (the `Keypair` invariant
    # `signing.nim` relies on to skip re-deriving `A` on every call, see
    # this function's own doc comment) -- so it must only run where cost
    # doesn't matter: debug-build tests, never release, and NEVER inside
    # the timing-sensitive path dudect measures.
    #
    # `when not defined(release)`, not a bare `assert` (RFC-002 slice 2
    # deviation from the RFC's literal mechanism, forced by empirical Nim
    # 2.2.10 behavior -- see `scalar.geScalarmultBase`'s matching assert
    # for the full writeup): the RFC's stated rationale ("plain assert --
    # stripped by -d:release") does not hold in this toolchain, and this
    # function already sits under `checks: off`, whose `checks` umbrella
    # bundles `assertions` off unconditionally -- so a bare `assert` here
    # would neither fire in debug builds NOR reliably disappear from
    # release ones. The `when` guard removes this whole block, including
    # the extra `geScalarmultBase` call, from `-d:release` compilation
    # entirely; the inner `{.push assertions: on.}` locally overrides the
    # surrounding checks-off region so the assert can actually fire in a
    # plain debug build.
    when not defined(release):
      {.push assertions: on.}
      assert A == pointEncode(geScalarmultBase(a)),
        "signDetached: publicBytes does not match derivePublic(seed)"
      {.pop.}

    nonceHash = sha512(prefix, msg)
    ct.wipe(prefix)

    scReduce(rBytes, nonceHash)
    r = toSecretScalar(rBytes)
    ct.wipe(nonceHash)

    let R = pointEncode(geScalarmultBase(r))
    let k = challenge(R, A, msg)
    let S = scMulAdd(k, a, r)

    for i in 0 ..< 32: result[i] = R[i]
    for i in 0 ..< 32: result[32 + i] = S[i]

    ct.wipe(aBytes)
    ct.wipe(a)
    ct.wipe(rBytes)
    ct.wipe(r)
  finally:
    ct.wipe(h)
    ct.wipe(aBytes)
    ct.wipe(a)
    ct.wipe(prefix)
    ct.wipe(nonceHash)
    ct.wipe(rBytes)
    ct.wipe(r)

{.pop.}
{.pop.}
