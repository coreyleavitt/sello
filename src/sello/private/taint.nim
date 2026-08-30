## sello/private/taint.nim — the taint CT harness's declassification
## register (RFC-005 slice 19, A1). Mirrors `private/ct.nim`'s social
## contract: exists to be called FROM the secret-handling code
## (`private/backend.nim`, `x25519.nim`, and — future slices — the
## ristretto255/sha512 secret paths), never imported by application code.
## Under `private/` for the same reason every other file in this
## directory is: no facade export, no api-surface baseline entry, no
## `test_facade.nim` reachability obligation.
##
## ## The mechanism, precisely
##
## `declassify(id, buf)` (buffer overload) and `declassify(id, val)`
## (scalar overload — several registered disclosures are single verdict
## words, e.g. `x25519`'s OR-accumulated all-zero check, not buffers;
## without this overload call sites would have to contort a verdict byte
## into a one-element array just to call the buffer form) are TEMPLATES,
## not procs — in every NORMAL build (no `-d:selloTaint`) they expand to
## `discard`: no FFI, no call, zero cost, for every build a consumer ever
## makes. **Codegen-unchanged proof (required by this module's own DoD):**
## after `declassify` calls were wired into `private/backend.nim`
## (`derivePublic`/`signDetached`) and `x25519.nim` (the static-role
## `x25519`'s all-zero verdict) — see those modules' own doc comments —
## the generated C for both files (via `nim c -d:release --nimcache:<dir>
## -c tests/unit/test_signing.nim` / `test_x25519.nim`, comparing
## `nimcache/@psello@sprivate@sbackend.nim.c` /
## `@psello@sx25519.nim.c` between a tree built from the pre-declassify
## commit and one built from the post-declassify commit) was diffed with
## `diff -u`: every diff hunk is a Nim-internal symbol-suffix
## renumbering only (e.g. `wipe__...backend_u17` becomes
## `wipe__...backend_u26`) — Nim's global unique-id counter shifts because
## the new `taint.nim` module (and its `import` in both files) declares a
## few more symbols ahead of these in link order; the counter shift
## touches every call site to an already-existing proc, not just the ones
## this slice added. No new instruction, call, branch, or memory
## operation appears anywhere in either diff — the `declassify` call
## sites themselves contribute LITERALLY NOTHING to the generated C, as
## designed. See the handoff doc's slice 19 entry for the exact commands,
## trees, and full diff.
##
## Under `-d:selloTaint`, `declassify` expands to a call into the shim TU
## (`private/taint_shim.c`, `{.compile.}`d only under that flag — no
## linked library, a deliberate, confined FFI exception that exists only
## in the taint build) which issues `VALGRIND_MAKE_MEM_DEFINED` on the
## disclosed bytes and bumps a per-id exercise counter the harness asserts
## against (every register entry must be exercised at least once,
## union-across-the-battery, skip-with-notation for entries whose
## `buildCondition` excludes the current configuration).
##
## **Building the core with `-d:selloTaint` outside the harness is a link
## error by design** (decided and recorded here, per A1's own text): the
## shim TU's function BODIES are gated on a second, narrower macro,
## `SELLO_TAINT_HARNESS_ACTIVE`, which ONLY `scripts/ct-taint.sh` passes
## (`--passC:"-DSELLO_TAINT_HARNESS_ACTIVE"`). `-d:selloTaint` alone (a
## consumer accidentally setting it, or some other harness compiling this
## TU) compiles `taint_shim.c` fine — the declarations exist — but leaves
## both functions bodyless, so a real call site fails at the final LINK
## step ("undefined reference to sello_taint_declassify") rather than a
## silent no-op or a missing-header compile error two layers removed from
## the actual cause. See `taint_shim.c`'s own header comment.
##
## ## The register
##
## `DeclassId` is the compile-time gate: the raw shim binding
## (`rawDeclassify` below) is UNEXPORTED and takes only a `DeclassId`, so
## every declassification in this codebase routes through a named,
## registered id — there is no way to reach the shim with an arbitrary
## int/string. Because `declassRegister` is typed
## `array[DeclassId, DeclassEntry]`, the register is complete BY
## CONSTRUCTION: every enum member must have an entry or the module fails
## to compile — "an unregistered declassification is a compile error" is
## therefore not a runtime check at all, it is Nim's own array-literal
## completeness rule. Pinned by a negative fixture
## (`tests/unit/fixtures/reject_taint_raw_shim_call.nim`): calling
## `rawDeclassify` directly from outside this module (bypassing the named,
## registered-by-construction `declassify` entry point) is a compile
## error because the symbol is not exported — proving the ONLY door in is
## the one that forces a registered id.
##
## `DeclassId` members follow a fixed `di`-prefix convention (settled here,
## before the first entry lands, since these ids are the citation currency
## module docs cite by — e.g. `Cites: diDerivePublicKey`).
##
## **Boundary rule (restated from A1's own text, load-bearing for what
## does NOT appear in this register):** a register entry records a
## *sanctioned publication* — public keys, signatures, and interior
## accept/reject verdicts over public data. Secret *outputs*
## (`X25519Shared`/`RistrettoShared` DH results) are never register
## entries: disclosing them is not sanctioned, and the harness's own KAT
## comparison of a secret output uses a HARNESS-SIDE
## `MAKE_MEM_DEFINED` on the harness's own copy, after the call returns —
## outside the library, and outside this register's scope entirely.

{.push raises: [], gcsafe.}

type
  DeclassId* = enum
    ## One member per sanctioned interior disclosure point. Each MUST
    ## have a `declassRegister` entry (enforced by the array's own type)
    ## and each real call site MUST cite its id in the citing module's own
    ## doc comment (`Cites: <id>`) — the register→docs half of A1's own
    ## anchor-drift check.
    diDerivePublicKey
      ## `private/backend.derivePublic`'s returned public key (32 bytes),
      ## declassified at the assign-result/declassify/return idiom this
      ## module's own doc specifies.
    diSignDetachedSignature
      ## `private/backend.signDetached`'s returned signature, `R || S`
      ## (64 bytes), same assign-result/declassify/return idiom.
    diX25519ZeroVerdict
      ## `x25519.x25519`'s OR-accumulated all-zero small-order-peer
      ## verdict byte (RFC 7748 §6.1's zero-output check) — the interior
      ## branch the `if acc == 0` reads, in BOTH the `X25519StaticSecret`
      ## overload (wired since slice 19) and the `X25519EphemeralSecret`
      ## overload (wired RFC-005 slice 21) — the identical disclosure
      ## class over two overloads sharing one id, per this member's
      ## original doc comment.
    diX25519BasePublicKey
      ## `x25519.x25519Base`'s returned public u-coordinate (32 bytes),
      ## declassified at the assign-result/declassify/return idiom —
      ## RFC-005 slice 21. Shared by BOTH overloads (`X25519StaticSecret`
      ## and `X25519EphemeralSecret`): neither has a branch of its own,
      ## each is a direct `ladder` call, so one id covers both call sites
      ## exactly as `diX25519ZeroVerdict` covers both `x25519` overloads.
    diRistrettoEncodeOutput
      ## The canonical 32-byte encoding of a `RistrettoPoint` a caller
      ## intends to publish — RFC-005 slice 21. **NO interior call site
      ## inside `ristretto.ristrettoEncode` itself** (see that function's
      ## own doc comment for why: it is reused on the genuine secret DH
      ## product inside `ristrettoScalarmult(sink RistrettoEphemeralSecret,
      ## ...)`, so an unconditional interior declassify there would
      ## violate this register's own boundary rule). Declassified instead
      ## at each genuinely-public CALL SITE of `ristrettoEncode` — this
      ## slice's own `tests/ct_taint/target_ristretto_scalarmult.nim`
      ## target — legitimate because `ristrettoEncode` has no interior
      ## branch of its own (straight-line CT plus `feCMove` selects), so
      ## a declassify by the caller, after the call returns, loses no
      ## coverage the way an interior-branch case would (contrast
      ## `diX25519ZeroVerdict`'s "too late" argument against exactly that
      ## pattern for a function WITH an interior branch).
    diRistrettoEqualVerdict
      ## `ristretto.\`==\``'s CT verdict byte (`uint8(eq1) or uint8(eq2)`),
      ## declassified immediately before return — RFC-005 slice 21. Same
      ## sanctioning argument as `diX25519ZeroVerdict`: the boolean this
      ## function hands back IS the disclosure the caller asked for by
      ## calling it.
    diRistrettoStaticSecretImportReject
      ## `ristretto.toRistrettoStaticSecret`'s `scIsCanonicalCT` accept/
      ## reject verdict over CALLER-SUPPLIED import bytes — promoted from
      ## the Stage-3 schema proof-spike (slice 19) to a live id, RFC-005
      ## slice 21. The verdict is a fact about the caller's own
      ## already-possessed bytes (an IMPORT boundary, not a derived-
      ## computation verdict), the class `diX25519ZeroVerdict` is not.
    diRistrettoEphemeralZeroVerdict
      ## `ristretto.ristrettoScalarmult(sink RistrettoEphemeralSecret,
      ## ...)`'s OR-accumulated all-zero identity-encoding verdict byte
      ## (RFC 9496 §4.3.2's canonical-encoding-of-identity-is-all-zero
      ## fact) — the interior branch the `if acc == 0` reads. RFC-005
      ## slice 21. A distinct id from `diX25519ZeroVerdict` (different
      ## anchor, different module, this register's one-anchor-per-id
      ## convention) even though the shape (OR-accumulate, zero-verdict)
      ## is the same construction.
    diSha512DigestKat
      ## `private/sha512.sha512`'s returned digest, for a caller's own
      ## KAT-style inspection — promoted from the Stage-3 schema
      ## proof-spike (slice 19) to a live id, RFC-005 slice 21. The
      ## INVERTED class: the MESSAGE is what gets tainted, the DIGEST is
      ## what gets declassified. **NO interior call site inside
      ## `sha512.sha512` itself** (see that function's own doc comment
      ## for why: it is reused for genuinely secret-derivation hashing
      ## internal to `private/backend.derivePublic`/`signDetached`, so an
      ## unconditional interior declassify there would silently un-taint
      ## those secret intermediates). Declassified instead at the CALL
      ## SITE that treats the digest as intentionally inspectable test
      ## data — this slice's own `tests/ct_taint/target_sha512.nim`
      ## target — legitimate for the same "no interior branch, so no
      ## coverage lost by declassifying after return" reason
      ## `diRistrettoEncodeOutput`'s own doc comment states.

  DeclassWidth* = enum
    ## Disclosed WIDTH, typed rather than left as a raw byte count — the
    ## audit value A1's own text calls out is "how much, not just where."
    dwVerdictByte   ## a single accept/reject verdict byte.
    dwPublicKey32   ## a derived/imported 32-byte public key.
    dwSignature64   ## a 64-byte ed25519 signature (`R || S`).
    dwDigest64      ## a 64-byte hash digest (sha512).

  DeclassEntry* = object
    id*: DeclassId
    width*: DeclassWidth
    anchor*: string
      ## The citing module-doc anchor, `"<module>.<proc>"` form — the
      ## string every citing doc comment's own `Cites: <id>` line is
      ## cross-checked against by the (future) anchor-drift emitter A1's
      ## text describes.
    rationale*: string
      ## Why this disclosure is sanctioned (public data, or a public
      ## verdict over public/already-committed data).
    buildCondition*: string
      ## "" if this id's call site exists in every taint-harness build;
      ## otherwise a short human-readable condition (e.g.
      ## `"-d:selloLibsodium"`) the harness's exercise check treats as a
      ## skip-with-notation exemption for configurations where the site
      ## does not compile in at all.

const declassRegister*: array[DeclassId, DeclassEntry] = [
  diDerivePublicKey: DeclassEntry(
    id: diDerivePublicKey,
    width: dwPublicKey32,
    anchor: "backend.derivePublic",
    rationale: "A derived ed25519 public key is public data the moment " &
      "derivePublic returns it to its caller (signing.keypair's own " &
      "invariant construction) -- withholding definedness from the " &
      "return value would only hide the disclosure from this harness, " &
      "not from any real consumer.",
    buildCondition: "",
  ),
  diSignDetachedSignature: DeclassEntry(
    id: diSignDetachedSignature,
    width: dwSignature64,
    anchor: "backend.signDetached",
    rationale: "An ed25519 signature is published data by definition -- " &
      "it exists to be sent to a verifier. Declassified once fully " &
      "assembled (R || S), immediately before return, matching the " &
      "assign-result/declassify/return idiom every derived-public-" &
      "material entry in this register follows.",
    buildCondition: "",
  ),
  diX25519ZeroVerdict: DeclassEntry(
    id: diX25519ZeroVerdict,
    width: dwVerdictByte,
    anchor: "x25519.x25519",
    rationale: "RFC 7748 section 6.1's zero-output check is a public " &
      "verdict over this caller's own DH computation (all-zero output " &
      "means the peer supplied a small-order point, itself public " &
      "data) -- the small-order-or-not fact is exactly what the " &
      "returned Option's some/none discriminant hands the caller " &
      "regardless, so branching on it openly costs no additional " &
      "secrecy.",
    buildCondition: "",
  ),
  diX25519BasePublicKey: DeclassEntry(
    id: diX25519BasePublicKey,
    width: dwPublicKey32,
    anchor: "x25519.x25519Base",
    rationale: "A derived X25519 public u-coordinate is public data the " &
      "moment x25519Base returns it -- the same rationale as " &
      "diDerivePublicKey, restated for X25519's own key-derivation " &
      "boundary. Shared by both the X25519StaticSecret and " &
      "X25519EphemeralSecret overloads: neither branches on its own " &
      "input, so one id covers both call sites.",
    buildCondition: "",
  ),
  diRistrettoEncodeOutput: DeclassEntry(
    id: diRistrettoEncodeOutput,
    width: dwPublicKey32,
    anchor: "ct_taint.target_ristretto_scalarmult",
    rationale: "ristrettoEncode's canonical wire encoding is the " &
      "actual disclosure boundary for a RistrettoPoint a caller " &
      "intends to publish (a Pedersen commitment, an OPRF blinded " &
      "element) -- the same role diDerivePublicKey/" &
      "diX25519BasePublicKey play for their own key types. NO interior " &
      "call site inside ristretto.ristrettoEncode itself: that " &
      "function is reused on the genuine secret DH product inside " &
      "ristrettoScalarmult(sink RistrettoEphemeralSecret, ...), so an " &
      "unconditional interior declassify there would violate this " &
      "register's own boundary rule (see ristrettoEncode's own doc " &
      "comment). Declassified instead at each genuinely-public call " &
      "site of ristrettoEncode -- this anchor names the taint TARGET " &
      "that does so, not a src/sello/ site, since ristrettoEncode has " &
      "no interior branch of its own (straight-line CT plus feCMove " &
      "selects) and therefore loses no coverage by being declassified " &
      "after it returns.",
    buildCondition: "",
  ),
  diRistrettoEqualVerdict: DeclassEntry(
    id: diRistrettoEqualVerdict,
    width: dwVerdictByte,
    anchor: "ristretto.`==`",
    rationale: "The equality verdict IS the return value a caller asked " &
      "for by calling `==` -- withholding definedness from it would " &
      "only hide the disclosure from this harness, not from any real " &
      "consumer (the same argument diDerivePublicKey's own rationale " &
      "makes for a returned public key). Declassified immediately " &
      "before return, matching every other verdict-byte entry's " &
      "assign-result/declassify/return idiom.",
    buildCondition: "",
  ),
  diRistrettoStaticSecretImportReject: DeclassEntry(
    id: diRistrettoStaticSecretImportReject,
    width: dwVerdictByte,
    anchor: "ristretto.toRistrettoStaticSecret",
    rationale: "toRistrettoStaticSecret's scIsCanonicalCT verdict over " &
      "CALLER-SUPPLIED import bytes (not a library-derived value) " &
      "decides accept (Some) vs. reject (None). The verdict is a fact " &
      "about the caller's OWN bytes, already fully in the caller's " &
      "possession before the call -- branching on whether they were " &
      "canonical discloses nothing the caller did not already have. " &
      "Distinct from diX25519ZeroVerdict's class (a verdict derived " &
      "FROM a secret computation) precisely because this verdict is " &
      "over an IMPORT boundary, not a derived DH/scalar result.",
    buildCondition: "",
  ),
  diRistrettoEphemeralZeroVerdict: DeclassEntry(
    id: diRistrettoEphemeralZeroVerdict,
    width: dwVerdictByte,
    anchor: "ristretto.ristrettoScalarmult",
    rationale: "RFC 9496 section 4.3.2's canonical-identity-encoding-is-" &
      "all-zero check is a public verdict over this caller's own DH " &
      "computation (an all-zero encoding means the peer point was the " &
      "identity, or the ephemeral scalar was 0 mod L -- either way, " &
      "public information the returned Option's some/none discriminant " &
      "hands the caller regardless) -- the same argument " &
      "diX25519ZeroVerdict's rationale makes for x25519's own zero-" &
      "output check.",
    buildCondition: "",
  ),
  diSha512DigestKat: DeclassEntry(
    id: diSha512DigestKat,
    width: dwDigest64,
    anchor: "ct_taint.target_sha512",
    rationale: "The harness's own KAT comparison needs the digest " &
      "bytes defined to compare against a known-answer vector. This " &
      "is the INVERTED class every other entry in this register is " &
      "not: sha512's MESSAGE is what a caller taints (matching " &
      "dudect's own sha512 target, which varies message content, not " &
      "a secret scalar), and the DIGEST -- not a verdict derived from " &
      "it -- is what gets declassified. NO interior call site inside " &
      "sha512.sha512 itself: that function is reused for genuinely " &
      "secret-derivation hashing internal to backend.derivePublic/" &
      "signDetached (h = sha512(seed), the nonce hash), so an " &
      "unconditional interior declassify there would silently un-taint " &
      "those secret intermediates (see sha512.sha512's own doc " &
      "comment). Declassified instead at the taint TARGET that treats " &
      "the digest as intentionally inspectable test data -- this " &
      "anchor names that target, not a src/sello/ site -- legitimate " &
      "because sha512/compress has no interior branch of its own " &
      "(pure ARX) and therefore loses no coverage by being " &
      "declassified after it returns. A hash digest carries no " &
      "secrecy obligation of its own once its (possibly secret) " &
      "input has been fully absorbed; declassifying it here matches " &
      "the same assign-result/declassify/return idiom the signature " &
      "and public-key entries above use.",
    buildCondition: "",
  ),
]

when defined(selloTaint):
  const declassIdCount = ord(high(DeclassId)) + 1
  {.passC: "-DSELLO_TAINT_ID_COUNT=" & $declassIdCount.}
  {.passC: "-I/usr/include".}
  {.compile: "taint_shim.c".}

  proc selloTaintDeclassifyRaw(id: cint; p: pointer; len: csize_t) {.
    importc: "sello_taint_declassify", cdecl.}
  proc selloTaintExerciseCountRaw(id: cint): cint {.
    importc: "sello_taint_exercise_count", cdecl.}

  proc rawDeclassify(id: DeclassId; p: pointer; len: csize_t) =
    ## Unexported by design (see this module's own doc comment) — the
    ## ONLY way to reach the shim is through a `declassify` template
    ## call site, which forces a compile-time-known, therefore
    ## by-construction-registered, `DeclassId`.
    selloTaintDeclassifyRaw(cint(ord(id)), p, len)

  proc exerciseCount*(id: DeclassId): int =
    ## The harness's own per-id exercise query (RFC-005 slice 22 will be
    ## the first CI consumer; `scripts/ct-taint.sh`, Stage 2 of this
    ## slice, is the first real caller). Exported ONLY under
    ## `-d:selloTaint` — no normal build has any use for it, and no
    ## normal build links the shim TU this reads counters from.
    int(selloTaintExerciseCountRaw(cint(ord(id))))

  template declassify*(id: static DeclassId; buf: var openArray[byte]) =
    rawDeclassify(id, addr buf[0], csize_t(buf.len))

  template declassify*[N: static int](id: static DeclassId;
                                       buf: var array[N, byte]) =
    rawDeclassify(id, addr buf[0], csize_t(N))

  template declassify*[T: SomeInteger](id: static DeclassId; val: var T) =
    rawDeclassify(id, addr val, csize_t(sizeof(T)))

  # --- Harness-only primitives (tests/ct_taint/'s own use) ---------------
  #
  # UNCOUNTED, not id/register-gated -- see taint_shim.c's own doc comment
  # on the C side of this split. `markUndefined` taints a harness-owned
  # input buffer before it is handed to library code; `markDefined` is the
  # boundary-rule idiom for a secret OUTPUT (X25519Shared/RistrettoShared)
  # the harness needs defined for its own KAT comparison, deliberately
  # NOT routed through `declassify`/a `DeclassId` (disclosing a secret DH
  # result is never sanctioned -- see this module's own "Boundary rule"
  # paragraph); `checkDefined` directly asserts definedness (an immediate
  # memcheck error if not) rather than relying on incidental branch/format
  # usage to surface an error.
  proc selloTaintMarkUndefinedRaw(p: pointer; len: csize_t) {.
    importc: "sello_taint_mark_undefined", cdecl.}
  proc selloTaintMarkDefinedRaw(p: pointer; len: csize_t) {.
    importc: "sello_taint_mark_defined", cdecl.}
  proc selloTaintCheckDefinedRaw(p: pointer; len: csize_t) {.
    importc: "sello_taint_check_defined", cdecl.}

  proc markUndefined*(buf: var openArray[byte]) =
    selloTaintMarkUndefinedRaw(addr buf[0], csize_t(buf.len))
  proc markUndefined*[N: static int](buf: var array[N, byte]) =
    selloTaintMarkUndefinedRaw(addr buf[0], csize_t(N))

  proc markDefined*(buf: var openArray[byte]) =
    selloTaintMarkDefinedRaw(addr buf[0], csize_t(buf.len))
  proc markDefined*[N: static int](buf: var array[N, byte]) =
    selloTaintMarkDefinedRaw(addr buf[0], csize_t(N))

  proc checkDefined*(buf: openArray[byte]) =
    selloTaintCheckDefinedRaw(unsafeAddr buf[0], csize_t(buf.len))
  proc checkDefined*[N: static int](buf: array[N, byte]) =
    selloTaintCheckDefinedRaw(unsafeAddr buf[0], csize_t(N))
else:
  template declassify*(id: static DeclassId; buf: var openArray[byte]) =
    discard

  template declassify*[N: static int](id: static DeclassId;
                                       buf: var array[N, byte]) =
    discard

  template declassify*[T: SomeInteger](id: static DeclassId; val: var T) =
    discard

{.pop.}

## ## Schema proof-spike (Stage 3, slice 19) — resolved, RFC-005 slice 21
##
## Slice 19's Stage 3 wrote `diSha512DigestKat` and
## `diRistrettoStaticSecretImportReject` on paper against this module's
## frozen `DeclassEntry` schema, before any real call site existed for
## either, to prove the schema would not need to change when they landed
## for real. Both compiled as `DeclassEntry` literals exactly as drafted
## then (no field or type change needed) — the proof-spike's actual
## verdict, recorded in the handoff doc's slice 19 entry. RFC-005 slice
## 21 is where both graduated: they are now live members of `DeclassId`
## and `declassRegister` above, with real `declassify` call sites in
## `private/sha512.sha512` and `ristretto.toRistrettoStaticSecret`
## respectively — see those modules' own `Cites:` doc comments. The
## schema itself needed no further change to accommodate either landing,
## confirming the spike's own prediction.
