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
      ## branch the `if acc == 0` in both the `X25519StaticSecret` and
      ## `X25519EphemeralSecret` overloads reads. This slice wires the
      ## `X25519StaticSecret` overload's site only; the ephemeral
      ## overload's identical disclosure class shares this id and is
      ## wired when that role joins the taint target list.

  DeclassWidth* = enum
    ## Disclosed WIDTH, typed rather than left as a raw byte count — the
    ## audit value A1's own text calls out is "how much, not just where."
    dwVerdictByte   ## a single accept/reject verdict byte.
    dwPublicKey32   ## a derived/imported 32-byte public key.
    dwSignature64   ## a 64-byte ed25519 signature (`R || S`).
    dwDigest64      ## a 64-byte hash digest (sha512) — schema proof-spike
                     ## register only as of this slice, see below.

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

## ## Schema proof-spike (Stage 3, DoD)
##
## Written on paper, against the FROZEN `DeclassEntry` schema above,
## before this slice closes — deliberately NOT added to the live
## `DeclassId` enum / `declassRegister` array (that would need real
## `declassify` call sites in `private/sha512.nim`/`ristretto.nim`, which
## this slice does not touch; both join the taint target list in a later
## slice, at which point these two drafts graduate into real entries).
## Both instantiate `DeclassEntry` without any field/type change, which is
## the proof-spike's actual verdict: the schema fits both the inverted
## disclosure class (message tainted, DIGEST declassified — every other
## register entry so far taints an input and declassifies a DIFFERENT,
## smaller verdict/derived value) and an import-path REJECT arm (a
## `false` accept/reject verdict over caller-supplied, not
## library-derived, bytes).
##
##   diSha512DigestKat: DeclassEntry(
##     id: diSha512DigestKat,
##     width: dwDigest64,
##     anchor: "sha512.sha512",
##     rationale: "The harness's own KAT comparison needs the digest " &
##       "bytes defined to compare against a known-answer vector. This " &
##       "is the INVERTED class every other entry in this register is " &
##       "not: sha512's MESSAGE is what a caller taints (matching " &
##       "dudect's own sha512 target, which varies message content, not " &
##       "a secret scalar), and the DIGEST -- not a verdict derived from " &
##       "it -- is what gets declassified. A hash digest carries no " &
##       "secrecy obligation of its own once its (possibly secret) " &
##       "input has been fully absorbed; declassifying it here matches " &
##       "the same assign-result/declassify/return idiom the signature " &
##       "and public-key entries above use.",
##     buildCondition: "",
##   )
##
##   diRistrettoStaticSecretImportReject: DeclassEntry(
##     id: diRistrettoStaticSecretImportReject,
##     width: dwVerdictByte,
##     anchor: "ristretto.toRistrettoStaticSecret",
##     rationale: "toRistrettoStaticSecret's scIsCanonicalCT verdict " &
##       "over CALLER-SUPPLIED import bytes (not a library-derived " &
##       "value) decides accept (Some) vs. reject (None). The verdict " &
##       "is a fact about the caller's OWN bytes, already fully in the " &
##       "caller's possession before the call -- branching on whether " &
##       "they were canonical discloses nothing the caller did not " &
##       "already have. Distinct from diX25519ZeroVerdict's class " &
##       "(a verdict derived FROM a secret computation) precisely " &
##       "because this verdict is over an IMPORT boundary, not a " &
##       "derived DH/scalar result -- both are sanctioned, for " &
##       "different reasons, which is why each gets its own rationale " &
##       "text rather than sharing one.",
##     buildCondition: "",
##   )
##
## Both compile as `DeclassEntry` literals under the schema exactly as
## written above (verified by pasting each into a scratch `const` during
## this spike) — no field needed adding, no type needed widening. The
## schema is FROZEN as of this slice.
