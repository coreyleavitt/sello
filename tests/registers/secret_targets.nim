## tests/registers/secret_targets.nim -- RFC-005 slice 20 (A7): the
## secret-target register. Validation metadata, not shippable library code
## (CLAUDE.md's own location rationale: `src/sello/` carries effect
## discipline and the api-surface baseline; a test-coverage ledger belongs
## with the tests, not the library).
##
## ## What this is, and is not
##
## "Which entry points hold secrets" is one fact three instruments
## currently enumerate independently: `tests/ct/ct_main.nim` (dudect
## timing targets), `tests/ct_taint/` (taint/memcheck targets), and the
## (future, slice 23) disasm gate's root list. A new secret-holding API
## could join one list and silently miss the others -- every list stays
## green, and the gap is invisible. This file is the checked fact-set the
## three instruments are asserted COMPLETE AGAINST (round-2's resolved
## "assert-against, not drive-from" design, `docs/rfc-005-validation-
## infra.md` lines 444-497): the instruments stay hand-built (each target
## is irreducibly bespoke -- four class designs, three input widths,
## deliberate non-entries with recorded rationale -- a register that could
## *generate* them would re-encode the harness as data, a worse
## programming language), and this table is what each instrument's own
## coverage assertion diffs itself against. The ONE legitimate drive-from
## is identity: `tests/ct/ct_main.nim` derives its printed dudect report
## names FROM this register's `Coverage.name` field (see that file's own
## `dudectTargetIds` + `static:` block), so a coverage assertion is a set
## comparison over real identifiers, never a hand-typed string that could
## silently drift from what the harness actually prints.
##
## ## Schema
##
## `array[SecretTargetId, SecretTargetEntry]` -- same shape family as
## `sello/private/taint.declassRegister` (deliberately: A7's own text
## calls the two "two columns of one audited fact-set") -- makes the
## register COMPLETE BY CONSTRUCTION: every enum member must have an
## entry or the module fails to compile, exactly like `declassRegister`'s
## own completeness guarantee.
##
## Each entry carries, per instrument (dudect / taint / disasm), a
## `Coverage` cell -- an object variant, frozen at three shapes:
##   - `ckDirect(name)`   -- this instrument has ITS OWN report/target
##     for this entry, identified by `name` (dudect: the exact string
##     `runDudect` prints; taint: the `ct-taint.sh` target-name column;
##     disasm: the bare `{.noinline.}` root's symbol name, A2's own unit
##     of analysis).
##   - `ckCoveredBy(id)`  -- this entry's own coverage is subsumed by
##     ANOTHER entry's `direct` cell for the SAME instrument (e.g. the
##     ephemeral ristretto scalarmult is dudect-`coveredBy` the static
##     scalarmult entry -- both run the identical `scalar.geScalarmultCT`
##     with full fixed-vs-random power, so a second target would add
##     runtime without adding information; the exact "ephemeral-covered-
##     by-static" rationale that used to live only as a code comment in
##     `tests/ct/ct_main.nim`'s module doc is now first-class data here).
##   - `ckExempt(rationale)` -- no target exists for this instrument, for
##     a stated reason. Two rationale registers share this ONE variant
##     rather than getting a fourth (`pending`/`notYetWired`) shape --
##     deliberately, per this slice's own task text ("decide the
##     vocabulary so slice 21 flips them to direct without schema
##     change"): a rationale beginning literally with the string
##     `"PENDING (slice 21)"` is a TEMPORARY exemption -- named in A1's
##     own target list (`docs/rfc-005-validation-infra.md` lines
##     115-290) but not yet wired into a live `tests/ct_taint/` target --
##     and every other rationale is a PERMANENT, stated design boundary
##     (e.g. "wipe timing is not a dudect concern", or the boundary rule
##     that a secret OUTPUT's disclosure is never sanctioned). Flipping a
##     `PENDING` cell to `ckDirect` when its target lands is a one-line
##     diff to THIS array; the `Coverage` variant itself never changes
##     shape. Every instrument's own coverage-check script greps for the
##     literal `"PENDING (slice 21)"` prefix to print an honest
##     skip-with-notation line rather than silently treating an exempt
##     cell as satisfied (this slice's own scope (c) instruction: "never
##     silently green").
##
## `declassIds`: the optional cross-link (A7's own text) -- the
## `sello/private/taint.DeclassId`s a taint run of this entry is expected
## to exercise, imported directly (not duplicated as strings) so the link
## is type-checked, not just textual. Empty for every entry whose taint
## cell is not `ckDirect` yet (there is nothing live to cross-link to).
##
## `qualifiedProc`/`facadeExported`/`ruleBasis`: the data the two-rule
## completeness check (`tests/registers/secret_target_check.py`) diffs
## against a live `nim jsondoc` scan of `src/sello.nim`'s facade surface.
## `qualifiedProc` is the EXACT `<resolved-module>.<symbol>` token
## `tests/api/api_surface_gen.py`'s own resolver would produce for a
## facade-exported entry (reusing that generator's corpus/resolution
## logic rather than a second signature scanner is this slice's own
## explicit instruction) -- for a curated, non-facade-exported entry
## (e.g. `private/backend.derivePublic`, which the dudect/taint harnesses
## call directly, bypassing `signing.keypair`/`sign`) it is instead the
## real module-qualified name for human/doc reference only, and
## `facadeExported` is `false` so the completeness check never expects a
## match for it.
##
## `ruleBasis`: `"rule1"` (exported proc accepting an enumerated
## secret-role type: `Seed`, `Keypair`, `X25519StaticSecret`,
## `X25519EphemeralSecret`, `X25519Shared`, `RistrettoStaticSecret`,
## `RistrettoEphemeralSecret`, `RistrettoShared` -- `Keypair` explicitly
## included per A7's own round-2 correction, closing the round-1 gap
## where `sign`'s own `Keypair` parameter was invisible to a check scoped
## to `distinct array` role types only), `"rule2"` (exported secret-
## IMPORT constructor -- a `to*Secret*`/`toSeed*`-pattern proc taking a
## bare array, the boundary where bytes *become* secrets, which no role
## type can type-match), or `"curated"` (present in this register because
## A1's own target list or an existing dudect/taint target names it, but
## outside the two mechanical rules' own scope -- stated as curated, per
## A7's own honesty requirement, not claimed mechanical). The RFC's own
## named curated-annex examples -- `ristrettoFromUniformBytes` (a raw
## 64-byte intake, not a `to*Secret*`-pattern name and not accepting a
## role type) and SHA-512's message input -- are exactly `"curated"`
## entries here, alongside `ristrettoEncode`/`` `==` ``, whose secret-
## DERIVED (not secret-role-TYPED) `RistrettoPoint` argument the same
## reasoning applies to (`RistrettoPoint` is a PUBLIC-register value by
## `ristretto.nim`'s own design -- see that module's doc comment -- so it
## is never itself a rule-1 role type, even though the protocols this
## register exists to serve routinely derive one from a live secret).
##
## `secretShape`: free-text description of which parameter/type actually
## carries the secret, since a role TYPE name alone does not always say
## which class of value it holds (e.g. `RistrettoShared`'s wrapped bytes
## ARE the shared secret itself, not a derived key).
##
## ## Two-rule completeness check, honestly scoped
##
## Rule 1 and rule 2 (both stated above) are checked mechanically by
## `tests/registers/secret_target_check.py` against a live `nim jsondoc`
## resolution of `src/sello.nim`'s facade (reusing
## `tests/api/api_surface_gen.py`'s own corpus/resolver -- a naive grep
## over signatures was tried and rejected by the RFC's own round-2 note;
## a jsondoc-resolved signature set is not naive). Raw-byte intakes
## OUTSIDE both patterns (`ristrettoFromUniformBytes`, SHA-512's message)
## are curated with review as the control, per A7's own text -- **stated
## as such, not claimed mechanical.**
##
## ## Disasm containment, prepared (A2, slice 23's own consumer)
##
## `disasmRoots()` returns the deduplicated union of every `ckDirect`
## disasm cell's root name -- the exact set A2's disasm gate will assert
## `⊆` the pinned baseline's root set against (containment, not equality:
## the baseline legitimately includes internal symbols -- `feCMove`,
## `feCSwap`, `cmovCached`, `feSqrtRatioM1` -- with no secret-role-typed
## export name of their own, per A2's own text, lines 290-352). No gate
## consumes this yet; this slice only exposes the contract.

import std/sets
import sello/private/taint

type
  SecretTargetId* = enum
    stDerivePublic
    stSignDetached
    stGeScalarmultBase
    stX25519Base
    stX25519EphemeralConsume
    stX25519StaticDH
    stX25519Ladder
    stX25519ToBytesStatic
    stX25519ToBytesShared
    stX25519WipeStatic
    stX25519WipeShared
    stX25519WipeEphemeral
    stToX25519StaticSecret
    stToSeed
    stKeypairSeed
    stKeypairExpectedPublic
    stSign
    stSigningWipeSeed
    stSigningWipeKeypair
    stPublic
    stToSeedBytes
    stRistrettoScalarmultStatic
    stRistrettoScalarmultEphemeral
    stRistrettoScalarmultBase
    stGeScalarmultCT
    stRistrettoEncode
    stRistrettoEqual
    stRistrettoFromUniformBytes
    stToRistrettoStaticSecret
    stToRistrettoStaticSecretWide
    stRistrettoWipeStatic
    stRistrettoWipeEphemeral
    stRistrettoWipeShared
    stRistrettoToBytesStatic
    stRistrettoToBytesShared
    stSha512Message
    stWipeGeneric

  CoverageKind* = enum
    ckDirect
    ckCoveredBy
    ckExempt

  Coverage* = object
    case kind*: CoverageKind
    of ckDirect:
      name*: string
    of ckCoveredBy:
      coveredBy*: SecretTargetId
    of ckExempt:
      rationale*: string

  SecretTargetEntry* = object
    id*: SecretTargetId
    qualifiedProc*: string
    facadeExported*: bool
    ruleBasis*: string        ## "rule1" | "rule2" | "curated"
    secretShape*: string
    dudect*: Coverage
    taint*: Coverage
    disasm*: Coverage
    declassIds*: seq[DeclassId]
    note*: string

const Pending = "PENDING (slice 21) -- named in A1's own target list " &
  "(docs/rfc-005-validation-infra.md lines 115-290), not yet wired into " &
  "a live tests/ct_taint/ target."

const secretTargetRegister*: array[SecretTargetId, SecretTargetEntry] = [
  stDerivePublic: SecretTargetEntry(
    id: stDerivePublic,
    qualifiedProc: "private/backend.derivePublic",
    facadeExported: false,
    ruleBasis: "curated",
    secretShape: "seed: array[32, byte] -- the raw ed25519 seed.",
    dudect: Coverage(kind: ckCoveredBy, coveredBy: stSignDetached),
    taint: Coverage(kind: ckDirect, name: "sign"),
    disasm: Coverage(kind: ckDirect, name: "derivePublic"),
    declassIds: @[diDerivePublicKey],
    note: "Not facade-exported directly -- signing.keypair(seed) wraps " &
      "it (see stKeypairSeed). dudect's own \"backend.signDetached\" " &
      "target calls derivePublic() then signDetached() in sequence " &
      "(tests/ct/ct_main.nim's opSignDetached), so this entry's own " &
      "timing is folded into that one report rather than isolated.",
  ),
  stSignDetached: SecretTargetEntry(
    id: stSignDetached,
    qualifiedProc: "private/backend.signDetached",
    facadeExported: false,
    ruleBasis: "curated",
    secretShape: "seed: array[32, byte] -- the raw ed25519 seed.",
    dudect: Coverage(kind: ckDirect, name: "backend.signDetached"),
    taint: Coverage(kind: ckDirect, name: "sign"),
    disasm: Coverage(kind: ckDirect, name: "signDetached"),
    declassIds: @[diSignDetachedSignature],
    note: "Not facade-exported directly -- signing.sign(kp, msg) wraps " &
      "it (see stSign).",
  ),
  stGeScalarmultBase: SecretTargetEntry(
    id: stGeScalarmultBase,
    qualifiedProc: "scalar.geScalarmultBase",
    facadeExported: false,
    ruleBasis: "curated",
    secretShape: "s: SecretScalar -- the signer's/keygen's secret scalar.",
    dudect: Coverage(kind: ckDirect, name: "scalar.geScalarmultBase"),
    taint: Coverage(kind: ckExempt, rationale: Pending),
    disasm: Coverage(kind: ckDirect, name: "geScalarmultBase"),
    declassIds: @[],
    note: "The fixed-base CT scalarmult underlying both signing/keygen " &
      "AND ristretto.ristrettoScalarmultBase's two overloads (see " &
      "stRistrettoScalarmultBase's coveredBy cell).",
  ),
  stX25519Base: SecretTargetEntry(
    id: stX25519Base,
    qualifiedProc: "x25519.x25519Base",
    facadeExported: true,
    ruleBasis: "rule1",
    secretShape: "secret: X25519StaticSecret | X25519EphemeralSecret " &
      "(two overloads) -- the caller's private X25519 scalar.",
    dudect: Coverage(kind: ckDirect, name: "x25519.x25519Base"),
    taint: Coverage(kind: ckExempt, rationale: Pending),
    disasm: Coverage(kind: ckCoveredBy, coveredBy: stX25519Ladder),
    declassIds: @[],
    note: "Bundles BOTH x25519Base overloads under one register row " &
      "(jsondoc/the facade-surface tooling treats them as one symbol). " &
      "Only the X25519StaticSecret arm (via toX25519StaticSecret) has " &
      "dedicated dudect coverage today -- the X25519EphemeralSecret " &
      "arm is not separately invoked by any dudect target, disclosed " &
      "here rather than silently implied by the shared entry.",
  ),
  stX25519EphemeralConsume: SecretTargetEntry(
    id: stX25519EphemeralConsume,
    qualifiedProc: "x25519.x25519",
    facadeExported: true,
    ruleBasis: "rule1",
    secretShape: "secret: sink X25519EphemeralSecret -- single-use " &
      "ephemeral scalar, consumed by this call.",
    dudect: Coverage(kind: ckDirect, name: "x25519(ephemeral) construct+consume"),
    taint: Coverage(kind: ckExempt, rationale: Pending),
    disasm: Coverage(kind: ckCoveredBy, coveredBy: stX25519Ladder),
    declassIds: @[],
    note: "dudect target is a construct+consume CALIBRATION check, not " &
      "a fixed-vs-random-secret leak test -- X25519EphemeralSecret has " &
      "no from-bytes constructor, so no fixed class can be built (see " &
      "ct_main.nim's own module doc). The genuine leak-value test for " &
      "this shared ladder() is stX25519StaticDH.",
  ),
  stX25519StaticDH: SecretTargetEntry(
    id: stX25519StaticDH,
    qualifiedProc: "x25519.x25519",
    facadeExported: true,
    ruleBasis: "rule1",
    secretShape: "secret: X25519StaticSecret -- reusable private scalar.",
    dudect: Coverage(kind: ckDirect, name: "x25519(static) vs peer"),
    taint: Coverage(kind: ckDirect, name: "x25519_static_normal"),
    disasm: Coverage(kind: ckCoveredBy, coveredBy: stX25519Ladder),
    declassIds: @[diX25519ZeroVerdict],
    note: "The genuine fixed-vs-random-SECRET leak test of the " &
      "arbitrary-peer DH path (RFC-003 slice 5). Taint drives BOTH " &
      "verdict arms (normal peer AND the RFC 7748 u=0 small-order " &
      "peer, tests/ct_taint/target_x25519_static.nim's " &
      "-d:x25519SmallOrderPeer build) -- this cell names the identity " &
      "anchor \"x25519_static_normal\" only; the smallorder run shares " &
      "the same DeclassId and register entry.",
  ),
  stX25519Ladder: SecretTargetEntry(
    id: stX25519Ladder,
    qualifiedProc: "x25519.ladder",
    facadeExported: false,
    ruleBasis: "curated",
    secretShape: "k: array[32, byte] -- the clamped secret scalar.",
    dudect: Coverage(kind: ckCoveredBy, coveredBy: stX25519Base),
    taint: Coverage(kind: ckExempt, rationale: Pending),
    disasm: Coverage(kind: ckDirect, name: "ladder"),
    declassIds: @[],
    note: "Module-private RFC 7748 Montgomery ladder, not facade- " &
      "exported -- curated because it is an A2 {.noinline.} disasm root " &
      "(docs/rfc-005-validation-infra.md lines 290-352) shared by every " &
      "X25519 secret-scalar entry above (stX25519Base, " &
      "stX25519EphemeralConsume, stX25519StaticDH all disasm-cover-by " &
      "this one root, since they all call the identical ladder()).",
  ),
  stX25519ToBytesStatic: SecretTargetEntry(
    id: stX25519ToBytesStatic,
    qualifiedProc: "x25519.toBytes",
    facadeExported: true,
    ruleBasis: "rule1",
    secretShape: "s: X25519StaticSecret -- exports the raw scalar bytes.",
    dudect: Coverage(kind: ckExempt, rationale:
      "Straight field copy, no secret-dependent branch or index -- CT " &
      "by construction, not a dedicated dudect target."),
    taint: Coverage(kind: ckExempt, rationale: Pending),
    disasm: Coverage(kind: ckExempt, rationale:
      "Plain field copy, not a {.noinline.} secret-path root."),
    declassIds: @[],
    note: "",
  ),
  stX25519ToBytesShared: SecretTargetEntry(
    id: stX25519ToBytesShared,
    qualifiedProc: "x25519.toBytes",
    facadeExported: true,
    ruleBasis: "rule1",
    secretShape: "sh: X25519Shared -- the completed DH shared secret.",
    dudect: Coverage(kind: ckExempt, rationale:
      "Straight field copy, no secret-dependent branch or index."),
    taint: Coverage(kind: ckExempt, rationale:
      "Boundary rule (private/taint.nim's own doc comment): a secret " &
      "OUTPUT's (X25519Shared) disclosure is never a sanctioned " &
      "DeclassId. The taint harness's own KAT comparison uses a " &
      "harness-side markDefined on ITS OWN copy after the call " &
      "returns, outside this register's scope entirely -- see " &
      "tests/ct_taint/target_x25519_static.nim's own header comment."),
    disasm: Coverage(kind: ckExempt, rationale:
      "Plain field copy, not a {.noinline.} secret-path root."),
    declassIds: @[],
    note: "PERMANENT exemption, not a slice-21 pending item -- see the " &
      "taint cell's own rationale.",
  ),
  stX25519WipeStatic: SecretTargetEntry(
    id: stX25519WipeStatic,
    qualifiedProc: "x25519.wipe",
    facadeExported: true,
    ruleBasis: "rule1",
    secretShape: "s: var X25519StaticSecret.",
    dudect: Coverage(kind: ckExempt, rationale:
      "A1's own wipe-paths note: wipe timing is not a dudect concern " &
      "(the volatile-store loop's length is PUBLIC, not secret-" &
      "dependent) -- observable-wipe correctness is a memcheck/" &
      "property concern instead."),
    taint: Coverage(kind: ckExempt, rationale: Pending & " A1's own " &
      "wipe-paths note: caller-owned buffer wipes ARE the observable " &
      "class taint can check (make-undefined-then-check-defined), but " &
      "no tests/ct_taint/ target exercises this wipe yet."),
    disasm: Coverage(kind: ckExempt, rationale:
      "private/ct.wipe is straight-line, no secret-dependent branch; " &
      "not in the A2 {.noinline.} root list."),
    declassIds: @[],
    note: "",
  ),
  stX25519WipeShared: SecretTargetEntry(
    id: stX25519WipeShared,
    qualifiedProc: "x25519.wipe",
    facadeExported: true,
    ruleBasis: "rule1",
    secretShape: "sh: var X25519Shared.",
    dudect: Coverage(kind: ckExempt, rationale:
      "Same wipe-timing-is-not-a-dudect-concern rationale as stX25519WipeStatic."),
    taint: Coverage(kind: ckExempt, rationale: Pending),
    disasm: Coverage(kind: ckExempt, rationale:
      "Not a {.noinline.} secret-path root."),
    declassIds: @[],
    note: "",
  ),
  stX25519WipeEphemeral: SecretTargetEntry(
    id: stX25519WipeEphemeral,
    qualifiedProc: "x25519.wipe",
    facadeExported: true,
    ruleBasis: "rule1",
    secretShape: "s: sink X25519EphemeralSecret.",
    dudect: Coverage(kind: ckExempt, rationale:
      "Same wipe-timing-is-not-a-dudect-concern rationale as stX25519WipeStatic."),
    taint: Coverage(kind: ckExempt, rationale: Pending),
    disasm: Coverage(kind: ckExempt, rationale:
      "Not a {.noinline.} secret-path root."),
    declassIds: @[],
    note: "",
  ),
  stToX25519StaticSecret: SecretTargetEntry(
    id: stToX25519StaticSecret,
    qualifiedProc: "x25519.toX25519StaticSecret",
    facadeExported: true,
    ruleBasis: "rule2",
    secretShape: "bytes: array[32, byte] -- the import boundary where " &
      "raw bytes become a secret.",
    dudect: Coverage(kind: ckCoveredBy, coveredBy: stX25519Base),
    taint: Coverage(kind: ckDirect, name: "x25519_static_normal"),
    disasm: Coverage(kind: ckExempt, rationale:
      "Plain object-literal construction, not a {.noinline.} secret-path root."),
    declassIds: @[],
    note: "dudect's opX25519Base/opX25519StaticDH both construct via " &
      "this proc INSIDE the measured region every sample -- its cost " &
      "is folded into those reports' own timing, not isolated.",
  ),
  stToSeed: SecretTargetEntry(
    id: stToSeed,
    qualifiedProc: "signing.toSeed",
    facadeExported: true,
    ruleBasis: "rule2",
    secretShape: "bytes: array[32, byte] -- the import boundary where " &
      "raw bytes become a Seed.",
    dudect: Coverage(kind: ckExempt, rationale:
      "Not exercised -- ct_main.nim's dudect target calls private/" &
      "backend.derivePublic/signDetached directly with a raw " &
      "array[32, byte] seed, bypassing signing.toSeed/Keypair " &
      "entirely (see opSignDetached). toSeed itself is a trivial " &
      "distinct-type wrap with no secret-dependent branch."),
    taint: Coverage(kind: ckDirect, name: "sign"),
    disasm: Coverage(kind: ckExempt, rationale:
      "Plain distinct-type wrap, not a {.noinline.} secret-path root."),
    declassIds: @[],
    note: "tests/ct_taint/target_sign.nim calls keypair(toSeed(seedBytes)) directly.",
  ),
  stKeypairSeed: SecretTargetEntry(
    id: stKeypairSeed,
    qualifiedProc: "signing.keypair",
    facadeExported: true,
    ruleBasis: "rule1",
    secretShape: "seed: sink Seed.",
    dudect: Coverage(kind: ckExempt, rationale:
      "Not exercised -- ct_main.nim calls private/backend.derivePublic " &
      "directly rather than through the Keypair wrapper; the " &
      "underlying secret-scalar arithmetic IS measured (stDerivePublic))."),
    taint: Coverage(kind: ckDirect, name: "sign"),
    disasm: Coverage(kind: ckCoveredBy, coveredBy: stDerivePublic),
    declassIds: @[diDerivePublicKey],
    note: "",
  ),
  stKeypairExpectedPublic: SecretTargetEntry(
    id: stKeypairExpectedPublic,
    qualifiedProc: "signing.keypair",
    facadeExported: true,
    ruleBasis: "rule1",
    secretShape: "seed: sink Seed (expectedPublic: PublicKey is public).",
    dudect: Coverage(kind: ckExempt, rationale:
      "Compares two PUBLIC values (a re-derived public key vs. the " &
      "caller-supplied expectedPublic) via wire.`==`'s ordinary " &
      "vartime compare -- no CT obligation, so not a dudect target by " &
      "design, not a coverage gap."),
    taint: Coverage(kind: ckExempt, rationale: Pending & " Named " &
      "explicitly in A1's own target list (\"the import paths " &
      "toRistrettoStaticSecret and keypair(seed, expectedPublic)\")."),
    disasm: Coverage(kind: ckCoveredBy, coveredBy: stDerivePublic),
    declassIds: @[],
    note: "janus consumer finding 2's load-time gate for persisted keys.",
  ),
  stSign: SecretTargetEntry(
    id: stSign,
    qualifiedProc: "signing.sign",
    facadeExported: true,
    ruleBasis: "rule1",
    secretShape: "kp: Keypair -- holds the secret scalar internally.",
    dudect: Coverage(kind: ckCoveredBy, coveredBy: stSignDetached),
    taint: Coverage(kind: ckCoveredBy, coveredBy: stSignDetached),
    disasm: Coverage(kind: ckCoveredBy, coveredBy: stSignDetached),
    declassIds: @[diSignDetachedSignature],
    note: "signing.sign(kp, msg) has two overloads (openArray[byte], " &
      "string), both bundled under this one entry -- both are thin " &
      "wrappers over private/backend.signDetached with no branch of " &
      "their own.",
  ),
  stSigningWipeSeed: SecretTargetEntry(
    id: stSigningWipeSeed,
    qualifiedProc: "signing.wipe",
    facadeExported: true,
    ruleBasis: "rule1",
    secretShape: "s: sink Seed.",
    dudect: Coverage(kind: ckExempt, rationale:
      "Wipe timing is not a dudect concern (see stX25519WipeStatic's " &
      "identical rationale)."),
    taint: Coverage(kind: ckExempt, rationale: Pending),
    disasm: Coverage(kind: ckExempt, rationale:
      "Not a {.noinline.} secret-path root."),
    declassIds: @[],
    note: "",
  ),
  stSigningWipeKeypair: SecretTargetEntry(
    id: stSigningWipeKeypair,
    qualifiedProc: "signing.wipe",
    facadeExported: true,
    ruleBasis: "rule1",
    secretShape: "kp: var Keypair.",
    dudect: Coverage(kind: ckExempt, rationale:
      "Wipe timing is not a dudect concern."),
    taint: Coverage(kind: ckExempt, rationale: Pending),
    disasm: Coverage(kind: ckExempt, rationale:
      "Not a {.noinline.} secret-path root."),
    declassIds: @[],
    note: "",
  ),
  stPublic: SecretTargetEntry(
    id: stPublic,
    qualifiedProc: "signing.public",
    facadeExported: true,
    ruleBasis: "rule1",
    secretShape: "kp: Keypair -- reads its already-public field.",
    dudect: Coverage(kind: ckExempt, rationale:
      "Returns an already-derived PUBLIC field via a plain field read, " &
      "no secret-dependent branch."),
    taint: Coverage(kind: ckExempt, rationale: Pending),
    disasm: Coverage(kind: ckExempt, rationale:
      "Plain field accessor, not a {.noinline.} secret-path root."),
    declassIds: @[],
    note: "",
  ),
  stToSeedBytes: SecretTargetEntry(
    id: stToSeedBytes,
    qualifiedProc: "signing.toSeedBytes",
    facadeExported: true,
    ruleBasis: "rule1",
    secretShape: "kp: Keypair -- exports the raw SEED bytes (the " &
      "flagship secret-disclosure boundary this proc's own facade " &
      "rename from toBytes exists to signal, per CLAUDE.md's own " &
      "round-3 finding A7 entry).",
    dudect: Coverage(kind: ckExempt, rationale:
      "Plain field read/copy, no secret-dependent branch or index -- " &
      "CT by construction."),
    taint: Coverage(kind: ckExempt, rationale: Pending & " A genuine " &
      "secret-disclosure boundary (exports Seed bytes) worth a " &
      "dedicated taint target; not yet built."),
    disasm: Coverage(kind: ckExempt, rationale:
      "Plain field copy, not a {.noinline.} secret-path root."),
    declassIds: @[],
    note: "",
  ),
  stRistrettoScalarmultStatic: SecretTargetEntry(
    id: stRistrettoScalarmultStatic,
    qualifiedProc: "ristretto.ristrettoScalarmult",
    facadeExported: true,
    ruleBasis: "rule1",
    secretShape: "secret: RistrettoStaticSecret.",
    dudect: Coverage(kind: ckDirect, name: "ristretto.ristrettoScalarmult"),
    taint: Coverage(kind: ckExempt, rationale: Pending),
    disasm: Coverage(kind: ckCoveredBy, coveredBy: stGeScalarmultCT),
    declassIds: @[],
    note: "Genuine fixed-vs-random-SECRET leak test (RFC-004 slice 7b) " &
      "via scalar.geScalarmultCT.",
  ),
  stRistrettoScalarmultEphemeral: SecretTargetEntry(
    id: stRistrettoScalarmultEphemeral,
    qualifiedProc: "ristretto.ristrettoScalarmult",
    facadeExported: true,
    ruleBasis: "rule1",
    secretShape: "secret: sink RistrettoEphemeralSecret.",
    dudect: Coverage(kind: ckCoveredBy, coveredBy: stRistrettoScalarmultStatic),
    taint: Coverage(kind: ckExempt, rationale: Pending),
    disasm: Coverage(kind: ckCoveredBy, coveredBy: stGeScalarmultCT),
    declassIds: @[],
    note: "Ephemeral-covered-by-static (this register's own first-" &
      "class-data version of the rationale ct_main.nim's module doc " &
      "states in prose): the ephemeral role's one consuming call runs " &
      "the identical scalar.geScalarmultCT the static entry already " &
      "measures with full fixed-vs-random power, so a dedicated " &
      "calibration target would add runtime without adding information.",
  ),
  stRistrettoScalarmultBase: SecretTargetEntry(
    id: stRistrettoScalarmultBase,
    qualifiedProc: "ristretto.ristrettoScalarmultBase",
    facadeExported: true,
    ruleBasis: "rule1",
    secretShape: "secret: RistrettoStaticSecret | RistrettoEphemeralSecret " &
      "(two overloads).",
    dudect: Coverage(kind: ckCoveredBy, coveredBy: stGeScalarmultBase),
    taint: Coverage(kind: ckExempt, rationale: Pending),
    disasm: Coverage(kind: ckCoveredBy, coveredBy: stGeScalarmultBase),
    declassIds: @[],
    note: "Bundles both overloads under one register row (same " &
      "collapsing rationale as stX25519Base) -- both delegate directly " &
      "to scalar.geScalarmultBase with no branch of their own.",
  ),
  stGeScalarmultCT: SecretTargetEntry(
    id: stGeScalarmultCT,
    qualifiedProc: "scalar.geScalarmultCT",
    facadeExported: false,
    ruleBasis: "curated",
    secretShape: "s: SecretScalar.",
    dudect: Coverage(kind: ckCoveredBy, coveredBy: stRistrettoScalarmultStatic),
    taint: Coverage(kind: ckExempt, rationale: Pending),
    disasm: Coverage(kind: ckDirect, name: "geScalarmultCT"),
    declassIds: @[],
    note: "Module-private CT variable-base scalarmult, curated as an " &
      "A2 disasm root -- the only route dudect measures it through is " &
      "ristretto.ristrettoScalarmult (static role).",
  ),
  stRistrettoEncode: SecretTargetEntry(
    id: stRistrettoEncode,
    qualifiedProc: "ristretto.ristrettoEncode",
    facadeExported: true,
    ruleBasis: "curated",
    secretShape: "pt: RistrettoPoint -- a PUBLIC-register value, but " &
      "routinely secret-DERIVED (a Pedersen commitment before " &
      "publication, an OPRF blinded element) in this module's own " &
      "motivating protocols. RistrettoPoint is not an enumerated " &
      "secret-role type, so this entry is curated (A1's own target " &
      "list names it explicitly), not rule-1-mandated.",
    dudect: Coverage(kind: ckDirect, name: "ristretto.ristrettoEncode"),
    taint: Coverage(kind: ckExempt, rationale: Pending),
    disasm: Coverage(kind: ckDirect, name: "ristrettoEncode"),
    declassIds: @[],
    note: "ristretto.ristrettoDecode gets NO register entry, " &
      "deliberately: its input is attacker-supplied wire data, public " &
      "by definition -- there is no secret class to measure (matching " &
      "ed25519.pointDecode's own precedent).",
  ),
  stRistrettoEqual: SecretTargetEntry(
    id: stRistrettoEqual,
    qualifiedProc: "ristretto.`==`",
    facadeExported: true,
    ruleBasis: "curated",
    secretShape: "a, b: RistrettoPoint -- same curated rationale as " &
      "stRistrettoEncode.",
    dudect: Coverage(kind: ckDirect, name: "ristretto.`==` (P,P) vs (P,Q)"),
    taint: Coverage(kind: ckExempt, rationale: Pending),
    disasm: Coverage(kind: ckDirect, name: "`==`"),
    declassIds: @[],
    note: "dudect carve-out (a VERDICT note, not a coverage gap -- the " &
      "dudect cell above stays `direct`): this target measurably FAILS " &
      "(worst-case |t| in the 20-40+ range), extensively investigated " &
      "and attributed to a harness resolution-floor artifact for very " &
      "fast primitives (~800-900 raw cycles, 30-600x smaller than every " &
      "other dudect target) rather than a genuine leak -- see " &
      "docs/ct-results.md and ct_main.nim's own module doc for the full " &
      "investigation (two rounds of non-shipped diagnostics, an " &
      "always-unequal control target showing an equally large spurious " &
      "|t|). This entry HAS a report; the carve-out is about the " &
      "report's own verdict, not about whether the instrument covers it.",
  ),
  stRistrettoFromUniformBytes: SecretTargetEntry(
    id: stRistrettoFromUniformBytes,
    qualifiedProc: "ristretto.ristrettoFromUniformBytes",
    facadeExported: true,
    ruleBasis: "curated",
    secretShape: "b: array[64, byte] -- a raw-byte intake, not a " &
      "to*Secret*/toSeed*-pattern name and not accepting a role type. " &
      "The RFC's own named curated-annex example " &
      "(docs/rfc-005-validation-infra.md lines 444-497): OPRF blinding " &
      "maps a client's PRIVATE input to the group, so this map's input " &
      "is secret in exactly the deployments this RFC headlines, even " &
      "though the map itself is a total function with no accept/reject " &
      "verdict.",
    dudect: Coverage(kind: ckDirect, name: "ristretto.ristrettoFromUniformBytes"),
    taint: Coverage(kind: ckExempt, rationale: Pending),
    disasm: Coverage(kind: ckExempt, rationale:
      "Total function, not in the A2 {.noinline.} root list today -- " &
      "its arithmetic runs through field/scalar primitives other roots " &
      "already cover."),
    declassIds: @[],
    note: "",
  ),
  stToRistrettoStaticSecret: SecretTargetEntry(
    id: stToRistrettoStaticSecret,
    qualifiedProc: "ristretto.toRistrettoStaticSecret",
    facadeExported: true,
    ruleBasis: "rule2",
    secretShape: "bytes: array[32, byte] -- import boundary, REJECTS " &
      "non-canonical (returns Option[..]).",
    dudect: Coverage(kind: ckExempt, rationale:
      "No dedicated dudect target -- the underlying scIsCanonicalCT " &
      "verdict is machine-checked branch-free (tests/verify/" &
      "symex_reduce.nim's carry-bound lemma) and mutation-killed (S25, " &
      "scIsCanonicalCT verdict flip) -- a dudect target would re-time " &
      "an already-proven primitive."),
    taint: Coverage(kind: ckExempt, rationale: Pending & " private/" &
      "taint.nim's own Stage-3 schema proof-spike already drafted " &
      "diRistrettoStaticSecretImportReject for exactly this proc -- " &
      "not yet promoted to a live DeclassId/target."),
    disasm: Coverage(kind: ckExempt, rationale:
      "scIsCanonicalCT is inlined into feEqualCT-style straight-line " &
      "code with no root of its own in the A2 list."),
    declassIds: @[],
    note: "",
  ),
  stToRistrettoStaticSecretWide: SecretTargetEntry(
    id: stToRistrettoStaticSecretWide,
    qualifiedProc: "ristretto.toRistrettoStaticSecretWide",
    facadeExported: true,
    ruleBasis: "rule2",
    secretShape: "bytes: array[64, byte] -- import boundary, TOTAL " &
      "(wide-reduces, no reject).",
    dudect: Coverage(kind: ckCoveredBy, coveredBy: stRistrettoScalarmultStatic),
    taint: Coverage(kind: ckExempt, rationale: Pending),
    disasm: Coverage(kind: ckExempt, rationale:
      "Total reduction, no accept/reject branch; not a {.noinline.} root."),
    declassIds: @[],
    note: "dudect's opRistrettoScalarmult constructs the secret via " &
      "this proc INSIDE the measured region every sample.",
  ),
  stRistrettoWipeStatic: SecretTargetEntry(
    id: stRistrettoWipeStatic,
    qualifiedProc: "ristretto.wipe",
    facadeExported: true,
    ruleBasis: "rule1",
    secretShape: "s: var RistrettoStaticSecret.",
    dudect: Coverage(kind: ckExempt, rationale:
      "Wipe timing is not a dudect concern."),
    taint: Coverage(kind: ckExempt, rationale: Pending),
    disasm: Coverage(kind: ckExempt, rationale:
      "Not a {.noinline.} secret-path root."),
    declassIds: @[],
    note: "",
  ),
  stRistrettoWipeEphemeral: SecretTargetEntry(
    id: stRistrettoWipeEphemeral,
    qualifiedProc: "ristretto.wipe",
    facadeExported: true,
    ruleBasis: "rule1",
    secretShape: "s: sink RistrettoEphemeralSecret.",
    dudect: Coverage(kind: ckExempt, rationale:
      "Wipe timing is not a dudect concern."),
    taint: Coverage(kind: ckExempt, rationale: Pending),
    disasm: Coverage(kind: ckExempt, rationale:
      "Not a {.noinline.} secret-path root."),
    declassIds: @[],
    note: "",
  ),
  stRistrettoWipeShared: SecretTargetEntry(
    id: stRistrettoWipeShared,
    qualifiedProc: "ristretto.wipe",
    facadeExported: true,
    ruleBasis: "rule1",
    secretShape: "sh: var RistrettoShared.",
    dudect: Coverage(kind: ckExempt, rationale:
      "Wipe timing is not a dudect concern."),
    taint: Coverage(kind: ckExempt, rationale: Pending),
    disasm: Coverage(kind: ckExempt, rationale:
      "Not a {.noinline.} secret-path root."),
    declassIds: @[],
    note: "",
  ),
  stRistrettoToBytesStatic: SecretTargetEntry(
    id: stRistrettoToBytesStatic,
    qualifiedProc: "ristretto.toBytes",
    facadeExported: true,
    ruleBasis: "rule1",
    secretShape: "s: RistrettoStaticSecret -- exports the raw scalar bytes.",
    dudect: Coverage(kind: ckExempt, rationale:
      "Plain field copy, no secret-dependent branch or index."),
    taint: Coverage(kind: ckExempt, rationale: Pending),
    disasm: Coverage(kind: ckExempt, rationale:
      "Plain field copy, not a {.noinline.} secret-path root."),
    declassIds: @[],
    note: "",
  ),
  stRistrettoToBytesShared: SecretTargetEntry(
    id: stRistrettoToBytesShared,
    qualifiedProc: "ristretto.toBytes",
    facadeExported: true,
    ruleBasis: "rule1",
    secretShape: "sh: RistrettoShared -- the completed DH-share output.",
    dudect: Coverage(kind: ckExempt, rationale:
      "Plain field copy, no secret-dependent branch or index."),
    taint: Coverage(kind: ckExempt, rationale:
      "Boundary rule, same as stX25519ToBytesShared: a secret OUTPUT's " &
      "(RistrettoShared) disclosure is never a sanctioned DeclassId."),
    disasm: Coverage(kind: ckExempt, rationale:
      "Plain field copy, not a {.noinline.} secret-path root."),
    declassIds: @[],
    note: "PERMANENT exemption, not a slice-21 pending item.",
  ),
  stSha512Message: SecretTargetEntry(
    id: stSha512Message,
    qualifiedProc: "private/sha512.sha512",
    facadeExported: false,
    ruleBasis: "curated",
    secretShape: "a (, b, c): openArray[byte] -- the message, which may " &
      "be secret-derived (the ed25519 seed hash, the nonce hash, the " &
      "challenge hash all route through this proc). The RFC's own named " &
      "curated-annex example alongside ristrettoFromUniformBytes.",
    dudect: Coverage(kind: ckDirect, name: "sha512.sha512 (4-block compress)"),
    taint: Coverage(kind: ckExempt, rationale: Pending & " private/" &
      "taint.nim's own Stage-3 schema proof-spike already drafted " &
      "diSha512DigestKat for exactly this proc -- not yet promoted to " &
      "a live DeclassId/target."),
    disasm: Coverage(kind: ckDirect, name: "compress"),
    declassIds: @[],
    note: "Not facade-exported (private/, sello is a 25519 library, not " &
      "a hash toolkit) -- curated because backend.derivePublic/" &
      "signDetached/challenge.challenge all call it on secret-derived " &
      "input.",
  ),
  stWipeGeneric: SecretTargetEntry(
    id: stWipeGeneric,
    qualifiedProc: "wipe.wipe",
    facadeExported: true,
    ruleBasis: "curated",
    secretShape: "bytes: var array[32, byte] -- untyped raw secret " &
      "material a caller holds outside any of sello's own secret-" &
      "carrying types. Not rule-1 (the parameter is a bare array, not " &
      "an enumerated secret-role type) -- curated because A1's own " &
      "wipe-paths note names exactly this class (\"caller-owned in-" &
      "place buffers, wipe.nim's overload\") as the observable subset " &
      "taint CAN check.",
    dudect: Coverage(kind: ckExempt, rationale:
      "Wipe timing is not a dudect concern."),
    taint: Coverage(kind: ckExempt, rationale: Pending),
    disasm: Coverage(kind: ckExempt, rationale:
      "Delegates to private/ct.wipe, itself not a {.noinline.} root " &
      "beyond the existing feCMove/feCSwap/cmovCached trio already " &
      "covered elsewhere."),
    declassIds: @[],
    note: "",
  ),
]

proc disasmRoots*(): seq[string] =
  ## The deduplicated union of every `ckDirect` disasm-cell root name --
  ## the set slice 23's disasm gate will assert `register roots ⊆
  ## baseline root set` against (containment, per A2's own text). Order
  ## is the register's own enum order (stable, reviewable diffs); dedup
  ## via a `HashSet` since several entries name the same root (e.g. every
  ## X25519 secret-scalar entry disasm-covers-by `stX25519Ladder`, so
  ## only THAT entry's own cell contributes "ladder" -- coveredBy cells
  ## never contribute a name of their own, by construction).
  var seen: HashSet[string]
  for entry in secretTargetRegister:
    if entry.disasm.kind == ckDirect and entry.disasm.name notin seen:
      seen.incl(entry.disasm.name)
      result.add(entry.disasm.name)
