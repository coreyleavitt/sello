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
##     deliberately, per RFC-005 slice 20's own task text ("decide the
##     vocabulary so slice 21 flips them to direct without schema
##     change"): a rationale beginning literally with the string
##     `"PENDING (slice N)"` (a module-level `const Pending`, referenced
##     BY IDENTIFIER at every call site rather than re-typed as a
##     literal, so a coverage-check script's grep and this array's own
##     cells can never drift) would be a TEMPORARY exemption -- named in
##     an instrument's own target list but not yet wired into a live
##     target -- and every other rationale is a PERMANENT, stated design
##     boundary (e.g. "wipe timing is not a dudect concern", or the
##     boundary rule that a secret OUTPUT's disclosure is never
##     sanctioned). Flipping a `PENDING` cell to `ckDirect` when its
##     target lands is a one-line diff to THIS array; the `Coverage`
##     variant itself never changes shape. Every instrument's own
##     coverage-check script greps for the literal `"PENDING (slice "`
##     prefix to print an honest skip-with-notation line rather than
##     silently treating an exempt cell as satisfied ("never silently
##     green"). **RFC-005 slice 21 flipped every one of the 28 taint-
##     column `PENDING (slice 21)` cells this slice's own predecessor
##     left behind to `ckDirect`/`ckCoveredBy`/a permanent `ckExempt`
##     rationale (0 PENDING cells remain as of this slice) -- the `const
##     Pending` binding itself is retired (no live reference left in this
##     array), kept available in this doc comment's own prose as the
##     mechanism record for a future instrument that needs the identical
##     temporary-exemption vocabulary again.**
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
    taint: Coverage(kind: ckCoveredBy, coveredBy: stDerivePublic),
    disasm: Coverage(kind: ckDirect, name: "geScalarmultBase"),
    declassIds: @[],
    note: "The fixed-base CT scalarmult underlying both signing/keygen " &
      "AND ristretto.ristrettoScalarmultBase's two overloads (see " &
      "stRistrettoScalarmultBase's coveredBy cell). Taint-coveredBy " &
      "stDerivePublic (RFC-005 slice 21): the \"sign\" taint target " &
      "exercises this proc's interior code path (as the unwrapped " &
      "SecretScalar behind backend.derivePublic's own call), with no " &
      "call site/DeclassId of its own -- a real secret-dependent branch " &
      "here would surface as an error inside that target.",
  ),
  stX25519Base: SecretTargetEntry(
    id: stX25519Base,
    qualifiedProc: "x25519.x25519Base",
    facadeExported: true,
    ruleBasis: "rule1",
    secretShape: "secret: X25519StaticSecret | X25519EphemeralSecret " &
      "(two overloads) -- the caller's private X25519 scalar.",
    dudect: Coverage(kind: ckDirect, name: "x25519.x25519Base"),
    taint: Coverage(kind: ckDirect, name: "x25519_base"),
    disasm: Coverage(kind: ckCoveredBy, coveredBy: stX25519Ladder),
    declassIds: @[diX25519BasePublicKey],
    note: "Bundles BOTH x25519Base overloads under one register row " &
      "(jsondoc/the facade-surface tooling treats them as one symbol). " &
      "Only the X25519StaticSecret arm (via toX25519StaticSecret) has " &
      "dedicated dudect coverage today -- the X25519EphemeralSecret " &
      "arm is not separately invoked by any dudect target, disclosed " &
      "here rather than silently implied by the shared entry. Taint " &
      "covers BOTH arms (RFC-005 slice 21): this cell names " &
      "\"x25519_base\" (the static-role target); " &
      "tests/ct_taint/target_x25519_ephemeral.nim exercises the " &
      "identical diX25519BasePublicKey call site via the ephemeral " &
      "overload, folded into stX25519EphemeralConsume's own cell below " &
      "rather than duplicated here.",
  ),
  stX25519EphemeralConsume: SecretTargetEntry(
    id: stX25519EphemeralConsume,
    qualifiedProc: "x25519.x25519",
    facadeExported: true,
    ruleBasis: "rule1",
    secretShape: "secret: sink X25519EphemeralSecret -- single-use " &
      "ephemeral scalar, consumed by this call.",
    dudect: Coverage(kind: ckDirect, name: "x25519(ephemeral) construct+consume"),
    taint: Coverage(kind: ckDirect, name: "x25519_ephemeral_normal"),
    disasm: Coverage(kind: ckCoveredBy, coveredBy: stX25519Ladder),
    declassIds: @[diX25519BasePublicKey, diX25519ZeroVerdict],
    note: "dudect target is a construct+consume CALIBRATION check, not " &
      "a fixed-vs-random-secret leak test -- X25519EphemeralSecret has " &
      "no from-bytes constructor, so no fixed class can be built (see " &
      "ct_main.nim's own module doc). The genuine leak-value test for " &
      "this shared ladder() is stX25519StaticDH. Taint (RFC-005 slice " &
      "21): tests/ct_taint/target_x25519_ephemeral.nim tapes the " &
      "private field via a harness-side cast (the type has no from-" &
      "bytes constructor), exercises x25519Base(ephemeral)'s shared " &
      "diX25519BasePublicKey call site and this overload's own " &
      "diX25519ZeroVerdict call site, both verdict arms (normal peer " &
      "AND the RFC 7748 u=0 small-order peer, " &
      "-d:x25519SmallOrderPeer) -- this cell names the identity anchor " &
      "\"x25519_ephemeral_normal\" only; the smallorder run shares the " &
      "same DeclassId and register entry, same convention as " &
      "stX25519StaticDH.",
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
    taint: Coverage(kind: ckCoveredBy, coveredBy: stX25519Base),
    disasm: Coverage(kind: ckDirect, name: "ladder"),
    declassIds: @[],
    note: "Module-private RFC 7748 Montgomery ladder, not facade- " &
      "exported -- curated because it is an A2 {.noinline.} disasm root " &
      "(docs/rfc-005-validation-infra.md lines 290-352) shared by every " &
      "X25519 secret-scalar entry above (stX25519Base, " &
      "stX25519EphemeralConsume, stX25519StaticDH all disasm-cover-by " &
      "this one root, since they all call the identical ladder()). " &
      "Taint-coveredBy stX25519Base (RFC-005 slice 21) for the same " &
      "reason: every X25519 taint target above runs this exact " &
      "function's own code path with no call site/DeclassId of its own.",
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
    taint: Coverage(kind: ckExempt, rationale:
      "Plain field copy, no secret-dependent branch or index for the " &
      "taint harness to check either (RFC-005 slice 21) -- the caller " &
      "already owns this secret, exporting it is not a sanctioned " &
      "PUBLICATION boundary the way diX25519BasePublicKey's own class " &
      "is, and there is no interior branch a memcheck run could ever " &
      "flag on this code path."),
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
    taint: Coverage(kind: ckDirect, name: "wipe_x25519"),
    disasm: Coverage(kind: ckExempt, rationale:
      "private/ct.wipe is straight-line, no secret-dependent branch; " &
      "not in the A2 {.noinline.} root list."),
    declassIds: @[],
    note: "RFC-005 slice 21: tests/ct_taint/target_wipe_x25519.nim " &
      "runs make-undefined-then-wipe-then-check-defined on this exact " &
      "overload's own memory (a `var` parameter -- no move/copy " &
      "involved), the cleanest of the three X25519 wipe checks. No " &
      "DeclassId: there is no accept/reject verdict here to register.",
  ),
  stX25519WipeShared: SecretTargetEntry(
    id: stX25519WipeShared,
    qualifiedProc: "x25519.wipe",
    facadeExported: true,
    ruleBasis: "rule1",
    secretShape: "sh: var X25519Shared.",
    dudect: Coverage(kind: ckExempt, rationale:
      "Same wipe-timing-is-not-a-dudect-concern rationale as stX25519WipeStatic."),
    taint: Coverage(kind: ckCoveredBy, coveredBy: stX25519WipeStatic),
    disasm: Coverage(kind: ckExempt, rationale:
      "Not a {.noinline.} secret-path root."),
    declassIds: @[],
    note: "Taint-coveredBy stX25519WipeStatic (RFC-005 slice 21): " &
      "target_wipe_x25519.nim's second block runs the identical " &
      "make-undefined-then-wipe-then-check-defined sequence on this " &
      "overload directly, in the same target file/register cell.",
  ),
  stX25519WipeEphemeral: SecretTargetEntry(
    id: stX25519WipeEphemeral,
    qualifiedProc: "x25519.wipe",
    facadeExported: true,
    ruleBasis: "rule1",
    secretShape: "s: sink X25519EphemeralSecret.",
    dudect: Coverage(kind: ckExempt, rationale:
      "Same wipe-timing-is-not-a-dudect-concern rationale as stX25519WipeStatic."),
    taint: Coverage(kind: ckCoveredBy, coveredBy: stX25519WipeStatic),
    disasm: Coverage(kind: ckExempt, rationale:
      "Not a {.noinline.} secret-path root."),
    declassIds: @[],
    note: "Taint-coveredBy stX25519WipeStatic (RFC-005 slice 21): " &
      "target_wipe_x25519.nim's third block runs this sink overload " &
      "with a genuinely tainted input end to end -- honestly disclosed " &
      "there as a WEAKER check than the two `var` blocks (the caller- " &
      "side memory check is confounded by Nim's own post-move " &
      "`wasMoved` reset, not `wipe`'s own store), still folded into " &
      "the same register cell rather than claiming an equally clean " &
      "isolation it does not have.",
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
    taint: Coverage(kind: ckDirect, name: "keypair_expected_public_match"),
    disasm: Coverage(kind: ckCoveredBy, coveredBy: stDerivePublic),
    declassIds: @[diDerivePublicKey],
    note: "janus consumer finding 2's load-time gate for persisted " &
      "keys. Taint (RFC-005 slice 21): NO new DeclassId/call site -- " &
      "by the time this proc's interior `kp.public == expectedPublic` " &
      "compare runs, kp.public's bytes are ALREADY DEFINED (the " &
      "diDerivePublicKey call site inside the keypair(seed) call this " &
      "proc makes internally already fired), so the compare runs on " &
      "fully-defined data regardless of match/mismatch arm -- see " &
      "tests/ct_taint/target_keypair_expected_public.nim's own header " &
      "comment for the full reasoning. Both arms driven " &
      "(-d:keypairMismatch selects mismatch); this cell names the " &
      "match arm's identity only, same convention as stX25519StaticDH.",
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
    taint: Coverage(kind: ckDirect, name: "wipe_signing"),
    disasm: Coverage(kind: ckExempt, rationale:
      "Not a {.noinline.} secret-path root."),
    declassIds: @[],
    note: "RFC-005 slice 21: tests/ct_taint/target_wipe_signing.nim's " &
      "first block runs make-undefined-then-wipe-then-check-defined via " &
      "a harness-side cast (Seed has no public raw-bytes accessor of " &
      "its own) -- honestly disclosed there as confounded by Nim's own " &
      "post-move `wasMoved` reset (the same disclosure " &
      "stX25519WipeEphemeral's own note makes for the identical " &
      "sink-parameter shape).",
  ),
  stSigningWipeKeypair: SecretTargetEntry(
    id: stSigningWipeKeypair,
    qualifiedProc: "signing.wipe",
    facadeExported: true,
    ruleBasis: "rule1",
    secretShape: "kp: var Keypair.",
    dudect: Coverage(kind: ckExempt, rationale:
      "Wipe timing is not a dudect concern."),
    taint: Coverage(kind: ckCoveredBy, coveredBy: stSigningWipeSeed),
    disasm: Coverage(kind: ckExempt, rationale:
      "Not a {.noinline.} secret-path root."),
    declassIds: @[],
    note: "Taint-coveredBy stSigningWipeSeed (RFC-005 slice 21): " &
      "target_wipe_signing.nim's second block exercises this exact " &
      "overload directly, through the PUBLIC toSeedBytes(kp) surface " &
      "(no harness-side cast needed -- see that file's own header " &
      "comment for why this is the cleanest of this slice's wipe " &
      "checks), in the same target file/register cell.",
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
    taint: Coverage(kind: ckExempt, rationale:
      "Returns an ALREADY-DECLASSIFIED field (RFC-005 slice 21): " &
      "kp.public was declassified once, at construction time, via the " &
      "real diDerivePublicKey call site inside keypair(seed)'s own " &
      "backend.derivePublic call -- nothing for a taint run to check " &
      "here, since the bytes this accessor reads are already fully " &
      "defined by the time any Keypair value exists to call it on."),
    disasm: Coverage(kind: ckExempt, rationale:
      "Plain field accessor, not a {.noinline.} secret-path root."),
    declassIds: @[diDerivePublicKey],
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
    taint: Coverage(kind: ckExempt, rationale:
      "Plain field copy, no secret-dependent branch or index for the " &
      "taint harness to check (RFC-005 slice 21, decided rather than " &
      "left pending): unlike diDerivePublicKey/diX25519BasePublicKey's " &
      "class, this proc hands the CALLER their OWN already-possessed " &
      "secret (the Keypair's own seed material) back for persistence " &
      "-- it is not a publication to a third party, so there is no " &
      "sanctioned-disclosure boundary here to register a DeclassId " &
      "for, the same reasoning stX25519ToBytesStatic's own rationale " &
      "states for X25519StaticSecret's raw-bytes export."),
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
    taint: Coverage(kind: ckDirect, name: "ristretto_scalarmult"),
    disasm: Coverage(kind: ckCoveredBy, coveredBy: stGeScalarmultCT),
    declassIds: @[diRistrettoEncodeOutput, diRistrettoEqualVerdict],
    note: "Genuine fixed-vs-random-SECRET leak test (RFC-004 slice 7b) " &
      "via scalar.geScalarmultCT. Taint (RFC-005 slice 21): " &
      "tests/ct_taint/target_ristretto_scalarmult.nim builds the secret " &
      "via toRistrettoStaticSecretWide (mirroring ct_main.nim's own " &
      "opRistrettoScalarmult construction -- see " &
      "stToRistrettoStaticSecretWide's own cell), calls this proc, " &
      "then encodes and `==`-compares the result -- neither " &
      "ristrettoScalarmultBase nor this proc has a branch of its own to " &
      "protect (both delegate straight into geScalarmultBase/" &
      "geScalarmultCT), so the target itself declassifies its own " &
      "encoded copy at diRistrettoEncodeOutput (see that id's own " &
      "register entry for why NOT inside ristrettoEncode itself), while " &
      "`` `==` ``'s own diRistrettoEqualVerdict call site fires for " &
      "real, inside the library.",
  ),
  stRistrettoScalarmultEphemeral: SecretTargetEntry(
    id: stRistrettoScalarmultEphemeral,
    qualifiedProc: "ristretto.ristrettoScalarmult",
    facadeExported: true,
    ruleBasis: "rule1",
    secretShape: "secret: sink RistrettoEphemeralSecret.",
    dudect: Coverage(kind: ckCoveredBy, coveredBy: stRistrettoScalarmultStatic),
    taint: Coverage(kind: ckDirect, name: "ristretto_ephemeral_normal"),
    disasm: Coverage(kind: ckCoveredBy, coveredBy: stGeScalarmultCT),
    declassIds: @[diRistrettoEphemeralZeroVerdict],
    note: "Ephemeral-covered-by-static for DUDECT (this register's own " &
      "first-class-data version of the rationale ct_main.nim's module " &
      "doc states in prose): the ephemeral role's one consuming call " &
      "runs the identical scalar.geScalarmultCT the static entry " &
      "already measures with full fixed-vs-random power, so a " &
      "dedicated TIMING target would add runtime without adding " &
      "information. TAINT is direct, not coveredBy (RFC-005 slice 21): " &
      "this overload's own OR-accumulated identity-encoding zero-" &
      "verdict (diRistrettoEphemeralZeroVerdict) is a call site the " &
      "static-role overload never reaches, so " &
      "tests/ct_taint/target_ristretto_ephemeral.nim gives it real, " &
      "independent taint coverage -- harness-side cast for the " &
      "private field (no from-bytes constructor), both verdict arms " &
      "(the degenerate RistrettoIdentity peer AND a normal peer, " &
      "-d:ristrettoIdentityPeer). RistrettoShared output handled by " &
      "the boundary rule (harness-side markDefined, no DeclassId).",
  ),
  stRistrettoScalarmultBase: SecretTargetEntry(
    id: stRistrettoScalarmultBase,
    qualifiedProc: "ristretto.ristrettoScalarmultBase",
    facadeExported: true,
    ruleBasis: "rule1",
    secretShape: "secret: RistrettoStaticSecret | RistrettoEphemeralSecret " &
      "(two overloads).",
    dudect: Coverage(kind: ckCoveredBy, coveredBy: stGeScalarmultBase),
    taint: Coverage(kind: ckCoveredBy, coveredBy: stRistrettoScalarmultStatic),
    disasm: Coverage(kind: ckCoveredBy, coveredBy: stGeScalarmultBase),
    declassIds: @[],
    note: "Bundles both overloads under one register row (same " &
      "collapsing rationale as stX25519Base) -- both delegate directly " &
      "to scalar.geScalarmultBase with no branch of their own. Taint-" &
      "coveredBy stRistrettoScalarmultStatic (RFC-005 slice 21): the " &
      "static overload is exercised directly by " &
      "target_ristretto_scalarmult.nim (basePt = " &
      "ristrettoScalarmultBase(secret)); the ephemeral overload is " &
      "exercised by target_ristretto_ephemeral.nim's own C1 = " &
      "ristrettoScalarmultBase(secret) borrow. Neither overload has a " &
      "branch of its own, so no separate DeclassId/call site is needed.",
  ),
  stGeScalarmultCT: SecretTargetEntry(
    id: stGeScalarmultCT,
    qualifiedProc: "scalar.geScalarmultCT",
    facadeExported: false,
    ruleBasis: "curated",
    secretShape: "s: SecretScalar.",
    dudect: Coverage(kind: ckCoveredBy, coveredBy: stRistrettoScalarmultStatic),
    taint: Coverage(kind: ckCoveredBy, coveredBy: stRistrettoScalarmultStatic),
    disasm: Coverage(kind: ckDirect, name: "geScalarmultCT"),
    declassIds: @[],
    note: "Module-private CT variable-base scalarmult, curated as an " &
      "A2 disasm root -- the only route dudect measures it through is " &
      "ristretto.ristrettoScalarmult (static role). Taint-coveredBy " &
      "the same entry (RFC-005 slice 21): both " &
      "target_ristretto_scalarmult.nim and " &
      "target_ristretto_ephemeral.nim run this exact function's own " &
      "code path with no call site/DeclassId of its own.",
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
    taint: Coverage(kind: ckDirect, name: "ristretto_scalarmult"),
    disasm: Coverage(kind: ckDirect, name: "ristrettoEncode"),
    declassIds: @[diRistrettoEncodeOutput],
    note: "ristretto.ristrettoDecode gets NO register entry, " &
      "deliberately: its input is attacker-supplied wire data, public " &
      "by definition -- there is no secret class to measure (matching " &
      "ed25519.pointDecode's own precedent). Taint (RFC-005 slice 21): " &
      "ristrettoEncode has DELIBERATELY NO interior declassify call " &
      "site (see that function's own doc comment) -- it is reused on " &
      "the genuine secret DH product inside " &
      "ristrettoScalarmult(sink RistrettoEphemeralSecret, ...), and an " &
      "unconditional interior declassify would violate this register's " &
      "own boundary rule for that path. diRistrettoEncodeOutput is " &
      "instead declassified at each genuinely-public CALL SITE: this " &
      "cell names \"ristretto_scalarmult\" (which also exercises " &
      "ristrettoScalarmultBase's/ristrettoScalarmult(static)'s own " &
      "encodings); target_ristretto_from_uniform.nim exercises the " &
      "identical id independently too.",
  ),
  stRistrettoEqual: SecretTargetEntry(
    id: stRistrettoEqual,
    qualifiedProc: "ristretto.`==`",
    facadeExported: true,
    ruleBasis: "curated",
    secretShape: "a, b: RistrettoPoint -- same curated rationale as " &
      "stRistrettoEncode.",
    dudect: Coverage(kind: ckDirect, name: "ristretto.`==` (P,P) vs (P,Q)"),
    taint: Coverage(kind: ckDirect, name: "ristretto_scalarmult"),
    disasm: Coverage(kind: ckDirect, name: "`==`"),
    declassIds: @[diRistrettoEqualVerdict],
    note: "RFC-005 slice 21 taint: unlike ristrettoEncode, `` `==` `` " &
      "HAS an interior declassify call site (no ephemeral-secret-path " &
      "reuse conflict -- RistrettoShared has no `==` of its own), " &
      "exercised by target_ristretto_scalarmult.nim comparing two " &
      "computed points against themselves and each other. " &
      "dudect carve-out (a VERDICT note, not a coverage gap -- the " &
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
    taint: Coverage(kind: ckDirect, name: "ristretto_from_uniform"),
    disasm: Coverage(kind: ckExempt, rationale:
      "Total function, not in the A2 {.noinline.} root list today -- " &
      "its arithmetic runs through field/scalar primitives other roots " &
      "already cover."),
    declassIds: @[diRistrettoEncodeOutput],
    note: "RFC-005 slice 21 taint: tests/ct_taint/target_ristretto_from_uniform.nim " &
      "taints the 64-byte input, calls this proc (a total function, no " &
      "interior branch), then encodes and declassifies its own copy of " &
      "the result at diRistrettoEncodeOutput (same reasoning as " &
      "stRistrettoScalarmultStatic's own cell: no call site inside " &
      "ristrettoEncode itself).",
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
    taint: Coverage(kind: ckDirect, name: "ristretto_import_canonical"),
    disasm: Coverage(kind: ckExempt, rationale:
      "scIsCanonicalCT is inlined into feEqualCT-style straight-line " &
      "code with no root of its own in the A2 list."),
    declassIds: @[diRistrettoStaticSecretImportReject],
    note: "RFC-005 slice 21 taint: promotes private/taint.nim's own " &
      "Stage-3 schema proof-spike draft to a live target. Both verdict " &
      "arms driven (-d:ristrettoImportNonCanonical selects the reject " &
      "arm, an all-0xFF input far above the group order L) -- this " &
      "cell names the canonical-accept arm's identity only, same " &
      "convention as stX25519StaticDH. GENUINE DESIGN CONFIRMATION " &
      "caught by an early draft of the target: on the accept arm, the " &
      "returned RistrettoStaticSecret's OWN bytes correctly stay " &
      "tainted (only the 1-byte verdict is declassified) -- an early " &
      "target draft asserted checkDefined on the accepted secret's own " &
      "bytes and correctly went RED, confirming this proc does not " &
      "leak the imported scalar past its accept/reject verdict; fixed " &
      "in the target, not the library (see " &
      "target_ristretto_import.nim's own header comment).",
  ),
  stToRistrettoStaticSecretWide: SecretTargetEntry(
    id: stToRistrettoStaticSecretWide,
    qualifiedProc: "ristretto.toRistrettoStaticSecretWide",
    facadeExported: true,
    ruleBasis: "rule2",
    secretShape: "bytes: array[64, byte] -- import boundary, TOTAL " &
      "(wide-reduces, no reject).",
    dudect: Coverage(kind: ckCoveredBy, coveredBy: stRistrettoScalarmultStatic),
    taint: Coverage(kind: ckCoveredBy, coveredBy: stRistrettoScalarmultStatic),
    disasm: Coverage(kind: ckExempt, rationale:
      "Total reduction, no accept/reject branch; not a {.noinline.} root."),
    declassIds: @[],
    note: "dudect's opRistrettoScalarmult constructs the secret via " &
      "this proc INSIDE the measured region every sample. Taint-" &
      "coveredBy the same entry (RFC-005 slice 21): " &
      "target_ristretto_scalarmult.nim's own secret construction " &
      "mirrors that exact idiom.",
  ),
  stRistrettoWipeStatic: SecretTargetEntry(
    id: stRistrettoWipeStatic,
    qualifiedProc: "ristretto.wipe",
    facadeExported: true,
    ruleBasis: "rule1",
    secretShape: "s: var RistrettoStaticSecret.",
    dudect: Coverage(kind: ckExempt, rationale:
      "Wipe timing is not a dudect concern."),
    taint: Coverage(kind: ckDirect, name: "wipe_ristretto"),
    disasm: Coverage(kind: ckExempt, rationale:
      "Not a {.noinline.} secret-path root."),
    declassIds: @[],
    note: "RFC-005 slice 21: tests/ct_taint/target_wipe_ristretto.nim's " &
      "first block runs make-undefined-then-wipe-then-check-defined on " &
      "this exact overload's own memory (a `var` parameter -- no move/" &
      "copy involved), same clean register as stX25519WipeStatic.",
  ),
  stRistrettoWipeEphemeral: SecretTargetEntry(
    id: stRistrettoWipeEphemeral,
    qualifiedProc: "ristretto.wipe",
    facadeExported: true,
    ruleBasis: "rule1",
    secretShape: "s: sink RistrettoEphemeralSecret.",
    dudect: Coverage(kind: ckExempt, rationale:
      "Wipe timing is not a dudect concern."),
    taint: Coverage(kind: ckCoveredBy, coveredBy: stRistrettoWipeStatic),
    disasm: Coverage(kind: ckExempt, rationale:
      "Not a {.noinline.} secret-path root."),
    declassIds: @[],
    note: "Taint-coveredBy stRistrettoWipeStatic (RFC-005 slice 21): " &
      "target_wipe_ristretto.nim's third block runs this sink overload " &
      "end to end, honestly disclosed there as confounded by Nim's own " &
      "post-move `wasMoved` reset, same register as " &
      "stX25519WipeEphemeral's own note.",
  ),
  stRistrettoWipeShared: SecretTargetEntry(
    id: stRistrettoWipeShared,
    qualifiedProc: "ristretto.wipe",
    facadeExported: true,
    ruleBasis: "rule1",
    secretShape: "sh: var RistrettoShared.",
    dudect: Coverage(kind: ckExempt, rationale:
      "Wipe timing is not a dudect concern."),
    taint: Coverage(kind: ckCoveredBy, coveredBy: stRistrettoWipeStatic),
    disasm: Coverage(kind: ckExempt, rationale:
      "Not a {.noinline.} secret-path root."),
    declassIds: @[],
    note: "Taint-coveredBy stRistrettoWipeStatic (RFC-005 slice 21): " &
      "target_wipe_ristretto.nim's second block exercises this exact " &
      "overload directly (a `var` parameter -- no move/copy involved), " &
      "in the same target file/register cell.",
  ),
  stRistrettoToBytesStatic: SecretTargetEntry(
    id: stRistrettoToBytesStatic,
    qualifiedProc: "ristretto.toBytes",
    facadeExported: true,
    ruleBasis: "rule1",
    secretShape: "s: RistrettoStaticSecret -- exports the raw scalar bytes.",
    dudect: Coverage(kind: ckExempt, rationale:
      "Plain field copy, no secret-dependent branch or index."),
    taint: Coverage(kind: ckExempt, rationale:
      "Plain field copy, no secret-dependent branch or index for the " &
      "taint harness to check either (RFC-005 slice 21) -- same " &
      "reasoning as stX25519ToBytesStatic's own rationale: the caller " &
      "already owns this secret, exporting it is not a sanctioned " &
      "publication boundary."),
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
    taint: Coverage(kind: ckDirect, name: "sha512"),
    disasm: Coverage(kind: ckDirect, name: "compress"),
    declassIds: @[diSha512DigestKat],
    note: "Not facade-exported (private/, sello is a 25519 library, not " &
      "a hash toolkit) -- curated because backend.derivePublic/" &
      "signDetached/challenge.challenge all call it on secret-derived " &
      "input. Taint (RFC-005 slice 21): promotes private/taint.nim's " &
      "own Stage-3 schema proof-spike draft to a live target -- " &
      "sha512/compress has DELIBERATELY NO interior declassify call " &
      "site (see sha512.sha512's own doc comment): it is reused for " &
      "genuinely secret-derivation hashing inside backend.derivePublic/ " &
      "signDetached (already exercised, undeclassified at THAT " &
      "internal level, by the \"sign\" target), so " &
      "tests/ct_taint/target_sha512.nim declassifies its own copy of " &
      "the digest at its own call site instead, across all three " &
      "one-shot overloads.",
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
    taint: Coverage(kind: ckDirect, name: "wipe_generic"),
    disasm: Coverage(kind: ckExempt, rationale:
      "Delegates to private/ct.wipe, itself not a {.noinline.} root " &
      "beyond the existing feCMove/feCSwap/cmovCached trio already " &
      "covered elsewhere."),
    declassIds: @[],
    note: "RFC-005 slice 21: tests/ct_taint/target_wipe_generic.nim -- " &
      "the simplest wipe target in this register, a plain caller-owned " &
      "array with no harness-side cast needed at all.",
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
