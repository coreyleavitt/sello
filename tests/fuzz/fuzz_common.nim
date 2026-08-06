## Shared strategies, oracle wrappers, and the run/report loop for sello's
## coverage-guided fuzz harness (RFC-001 review finding 12). Imported by
## `fuzz_main.nim`; not a test itself, mirroring `tests/ct/dudect.nim`'s role
## as the engine behind `tests/ct/ct_main.nim`.
##
## SCOPE -- attacker-controlled-input surface ONLY. The three targets below
## (pointDecode, verify, x25519's peer public u-coordinate) are exactly the
## boundary where sello parses bytes nobody had to prove well-formed before
## handing them to us. Deliberately NOT fuzzed: `backend.signDetached` and
## `scalar.geScalarmultBase` -- those hold the secret scalar and are
## branchless BY DESIGN (constant-time discipline, CLAUDE.md's verify/sign
## split); their risk is a TIMING side channel on secret data, which a
## mutation fuzzer cannot observe or usefully stress, and which
## `tests/ct/`'s dudect harness already owns. Feeding fuzzer-chosen bytes
## into a signing function would also misuse it -- CLAUDE.md is explicit
## that verify-side code has no CT requirement and signing-side code must
## never be exercised as if it were public-input-safe.
##
## Coverage-guidance scope note: proptest's `{.cover.}` pragma is
## source-level instrumentation (it rewrites the annotated proc's own AST).
## To keep sello's audited crypto modules (ed25519.nim/scalar.nim/x25519.nim)
## completely unmodified by this batch, `{.cover.}` is applied ONLY to this
## file's thin oracle wrappers below, never to pointDecode/verify/x25519
## themselves. The coverage signal steering proptest's mutator is therefore
## "which outcome branch did the wrapper take" (decode ok/reject, verify
## accept/reject, x25519 some/none) -- real coverage-guided admission (the
## corpus grows toward inputs that flip these outcomes), just at coarser
## granularity than instrumenting the SUT's internals would give. This is a
## deliberate, documented trade-off against touching already-reviewed
## crypto source, not an oversight.
##
## Oracle (what counts as a finding): `fuzzWith` maps any uncaught
## exception/Defect from the wrapper (RangeDefect, IndexDefect, an
## AssertionDefect from a `doAssert` below, ...) to a retained crash --
## that is the "no crash/panic/RangeDefect on any input" invariant the
## mission asks for. Two cheap, genuinely-free self-consistency checks ride
## along as `doAssert`s (so a violation is ALSO a finding, not a silent
## pass):
##   - pointDecode success implies the decoded point's canonical
##     re-encoding is itself canonical (`pointEncode` . `pointDecode`
##     round-trips into `feBytesCanonical` territory).
##   - x25519 returning `some` implies the shared secret is not all-zero
##     (all-zero is reserved for the documented small-order-peer rejection,
##     which returns `none`).
## "verify never accepts a signature that trivially differs from a valid
## one" is NOT checked here -- unstructured mutation essentially never
## produces a valid signature to perturb in the first place. That ground is
## already covered by `tests/unit/test_properties_signing.nim`'s structured
## single-bit-flip properties (B4a), which start from a real signature.
import std/[options, times]
import proptest
import sello/ed25519
import sello/scalar
import sello/field
import sello/x25519

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

proc randByte*(): Strategy[byte] =
  integers(0, 255).map(proc(x: int): byte = byte(x))

proc bytes32*(): Strategy[array[32, byte]] =
  arrays[32, byte](randByte())

proc bytes64*(): Strategy[array[64, byte]] =
  arrays[64, byte](randByte())

type
  VerifyInput* = object
    sig*: array[64, byte]
    msg*: seq[byte]
    pk*: array[32, byte]

proc verifyInputs*(): Strategy[VerifyInput] =
  ## Composite strategy over sig || msg || pk -- everything `verify` reads.
  ## `newStrategy` is proptest's documented escape hatch for a strategy over
  ## a type its combinators don't build directly (no built-in tuple/record
  ## zip combinator; see strategy.nim's `newStrategy` doc comment).
  let sigS = bytes64()
  let msgS = bytes(0, 512)
  let pkS = bytes32()
  newStrategy[VerifyInput](proc(src: var DataSource): VerifyInput =
    VerifyInput(sig: sigS.run(src), msg: msgS.run(src), pk: pkS.run(src)))

# ---------------------------------------------------------------------------
# Oracle wrappers ({.cover.} lives here, not in sello's own source -- see
# the module doc comment above)
# ---------------------------------------------------------------------------

proc coveredPointDecode*(bytes: array[32, byte]) {.cover.} =
  let r = pointDecode(bytes)
  if r.isSome:
    let p = r.get()
    let reenc = pointEncode(p)
    doAssert feBytesCanonical(reenc),
      "pointDecode accepted an input whose canonical re-encode isn't canonical"
  else:
    discard

proc coveredVerify*(inp: VerifyInput) {.cover.} =
  let ok = verify(toSignature(inp.sig), inp.msg, toPublicKey(inp.pk))
  if ok:
    # A mutation-found "valid" signature over unstructured input would
    # itself be an extraordinary finding (a forgery) -- fuzzWith already
    # retains it as a crash if it ever raises, but acceptance itself
    # doesn't raise, so this branch exists purely to give {.cover.} an
    # edge to record (see the module doc's coverage-granularity note) and
    # as a landing spot if a future maintainer wants to add a check here.
    discard
  else:
    discard

let localSecretForFuzzing = toX25519StaticSecret([
  1'u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
  17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32])
  ## Fixed, non-secret placeholder scalar (RFC-001 ledger #29 revisited:
  ## `X25519Key` replaced by role-typed `X25519StaticSecret`/`X25519Public`/
  ## `X25519Shared`). The fuzz target is the PEER's public u-coordinate
  ## only -- the attacker-controlled surface named in the mission -- so
  ## the local scalar is a constant unstructured mutation never touches.
  ## This is not a timing-sensitive use (no measurement is taken here;
  ## dudect owns that), so a fixed non-random value is fine. `let`, not
  ## `const`: `X25519StaticSecret` carries a `=destroy` hook, which a compile-time
  ## `const` cannot (no destructor evaluation in the VM).

proc coveredX25519*(peerPublic: array[32, byte]) {.cover.} =
  let r = x25519(localSecretForFuzzing, toX25519Public(peerPublic))
  if r.isSome:
    let shared = toBytes(r.get())
    var acc: byte = 0
    for b in shared: acc = acc or b
    doAssert acc != 0'u8,
      "x25519 returned Some(...) with an all-zero shared secret"
  else:
    discard

# ---------------------------------------------------------------------------
# Run + report
# ---------------------------------------------------------------------------

proc runTarget*[T](name: string; strat: Strategy[T]; prop: proc(x: T);
                    seconds: int; seedVal: uint64) =
  echo "=== fuzzing ", name, " (", seconds, "s budget, IR mutation mode) ==="
  var settings = FuzzSettings(
    timeBudget: initDuration(seconds = seconds),
    seed: seedVal,
    mutationMode: fmIR)
  let report = fuzzWith(strat, prop, settings)
  let corpusSize = case report.corpus.kind
                   of fckIR: report.corpus.irEntries.len
                   of fckBytes: report.corpus.byteEntries.len
  echo "  iterations:        ", report.iterations
  echo "  coverage edges hit: ", report.coverageHits
  echo "  corpus size:        ", corpusSize
  echo "  crashes found:      ", report.irCrashes.len
  echo "  time budget hit:    ", report.timedOut
  if report.irCrashes.len > 0:
    echo "  !!! CRASH FOUND in ", name, " !!!"
    for i, c in report.irCrashes:
      echo "    [", i, "] ", c.message
    quit(1)
