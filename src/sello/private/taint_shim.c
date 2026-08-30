/* src/sello/private/taint_shim.c -- the taint CT harness's confined FFI
 * exception (RFC-005 slice 19, A1). Compiled ONLY under `-d:selloTaint`
 * (see taint.nim's conditional `{.compile.}`) -- never part of a
 * consumer's ordinary build, which sees `declassify` expand to nothing at
 * all (see taint.nim's own module doc for the codegen-unchanged proof).
 *
 * Deliberately separate from tests/ct_taint/spike_shim.c (the Stage-1
 * go/no-go spike's own throwaway shim): this is the production TU the
 * real `declassify` calls route through, with a per-id exercise counter
 * the harness asserts against (the register-completeness check A1's own
 * text describes) and the deliberate link-error-outside-the-harness
 * mechanism below. It also carries the by-address MAKE_MEM_UNDEFINED /
 * MAKE_MEM_DEFINED / CHECK_MEM_IS_DEFINED wrappers `tests/ct_taint/`'s
 * own harness code uses directly (taint.nim's harness-only
 * `markUndefined`/`markDefined`/`checkDefined` wrappers, below) -- one
 * shim TU for both the production declassification path and the
 * harness's own tainting/assertion needs, rather than a second,
 * duplicated valgrind-macro-wrapping C file.
 *
 * By-address contract (pointer + len), matching the BoringSSL
 * CONSTTIME_DECLASSIFY construction the RFC records: client requests
 * operate on addressable memory, so `sello_taint_declassify` wraps the
 * memory directly rather than taking a value -- a verdict word spilled to
 * the stack by this call's own clobber semantics is exactly what makes a
 * subsequent plain read of it defined again.
 *
 * SELLO_TAINT_ID_COUNT is supplied by taint.nim's own `{.passC.}` pragma,
 * computed from `ord(high(DeclassId)) + 1` at Nim compile time -- so the
 * counter array is always exactly sized to the live enum, never a
 * generously-guessed constant that could silently under-size after a
 * register grows.
 *
 * Deliberate link-error-outside-the-harness mechanism (A1's own text:
 * "building the core with -d:selloTaint outside the harness must be a
 * link error by design"): the real function BODIES below are gated on
 * SELLO_TAINT_HARNESS_ACTIVE, a second, narrower macro that ONLY
 * scripts/ct-taint.sh passes (via `--passC:"-DSELLO_TAINT_HARNESS_ACTIVE"`)
 * -- `-d:selloTaint` alone (e.g. a consumer accidentally setting it, or
 * building this TU from some other harness) compiles this file fine
 * (the declarations exist) but leaves both functions BODYLESS, so any
 * real call site fails at the final link step with "undefined reference"
 * -- a deliberate, legible failure mode instead of a silent no-op or a
 * confusing missing-header compile error two layers removed from the
 * actual cause.
 */
#include <stddef.h>

#ifdef SELLO_TAINT_HARNESS_ACTIVE
#include <valgrind/memcheck.h>

static int sello_taint_exercise_counters[SELLO_TAINT_ID_COUNT];

void sello_taint_declassify(int id, void *p, size_t len) {
  VALGRIND_MAKE_MEM_DEFINED(p, len);
  if (id >= 0 && id < SELLO_TAINT_ID_COUNT) {
    sello_taint_exercise_counters[id]++;
  }
}

int sello_taint_exercise_count(int id) {
  if (id < 0 || id >= SELLO_TAINT_ID_COUNT) {
    return -1;
  }
  return sello_taint_exercise_counters[id];
}

/* Harness-only primitives (RFC-005 slice 19, A1 -- tests/ct_taint/'s own
 * use via taint.nim's harness-side wrappers, never called from src/
 * secret-handling code): UNCOUNTED, not gated by a registered DeclassId
 * -- these operate on the HARNESS'S OWN copies of data, either tainting
 * an input before it ever enters the library (mark_undefined) or
 * asserting/forcing definedness on the harness side (check_defined,
 * mark_defined), never on a disclosure INTERIOR to library code (that is
 * `sello_taint_declassify`'s job, above, and it alone is what the A1
 * register/exercise-counter machinery is checked against). `mark_defined`
 * in particular is the boundary-rule idiom for a secret OUTPUT
 * (X25519Shared/RistrettoShared): the harness's own KAT comparison needs
 * the bytes defined to compare, but disclosing a secret DH/scalarmult
 * result is never sanctioned, so this deliberately bypasses the
 * id/register/counter machinery entirely rather than routing through
 * `sello_taint_declassify` under a borrowed id.
 */
void sello_taint_mark_undefined(void *p, size_t len) {
  VALGRIND_MAKE_MEM_UNDEFINED(p, len);
}

void sello_taint_mark_defined(void *p, size_t len) {
  VALGRIND_MAKE_MEM_DEFINED(p, len);
}

void sello_taint_check_defined(const void *p, size_t len) {
  VALGRIND_CHECK_MEM_IS_DEFINED(p, len);
}
#endif /* SELLO_TAINT_HARNESS_ACTIVE */
