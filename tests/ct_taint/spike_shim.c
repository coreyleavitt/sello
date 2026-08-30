/* tests/ct_taint/spike_shim.c -- Stage 1 go/no-go spike shim (RFC-005
 * slice 19, A1). Deliberately separate from the production
 * src/sello/private/taint_shim.c built in Stage 2: this file exists only
 * to answer the go/no-go question ("can Valgrind memcheck, driven via
 * client-request macros reached from a tiny C shim, produce zero errors
 * on a masked-select chain and exactly one resolvable error class on a
 * planted secret-conditioned branch") before any register/DeclassId
 * machinery is built. Compiled only by this spike's own toy binaries
 * (tests/ct_taint/spike_clean.nim, spike_leaky.nim) -- never part of the
 * production build, no {.compile.} reference from src/.
 *
 * By-address contract (pointer + len), matching the BoringSSL
 * CONSTTIME_DECLASSIFY construction recorded in the RFC: client requests
 * operate on addressable memory, so these wrap the memory directly rather
 * than taking a value.
 */
#include <valgrind/memcheck.h>
#include <stddef.h>

void spike_taint_undefined(void *p, size_t len) {
  VALGRIND_MAKE_MEM_UNDEFINED(p, len);
}

void spike_taint_defined(void *p, size_t len) {
  VALGRIND_MAKE_MEM_DEFINED(p, len);
}
