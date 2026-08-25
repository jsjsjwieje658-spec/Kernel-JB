// trustcache_nokcall.h
//
// RootHide port (Relaxin upstream): minimal forward declarations for the
// no-kcall trustcache subsystem. The full Relaxin implementation
// (trustcache_nokcall.c, trustcache_nokcall_controller.c, trustcache_nokcall_kernel.c,
// trustcache_nokcall_word32.c, trustcache_nokcall_model.c, trustcache_nokcall_owner.c)
// has been removed from Kernel-JB because it depends on Relaxin's evolved
// primitives.h struct layout (gPrimitives.kvtophys, gPrimitives.protectedKwrite32)
// and helper functions (rlx_ksymbol, etc.) that Kernel-JB doesn't have.
//
// The functions below are stubbed in roothide_compat_stubs.c — they return
// safe defaults so callers (e.g. roothider/common.m) take the existing
// kcall-based trustcache path. A future commit will port the real
// implementations from Relaxin once the primitives.h struct layout has been
// merged.
#ifndef TRUSTCACHE_NOKCALL_H
#define TRUSTCACHE_NOKCALL_H

#include <stdbool.h>
#include <stdint.h>

#include "trustcache_structs.h"

#ifdef __cplusplus
extern "C" {
#endif

// Stub: returns false (no-kcall path NOT required) so callers take the
// existing kcall-based trustcache path. Real impl checks SPTM/PPL state.
bool trustcache_nokcall_is_required(void);

// Stub: returns -1 (failure). PID 1 should fall back to the kcall-based
// jb_trustcache_append_entries helper.
int trustcache_nokcall_bootstrap_append_entries(const trustcache_entry_v1 *entries, uint32_t entryCount);

#ifdef __cplusplus
}
#endif

#endif
