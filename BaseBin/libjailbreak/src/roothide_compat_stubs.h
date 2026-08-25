// roothide_compat_stubs.h
//
// RootHide port (Relaxin upstream): forward declarations for the stub
// implementations in roothide_compat_stubs.c. These functions are referenced
// by the Relaxin roothide code (roothider/common.m, recdhash.m, signatures.m,
// jbdomain_roothide.c, etc.) but are not yet implemented natively in
// Kernel-JB. The stubs return error codes or safe defaults so the build
// links cleanly; a future commit will replace each with a real implementation
// ported from Relaxin.
#ifndef ROOTHIDE_COMPAT_STUBS_H
#define ROOTHIDE_COMPAT_STUBS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "jbserver_domains.h"  // for JBS_TRUSTCACHE_HASH_SIZE
#include "trustcache.h"        // for cdhash_t

#ifdef __cplusplus
extern "C" {
#endif

// Stub: checks whether the running kernel uses SPTM (System Page Table Monitor).
// Defers to gSystemInfo.kernelConstant.sptmBase != 0.
bool system_info_uses_sptm(void);

// Stub: Relaxin's XPC API for querying cdhash presence in the runtime trustcache.
// Returns -1 and *foundOut=false until the real impl is ported.
int jbclient_platform_trustcache_query_cdhash(const uint8_t cdhash[JBS_TRUSTCACHE_HASH_SIZE], bool *foundOut);

// Stub: Relaxin's XPC API for probing the trustcache owner status.
// Returns -1 and *availableOut=false until the real impl is ported.
int jbclient_platform_trustcache_owner_probe(bool *availableOut, int *ownerStatusOut);

// Stub: Relaxin's XPC API for appending trustcache entries in batch.
// Falls back to iterating and calling jbclient_root_trustcache_add_cdhash per hash.
int jbclient_root_trustcache_append_entries(const void *entries, uint32_t entryCount);

// Stub: libjailbreak-side wrapper for batch trustcache append.
// Falls back to jb_trustcache_add_cdhashes.
int jb_trustcache_append_entries(const void *entries, uint32_t entryCount);

// Alias: Relaxin names this function jb_trustcache_append_cdhashes (different
// from Kernel-JB's jb_trustcache_add_cdhashes). This alias dispatches to the
// Kernel-JB variant.
int jb_trustcache_append_cdhashes(cdhash_t *hashes, uint32_t hashCount);

// Stub: query cdhash presence via the libjailbreak-side wrapper.
int trustcache_query_cdhash(const uint8_t hash[JBS_TRUSTCACHE_HASH_SIZE], bool *foundOut);

// Stub: Relaxin's macho cdhash calculator (from roothider/signatures.m).
// Called with 2 args (MachO *, cdhash_t which is uint8_t[20]). Returns false
// (failure) until the real impl is ported. Argument type is `void *` here to
// avoid pulling in ChOma headers; the actual call site passes MachO * which
// is link-compatible.
//
// NOTE: csd_superblob_is_adhoc_signed is NOT stubbed here because Kernel-JB
// already has a native implementation in signatures.c with the matching
// Relaxin signature. The forward declaration is below (using void * to avoid
// pulling in ChOma headers; the actual call site passes CS_DecodedSuperBlob *
// which is link-compatible).
bool csd_superblob_is_adhoc_signed(void *superblob);
bool macho_calculate_adhoc_cdhash(void *macho, uint8_t *cdhashOut);

// Stub: Relaxin's kernel symbol resolver.
// Returns 0 (not found) until the real impl is ported.
uint64_t rlx_ksymbol(const char *name);

#ifdef __cplusplus
}
#endif

#endif
