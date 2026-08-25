// roothide_compat_stubs.c
//
// RootHide port (Relaxin upstream): stubs for functions referenced by Relaxin's
// roothide code that are not yet implemented in Kernel-JB. These return error
// codes or safe defaults so the build links cleanly; a future commit will
// replace each stub with a real implementation ported from Relaxin.
//
// The functions here are:
//   - system_info_uses_sptm()        — checks whether the kernel uses SPTM
//                                       (Kernel-JB has its own detection; stub
//                                       defers to a simple check)
//   - jbclient_platform_trustcache_*  — Relaxin's new trustcache XPC API
//                                       (Kernel-JB has jbclient_root_trustcache_*
//                                       with different signatures)
//   - jbclient_root_trustcache_append_entries — Relaxin variant
//   - jb_trustcache_append_entries    — Relaxin variant
//   - trustcache_query_cdhash         — Relaxin variant
//   - csd_superblob_is_adhoc_signed  — Relaxin signature helper
//   - macho_calculate_adhoc_cdhash   — Relaxin macho helper
//   - rlx_ksymbol                     — Relaxin symbol resolver
//
// When the corresponding Relaxin source files are ported (signatures.c, the
// trustcache_nokcall subsystem, etc.), these stubs should be removed.

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "info.h"
#include "primitives.h"
#include "trustcache.h"
#include "jbserver_domains.h"   // for JBS_TRUSTCACHE_HASH_SIZE
#include "jbclient_xpc.h"       // for jbclient_root_trustcache_add_cdhash
#include "roothide_compat_stubs.h"  // self-declarations

// Stub: Relaxin's system_info_uses_sptm() — checks SPTM presence.
// Kernel-JB has SPTM detection via gSystemInfo.kernelConstant.sptmBase != 0;
// we reuse that.
bool system_info_uses_sptm(void) {
    return gSystemInfo.kernelConstant.sptmBase != 0;
}

// Stub: Relaxin's jbclient_platform_trustcache_query_cdhash.
// Returns "not found" until the real impl is ported.
int jbclient_platform_trustcache_query_cdhash(const uint8_t cdhash[JBS_TRUSTCACHE_HASH_SIZE], bool *foundOut) {
    if (foundOut) *foundOut = false;
    return -1;
}

// Stub: Relaxin's jbclient_platform_trustcache_owner_probe.
// Returns "not available" until the real impl is ported.
int jbclient_platform_trustcache_owner_probe(bool *availableOut, int *ownerStatusOut) {
    if (availableOut) *availableOut = false;
    if (ownerStatusOut) *ownerStatusOut = 0;
    return -1;
}

// Stub: Relaxin's jbclient_root_trustcache_append_entries.
// Falls back to the per-hash add_cdhash variant that Kernel-JB already has.
int jbclient_root_trustcache_append_entries(const void *entries, uint32_t entryCount) {
    if (!entries || entryCount == 0) return -1;
    // Best-effort fallback: iterate and add each cdhash via Kernel-JB's existing
    // jbclient_root_trustcache_add_cdhash API. Real impl will use the new append
    // XPC action when ported.
    const cdhash_t *hashes = (const cdhash_t *)entries;
    for (uint32_t i = 0; i < entryCount; i++) {
        int r = jbclient_root_trustcache_add_cdhash((uint8_t *)(hashes + i), JBS_TRUSTCACHE_HASH_SIZE);
        if (r != 0) return r;
    }
    return 0;
}

// Stub: Relaxin's jb_trustcache_append_entries (libjailbreak-side wrapper).
// Falls back to jb_trustcache_add_cdhashes (which Kernel-JB has).
int jb_trustcache_append_entries(const void *entries, uint32_t entryCount) {
    if (!entries || entryCount == 0) return -1;
    return jb_trustcache_add_cdhashes((cdhash_t *)entries, entryCount);
}

// Alias: Relaxin names this jb_trustcache_append_cdhashes; Kernel-JB has
// jb_trustcache_add_cdhashes. Dispatch to the Kernel-JB variant.
int jb_trustcache_append_cdhashes(cdhash_t *hashes, uint32_t hashCount) {
    return jb_trustcache_add_cdhashes(hashes, hashCount);
}

// Stub: Relaxin's trustcache_query_cdhash.
// Falls back to jbclient_platform_trustcache_query_cdhash (stubbed above).
int trustcache_query_cdhash(const uint8_t hash[JBS_TRUSTCACHE_HASH_SIZE], bool *foundOut) {
    return jbclient_platform_trustcache_query_cdhash(hash, foundOut);
}

// Stub: Relaxin's macho_calculate_adhoc_cdhash (from roothider/signatures.m).
// Called with 2 args (MachO *, cdhash_t which is uint8_t[20]). Returns false
// (failure) until the real impl is ported. Callers should fall back to
// Kernel-JB's existing cdhash calculation helpers.
//
// NOTE: csd_superblob_is_adhoc_signed is NOT stubbed here because Kernel-JB
// already has a native implementation in signatures.c (line 60) with the
// matching Relaxin signature `bool csd_superblob_is_adhoc_signed(CS_DecodedSuperBlob *)`.
// We just need a forward declaration in signatures.h — added there separately.
bool macho_calculate_adhoc_cdhash(void *macho, uint8_t *cdhashOut) {
    (void)macho;
    if (cdhashOut) {
        for (int i = 0; i < 20; i++) cdhashOut[i] = 0;
    }
    return false;
}

// Stub: Relaxin's rlx_ksymbol (used by trustcache_nokcall_kernel.c).
// Returns 0 (not found) until the real symbol resolver is ported.
uint64_t rlx_ksymbol(const char *name) {
    (void)name;
    return 0;
}

// Stub: Relaxin's trustcache_nokcall_is_required (from trustcache_nokcall.c,
// which was removed because its implementation depends on Relaxin's
// evolved primitives.h struct layout). Returns false so callers take the
// existing kcall-based trustcache path.
bool trustcache_nokcall_is_required(void) {
    return false;
}

// Stub: Relaxin's trustcache_nokcall_bootstrap_append_entries.
// Returns -1 (failure). PID 1 should fall back to the kcall-based
// jb_trustcache_append_entries helper.
int trustcache_nokcall_bootstrap_append_entries(const void *entries, uint32_t entryCount) {
    (void)entries; (void)entryCount;
    return -1;
}

// Stub: protected kwrite32 — uses regular kwrite32 if available.
int protectedKwrite32_stub(uint64_t kaddr, uint32_t value) {
    // Kernel-JB doesn't have a separate "protected kwrite" path yet;
    // we fall back to the regular kwrite32 helper.
    extern int kwrite32(uint64_t va, uint32_t v);
    return kwrite32(kaddr, value);
}

// Stub: kvtophys — uses gPrimitives.vtophys if available.
uint64_t kvtophys_stub(uint64_t va) {
    if (gPrimitives.kvtophys) {
        return gPrimitives.kvtophys(va);
    }
    if (gPrimitives.vtophys) {
        return gPrimitives.vtophys(gSystemInfo.kernelConstant.cpuTTEP, va);
    }
    return 0;
}

// Stub: kaccess_mapped — uses gPrimitives.kaccess_mapped if available,
// else returns -1.
int kaccess_mapped_stub(uint64_t va, uint64_t size, void (^accessorBlock)(void *)) {
    if (gPrimitives.kaccess_mapped) {
        // Note: kernel_map_accessor is `void (^)(void *)` in Kernel-JB and Relaxin
        return gPrimitives.kaccess_mapped(va, size, accessorBlock);
    }
    return -1;
}

// Stub: kreadbuf_protected / kwritebuf_protected — fall back to unprotected
// variants until the protected-kwrite primitive is ported from Relaxin.
int kreadbuf_protected(uint64_t kaddr, void *output, size_t size) {
    return kreadbuf(kaddr, output, size);
}

int kwritebuf_protected(uint64_t kaddr, const void *input, size_t size) {
    return kwritebuf(kaddr, input, size);
}
