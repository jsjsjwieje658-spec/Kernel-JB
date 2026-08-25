#include "primitives.h"
#include "info.h"
#include "kernel.h"
#include "util.h"
#include "translation.h"
#include "trustcache.h"
#include "jbclient_xpc.h"
#include "stock_fixes.h"

int jbclient_initialize_primitives_internal(bool physrwPTE);
int jbclient_initialize_primitives(void);

// ============ RootHide (Relaxin upstream fork) ============
// The full RootHide runtime is implemented under BaseBin/libjailbreak/src/roothider/
// (ported from Relaxin's Vendor/Dopamine/BaseBin/libjailbreak/src/roothider/).
// The canonical public API lives in BaseBin/_external/include/roothide.h:
//   - jbroot(path)        — prefix path with the current jbroot
//   - rootfs(path)         — prefix path with /
//   - jbrand()             — 64-bit jailbreak session identifier
//   - jbroot_alloc/rootfs_alloc/jbrootat_alloc — caller-frees variants
// These symbols are provided at runtime by libroothide.dylib (shipped with the
// RootHide bootstrap tarball). At link time, basebin/_external/lib/libroothide.tbd
// supplies the symbol declarations.
//
// The XPC client API for the JBS_DOMAIN_ROOTHIDE handler is declared in
// jbclient_xpc.h (the section labeled "ROOTHIDE SPECIFIC"). Implementations
// live in jbclient_roothide.c (also ported from Relaxin).

#ifdef __cplusplus
extern "C" {
#endif

// Environment helpers for clean-mode propagation (Kernel-JB-specific).
// These env vars are read by systemhook/main.c and dyldhook/main.c to decide
// whether to skip tweak injection for a child process. The Relaxin upstream
// uses a different propagation mechanism (roothidehooks.dylib per-process hooks),
// but these env vars are still respected for backward compatibility with the
// existing Kernel-JB Application-side bootstrap logic in DOBootstrapper.m.
#define ROOTHIDE_CLEAN_MODE_ENV "ROOTHIDE_CLEAN_MODE"
#define ROOTHIDE_JBROOT_ENV     "JBROOT"
#define ROOTHIDE_MODE_ENV       "ROOTHIDE_MODE"

// Maximum sizes for RootHide internals (Kernel-JB-specific).
#define ROOTHIDE_MAX_BLACKLIST_ENTRIES 256
#define ROOTHIDE_RANDOM_STRING_LENGTH  16
#define ROOTHIDE_JBROOT_PATH_MAX       PATH_MAX

#ifdef __cplusplus
}
#endif
