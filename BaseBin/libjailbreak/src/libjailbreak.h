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

// ============ RootHide API ============
// These functions provide RootHide-style jailbreak hiding functionality
// They allow selective injection and path randomization

#ifdef __cplusplus
extern "C" {
#endif

// Path conversion functions for RootHide mode
// NOTE: previously `jbroot(path)` and `rootfs(path)` were declared here. They
// were renamed to `roothide_sanitize_path_v2()` to avoid a name collision with
// `jbroot.c::get_jbroot()` (no args, different meaning). The on-disk jbroot
// path is the same for every process (set at jailbreak time by DOBootstrapper),
// so the function is effectively a no-op.
const char* roothide_sanitize_path_v2(const char* path);
unsigned long long jbrand(void);       // Returns unique jailbreak session identifier

// RootHide initialization and management
int roothide_init(void);                          // Initialize RootHide subsystem
int rothide_add_blacklist(const char* bundleID);  // Add app to blacklist (no injection)
int rothide_remove_blacklist(const char* bundleID); // Remove app from blacklist
bool roothide_is_blacklisted(const char* bundleID); // Check if app is blacklisted
const char* roothide_get_jbroot(void);            // Get current randomized jbroot path
int rothide_convert_path(const char* input, char* output, size_t outsize); // Convert path with redirect

// Environment helpers for clean mode propagation
#define ROOTHIDE_CLEAN_MODE_ENV "ROOTHIDE_CLEAN_MODE"
#define ROOTHIDE_JBROOT_ENV     "JBROOT"
#define ROOTHIDE_MODE_ENV       "ROOTHIDE_MODE"

// Maximum sizes for RootHide internals
#define ROOTHIDE_MAX_BLACKLIST_ENTRIES 256
#define ROOTHIDE_RANDOM_STRING_LENGTH  16
#define ROOTHIDE_JBROOT_PATH_MAX       PATH_MAX

#ifdef __cplusplus
}
#endif