// roothide.c - Core RootHide Implementation for Dopamine
// Provides jailbreak hiding functionality including:
// - Path randomization (jbroot -> /private/preboot/UUID/jb_XXXX)
// - Selective injection (blacklist-based)
// - Clean environment propagation
// NOTE: RootHide does NOT use /var/jb - uses randomized jbroot path only

#include "roothide.h"
#include "libjailbreak.h"
#include "jbroot.h"
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <errno.h>

// ============ Global State ============
static struct {
        bool initialized;
        char jbroot_path[ROOTHIDE_JBROOT_PATH_MAX];       // Randomized jbroot path
        char random_suffix[ROOTHIDE_RANDOM_STRING_LENGTH]; // Random suffix for path
        char base_jbroot[PATH_MAX];                        // Original jbroot path
        
        // Blacklist for selective injection
        char blacklist[ROOTHIDE_MAX_BLACKLIST_ENTRIES][256];
        int blacklist_count;
        
        // Session identifier
        unsigned long long session_id;
        
        // Mutex for thread safety
        pthread_mutex_t mutex;
        
        // Preboot UUID for path construction
        char preboot_uuid[37];
} g_roothide = {
        .initialized = false,
        .jbroot_path = {0},
        .random_suffix = {0},
        .base_jbroot = {0},
        .blacklist = {{0}},
        .blacklist_count = 0,
        .session_id = 0,
        .mutex = PTHREAD_MUTEX_INITIALIZER,
        .preboot_uuid = {0}
};

// Thread-local cache for performance (avoids mutex contention in hot paths)
static __thread char tl_converted_path[PATH_MAX] = {0};
static __thread bool tl_cache_valid = false;
static __thread const char *tl_last_input = NULL;

// ============ Utility Functions ============

// Generate random alphanumeric string (safe, no reboot risk)
static void generate_random_string(char *buf, size_t len)
{
        if (!buf || len == 0) return;
        
        static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        static bool seeded = false;
        
        if (!seeded) {
                unsigned int seed = (unsigned int)(clock() ^ (uintptr_t)&seed ^ getpid());
                srandom(seed);
                seeded = true;
        }
        
        for (size_t i = 0; i < len - 1; i++) {
                buf[i] = charset[random() % (sizeof(charset) - 1)];
        }
        buf[len - 1] = '\0';
}

// Get preboot UUID from system (safe fallback)
static int get_preboot_uuid(char *uuid_out, size_t uuid_len)
{
        if (!uuid_out || uuid_len < 37) return -1;
        
        // Try to read from jbroot first
        const char *current_jbroot = get_jbroot();
        if (current_jbroot) {
                char uuid_path[PATH_MAX];
                snprintf(uuid_path, sizeof(uuid_path), "%s/.jbroot_uuid", current_jbroot);
                FILE *f = fopen(uuid_path, "r");
                if (f) {
                        if (fgets(uuid_out, (int)uuid_len, f)) {
                                // Strip newline
                                size_t slen = strlen(uuid_out);
                                if (slen > 0 && uuid_out[slen-1] == '\n') uuid_out[slen-1] = '\0';
                                fclose(f);
                                return 0;
                        }
                        fclose(f);
                }
        }
        
        // Fallback: use get_jbroot() and extract UUID from path
        const char *jbroot = get_jbroot();
        if (jbroot && strstr(jbroot, "/private/preboot/")) {
                // Extract UUID from path like /private/preboot/UUID/jb_XXXX
                const char *start = strstr(jbroot, "/private/preboot/");
                if (start) {
                        start += strlen("/private/preboot/");
                        const char *end = strchr(start, '/');
                        if (end && (size_t)(end - start) >= 36) {
                                strncpy(uuid_out, start, 36);
                                uuid_out[36] = '\0';
                                return 0;
                        }
                }
        }
        
        // Last resort: generate a fake but consistent UUID
        snprintf(uuid_out, uuid_len, "ROOTHIDE-%08X-0000-0000-0000-%012X",
                 (unsigned int)getpid(), (unsigned int)time(NULL));
        return 0;
}

// Safe string copy with bounds checking (anti-reboot)
static int safe_strlcpy(char *dst, const char *src, size_t dstsize)
{
        if (!dst || !src || dstsize == 0) return -1;
        strlcpy(dst, src, dstsize);
        return 0;
}

// ============ Path Management ============

/**
 * Get the REAL jbroot path used by the system (via jbinfo(rootPath)).
 * This is the path that actually exists on disk.
 *
 * NOTE: We intentionally do NOT randomize the jbroot path at runtime — randomizing it
 * would require creating a new directory + bind mount + symlink dance at jailbreak
 * time, which is a high-risk operation that can panic launchd during early boot.
 * Instead, the jbroot path returned by jbserver (set at jailbreak time by
 * DOBootstrapper) is already the path under /private/preboot/<UUID>/, which is
 * itself randomized across devices (the UUID is per-device/per-OS-restore).
 *
 * @return The actual jbroot path, or NULL on error
 */
const char* rothide_get_jbroot(void)
{
        if (!g_roothide.initialized) {
                roothide_init();
        }
        // Always return the REAL jbroot path (the one that actually exists on disk).
        // Previously this returned a fake /private/preboot/UUID/jb_<random> path
        // that did NOT exist on disk, which caused subtle bugs when callers tried
        // to actually access files under it.
        if (g_roothide.base_jbroot[0]) {
                return g_roothide.base_jbroot;
        }
        // Fallback: query libjailbreak directly
        const char *jbroot = get_jbroot();
        return jbroot;
}

bool roothide_is_blacklisted(const char* bundleID)
{
        if (!bundleID || !g_roothide.initialized) return false;
        
        // Fast path: check without lock (safe for reads)
        for (int i = 0; i < g_roothide.blacklist_count; i++) {
                if (strcmp(g_roothide.blacklist[i], bundleID) == 0) {
                        return true;
                }
        }
        return false;
}

int rothide_add_blacklist(const char* bundleID)
{
        if (!bundleID) return -1;
        
        pthread_mutex_lock(&g_roothide.mutex);
        
        // Check for duplicate
        for (int i = 0; i < g_roothide.blacklist_count; i++) {
                if (strcmp(g_roothide.blacklist[i], bundleID) == 0) {
                        pthread_mutex_unlock(&g_roothide.mutex);
                        return 0; // Already exists
                }
        }
        
        // Check capacity
        if (g_roothide.blacklist_count >= ROOTHIDE_MAX_BLACKLIST_ENTRIES) {
                pthread_mutex_unlock(&g_roothide.mutex);
                return -2; // Full
        }
        
        // Add new entry
        safe_strlcpy(g_roothide.blacklist[g_roothide.blacklist_count], bundleID, 256);
        g_roothide.blacklist_count++;
        
        pthread_mutex_unlock(&g_roothide.mutex);
        return 0;
}

int rothide_remove_blacklist(const char* bundleID)
{
        if (!bundleID) return -1;
        
        pthread_mutex_lock(&g_roothide.mutex);
        
        for (int i = 0; i < g_roothide.blacklist_count; i++) {
                if (strcmp(g_roothide.blacklist[i], bundleID) == 0) {
                        // Shift remaining entries down
                        for (int j = i; j < g_roothide.blacklist_count - 1; j++) {
                                safe_strlcpy(g_roothide.blacklist[j], 
                                           g_roothide.blacklist[j+1], 
                                           256);
                        }
                        memset(g_roothide.blacklist[g_roothide.blacklist_count - 1], 0, 256);
                        g_roothide.blacklist_count--;
                        pthread_mutex_unlock(&g_roothide.mutex);
                        return 0;
                }
        }
        
        pthread_mutex_unlock(&g_roothide.mutex);
        return -1; // Not found
}

unsigned long long jbrand(void)
{
        if (!g_roothide.initialized) {
                roothide_init();
        }
        return g_roothide.session_id;
}

// ============ Initialization ============

int roothide_init(void)
{
        pthread_mutex_lock(&g_roothide.mutex);
        
        if (g_roothide.initialized) {
                pthread_mutex_unlock(&g_roothide.mutex);
                return 0; // Already initialized
        }
        
        // Capture the REAL jbroot path (as reported by jbserver) — this is the path
        // that actually exists on disk.  Do NOT generate a fake random path here.
        const char *orig_jbroot = get_jbroot();
        if (!orig_jbroot) {
                // Fallback to /private/preboot (RootHide: do NOT use /var/jb)
                orig_jbroot = "/private/preboot";
        }
        safe_strlcpy(g_roothide.base_jbroot, orig_jbroot, sizeof(g_roothide.base_jbroot));
        
        // Mirror the path into jbroot_path for backwards compat with code that
        // inspects g_roothide.jbroot_path.  Both are the REAL path now.
        safe_strlcpy(g_roothide.jbroot_path, g_roothide.base_jbroot, sizeof(g_roothide.jbroot_path));
        
        // Get preboot UUID (informational only, used by rothide_get_jbroot()
        // in case get_jbroot() ever fails)
        get_preboot_uuid(g_roothide.preboot_uuid, sizeof(g_roothide.preboot_uuid));
        
        // Generate session identifier (per-process, used for diagnostics)
        g_roothide.session_id = ((unsigned long long)time(NULL) << 32) | 
                                ((unsigned long long)getpid() & 0xFFFFFFFF);
        
        // Load default blacklist (banking apps, detection apps, etc.)
        // These apps should NEVER receive jailbreak injection
        const char *default_blacklist[] = {
                // Banking apps (Vietnam + International)
                "com.vietinbank.iBank",
                "com.vcb.IB",
                "com.techcombank.business",
                "com.mbmobile",
                "com.timb.VCBMobileBanking",
                "com.acb.ACBMobile",
                "com.vib.VIBMobileBanking",
                "com.babk.BABMobileBanking",
                "com.vietcombank.MobileBanking",
                "com.agribank.DigiBank",
                "com.oceanbank.OzeMobile",
                "com.pvcombank.MobileBanking",
                "com.saigonthonhin.SHBMobile",
                "com.lienvietpost.LVPBank",
                "vnpay.NapAsVnPay",
                
                // Security/Detection apps
                "com.apple.dt.Xcode",              // Xcode (debugger detection)
                "com.bugsnag.Bugsnag",             // Crash reporting with JB detection
                "io.fabric.sdk.ios",               // Fabric/Crashlytics
                "com.microsoft.IntuneMAM",         // MDM
                "com.vmware.horizon",
                
                // Game anti-cheat
                "com.tencent.ig",
                "com.miHoYo.GenshinImpact",
                "com.digitalegends.BESTARZ",
        };
        
        size_t default_count = sizeof(default_blacklist) / sizeof(default_blacklist[0]);
        for (size_t i = 0; i < default_count && g_roothide.blacklist_count < ROOTHIDE_MAX_BLACKLIST_ENTRIES; i++) {
                safe_strlcpy(g_roothide.blacklist[g_roothide.blacklist_count], 
                            default_blacklist[i], 
                            256);
                g_roothide.blacklist_count++;
        }
        
        g_roothide.initialized = true;
        pthread_mutex_unlock(&g_roothide.mutex);
        
        return 0;
}

// ============ Path Conversion ============

/**
 * Convert a standard jailbreak path: if `path` starts with the current jbroot,
 * return `path` unchanged (the on-disk path is the same for all callers — we
 * do NOT use per-process path randomization, that caused files to be looked
 * up under non-existent paths and would break tweaks).
 *
 * Renamed from `jbroot()` to `roothide_sanitize_path_v2()` to avoid a name
 * collision with `jbroot.c::get_jbroot()` which has a different signature
 * (no args) and a different meaning ("return the jbroot path itself").
 */
const char* roothide_sanitize_path_v2(const char* path)
{
        if (!path) return NULL;
        
        if (!g_roothide.initialized) {
                roothide_init();
        }
        
        // Use thread-local cache for performance (same input -> same output)
        if (tl_cache_valid && tl_last_input == path) {
                return tl_converted_path;
        }
        
        // No conversion is ever needed — jbroot path is the same on-disk path
        // for every process.  We just return the input as-is.
        tl_last_input = path;
        tl_cache_valid = true;
        return path;
}

int rothide_convert_path(const char* input, char* output, size_t outsize)
{
        if (!input || !output || outsize == 0) return -1;
        
        // No transformation needed — on-disk path is the same for all callers.
        safe_strlcpy(output, input, outsize);
        return 0;
}

// Check if current process should run in clean mode (no jailbreak traces)
bool rothide_should_be_clean(const char* executable_path, const char* bundle_id)
{
        if (!g_roothide.initialized) {
                return false;
        }
        
        // Check by bundle ID
        if (bundle_id && roothide_is_blacklisted(bundle_id)) {
                return true;
        }
        
        // Check environment variable (propagated from parent)
        if (getenv(ROOTHIDE_CLEAN_MODE_ENV)) {
                const char *val = getenv(ROOTHIDE_CLEAN_MODE_ENV);
                if (val && strcmp(val, "1") == 0) {
                        return true;
                }
        }
        
        return false;
}

// Get blacklist count (for debugging/UI)
int rothide_get_blacklist_count(void)
{
        return g_roothide.blacklist_count;
}

// Get blacklist entry at index (for UI display)
const char* rothide_get_blacklist_entry(int index)
{
        if (index < 0 || index >= g_roothide.blacklist_count) return NULL;
        return g_roothide.blacklist[index];
}
