// roothide.c - Core RootHide Implementation for Dopamine
// Provides jailbreak hiding functionality including:
// - Path randomization (/var/jb -> /private/preboot/UUID/jb_XXXX)
// - Selective injection (blacklist-based)
// - Clean environment propagation

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
        char base_jbroot[PATH_MAX];                        // Original /var/jb path
        
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
        
        // Try to read from /var/jb first (standard rootless location)
        FILE *f = fopen("/var/jb/.jbroot_uuid", "r");
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
        
        // Fallback: use get_jbroot() and extract UUID from path
        const char *jbroot = get_jbroot();
        if (jbroot && strstr(jbroot, "/private/preboot/")) {
                // Extract UUID from path like /private/preboot/UUID/var/jb
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

// ============ Public API Implementation ============

int roothide_init(void)
{
        pthread_mutex_lock(&g_roothide.mutex);
        
        if (g_roothide.initialized) {
                pthread_mutex_unlock(&g_roothide.mutex);
                return 0; // Already initialized
        }
        
        // Get original jbroot path
        const char *orig_jbroot = get_jbroot();
        if (!orig_jbroot) {
                // Fallback to standard rootless path
                orig_jbroot = "/var/jb";
        }
        safe_strlcpy(g_roothide.base_jbroot, orig_jbroot, sizeof(g_roothide.base_jbroot));
        
        // Get preboot UUID
        get_preboot_uuid(g_roothide.preboot_uuid, sizeof(g_roothide.preboot_uuid));
        
        // Generate random suffix for path randomization
        generate_random_string(g_roothide.random_suffix, sizeof(g_roothide.random_suffix));
        
        // Construct randomized jbroot path: /private/preboot/{UUID}/jb_{random}
        snprintf(g_roothide.jbroot_path, sizeof(g_roothide.jbroot_path),
                 "/private/preboot/%s/jb_%s",
                 g_roothide.preboot_uuid,
                 g_roothide.random_suffix);
        
        // Generate session identifier
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

const char* roothide_get_jbroot(void)
{
        if (!g_roothide.initialized) {
                rothide_init();
        }
        return g_roothide.jbroot_path;
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
                rothide_init();
        }
        return g_roothide.session_id;
}

const char* jbroot(const char* path)
{
        if (!path) return NULL;
        
        if (!g_roothide.initialized) {
                rothide_init();
        }
        
        // Use thread-local cache for performance
        if (tl_cache_valid && tl_last_input == path) {
                return tl_converted_path;
        }
        
        // Convert path: replace /var/jb prefix with randomized jbroot
        const char *result = NULL;
        
        if (strncmp(path, "/var/jb/", 8) == 0) {
                // Standard rootless path conversion
                snprintf(tl_converted_path, sizeof(tl_converted_path), "%s%s", 
                        g_roothide.jbroot_path, path + 7); // Skip "/var/jb" keep "/"
                result = tl_converted_path;
        }
        else if (strncmp(path, "/var/jb", 7) == 0 && strlen(path) == 7) {
                // Exact match for /var/jb
                safe_strlcpy(tl_converted_path, g_roothide.jbroot_path, sizeof(tl_converted_path));
                result = tl_converted_path;
        }
        else {
                // No conversion needed, return original
                result = path;
        }
        
        tl_last_input = path;
        tl_cache_valid = true;
        
        return result;
}

const char* rootfs(const char* path)
{
        // Alias for jbroot - backward compatibility
        return jbroot(path);
}

int rothide_convert_path(const char* input, char* output, size_t outsize)
{
        if (!input || !output || outsize == 0) return -1;
        
        const char *converted = jbroot(input);
        if (!converted) return -1;
        
        safe_strlcpy(output, converted, outsize);
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
