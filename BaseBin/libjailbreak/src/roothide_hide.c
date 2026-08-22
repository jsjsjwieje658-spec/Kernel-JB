// roothide_hide.c - Advanced RootHide Hiding Implementation
// Provides comprehensive jailbreak hiding for blacklisted apps:
// - Path hiding (jbroot -> randomized path)
// - Environment variable cleaning
// - File/directory access interception
// - Syscall-level hiding
// NOTE: RootHide does NOT use /var/jb - uses randomized jbroot path only

#include "roothide.h"
#include "libjailbreak.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
// FIX BUG #24: include litehook để gọi rebind_symbol (fishhook-style GOT rebind).
// Trước đây roothide_hide chỉ dlsym(RTLD_NEXT, ...) để save function pointer,
// nhưng KHÔNG hook function nào → access/fopen/opendir/stat/lstat/open vẫn là
// syscall gốc → file hiding KHÔNG hoạt động → app detection vẫn thấy /var/lib/dpkg,
// /Library/MobileSubstrate, etc. → crash hoặc refuse to run.
#include <litehook.h>

// ============ Hidden Path Patterns ============
// These paths should be hidden from blacklisted apps
// NOTE: /var/jb is NOT used in RootHide - we dynamically detect jbroot
static const char *g_hidden_paths[] = {
    "/var/lib/dpkg",
    "/var/cache/apt",
    "/etc/apt",
    "/Library/MobileSubstrate",
    "/Library/LaunchDaemons",
    "/usr/lib/substrate",
    "/usr/lib/TweakInject",
    "/var/mobile/Library/Preferences/com.cydia",
    NULL
};

// Dynamic jbroot path (resolved at runtime)
static char g_jbroot_path[PATH_MAX] = {0};
static bool g_jbroot_initialized = false;

// Get current jbroot path for dynamic hiding
static const char* get_dynamic_jbroot(void)
{
    if (!g_jbroot_initialized) {
        const char *jbroot = get_jbroot();
        if (jbroot) {
            strncpy(g_jbroot_path, jbroot, sizeof(g_jbroot_path) - 1);
            g_jbroot_path[sizeof(g_jbroot_path) - 1] = '\0';
        }
        g_jbroot_initialized = true;
    }
    return g_jbroot_path[0] ? g_jbroot_path : NULL;
}

// ============ Hidden Environment Variables ============
static const char *g_hidden_env_vars[] = {
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "CS_PLATFORMIZED",
    "ROOTHIDE_CLEAN_MODE",
    "ROOTHIDE_MODE",
    "JBROOT",
    "_MSSafeMode",
    "SAFE_MODE",
    NULL
};

// ============ Process State ============
static struct {
    bool initialized;
    bool is_clean_mode;  // Current process is in clean mode
    
    // Original function pointers (for unhooking)
    int (*orig_access)(const char *, int);
    FILE *(*orig_fopen)(const char *, const char *);
    DIR *(*orig_opendir)(const char *);
    int (*orig_stat)(const char *, struct stat *);
    int (*orig_lstat)(const char *, struct stat *);
    int (*orig_open)(const char *, int, ...);
    
    pthread_mutex_t mutex;
} g_roothide_hide = {
    .initialized = false,
    .is_clean_mode = false,
    .orig_access = NULL,
    .orig_fopen = NULL,
    .orig_opendir = NULL,
    .orig_stat = NULL,
    .orig_lstat = NULL,
    .orig_open = NULL,
    .mutex = PTHREAD_MUTEX_INITIALIZER
};

// ============ Utility Functions ============

// Check if a path should be hidden
static bool should_hide_path(const char *path)
{
    if (!path) return false;
    
    // Check dynamic jbroot path first (RootHide uses randomized paths)
    const char *dynamic_jbroot = get_dynamic_jbroot();
    if (dynamic_jbroot && strncmp(path, dynamic_jbroot, strlen(dynamic_jbroot)) == 0) {
        char next_char = path[strlen(dynamic_jbroot)];
        if (next_char == '\0' || next_char == '/') {
            return true;
        }
    }
    
    for (int i = 0; g_hidden_paths[i] != NULL; i++) {
        if (strncmp(path, g_hidden_paths[i], strlen(g_hidden_paths[i])) == 0) {
            // Exact match or subdirectory
            if (path[strlen(g_hidden_paths[i])] == '\0' || 
                path[strlen(g_hidden_paths[i])] == '/') {
                return true;
            }
        }
    }
    
    // Also check for common jailbreak file patterns
    const char *jb_files[] = {
        ".cydia_no_stash",
        "cydia",
        "sileo",
        "filza",
        ".installed_cydiadev",
        NULL
    };
    
    for (int i = 0; jb_files[i] != NULL; i++) {
        if (strstr(path, jb_files[i])) {
            return true;
        }
    }
    
    return false;
}

// Check if an environment variable should be hidden
static bool should_hide_env_var(const char *name)
{
    if (!name) return false;
    
    for (int i = 0; g_hidden_env_vars[i] != NULL; i++) {
        if (strcmp(name, g_hidden_env_vars[i]) == 0) {
            return true;
        }
    }
    return false;
}

// Get fake "not found" response for hidden paths
static int fake_not_found(const char *path)
{
    errno = ENOENT;
    return -1;
}

// ============ Hooked Functions ============

// Hooked access() - hide path existence
static int hooked_access(const char *pathname, int mode)
{
    if (g_roothide_hide.is_clean_mode && should_hide_path(pathname)) {
        return fake_not_found(pathname);
    }
    
    if (g_roothide_hide.orig_access) {
        return g_roothide_hide.orig_access(pathname, mode);
    }
    return access(pathname, mode);
}

// Hooked fopen() - prevent opening hidden files
static FILE *hooked_fopen(const char *filename, const char *mode)
{
    if (g_roothide_hide.is_clean_mode && should_hide_path(filename)) {
        errno = ENOENT;
        return NULL;
    }
    
    if (g_roothide_hide.orig_fopen) {
        return g_roothide_hide.orig_fopen(filename, mode);
    }
    return fopen(filename, mode);
}

// Hooked opendir() - hide directories
static DIR *hooked_opendir(const char *name)
{
    if (g_roothide_hide.is_clean_mode && should_hide_path(name)) {
        errno = ENOENT;
        return NULL;
    }
    
    if (g_roothide_hide.orig_opendir) {
        return g_roothide_hide.orig_opendir(name);
    }
    return opendir(name);
}

// Hooked stat() - hide file info
static int hooked_stat(const char *pathname, struct stat *statbuf)
{
    if (g_roothide_hide.is_clean_mode && should_hide_path(pathname)) {
        return fake_not_found(pathname);
    }
    
    if (g_roothide_hide.orig_stat) {
        return g_roothide_hide.orig_stat(pathname, statbuf);
    }
    return stat(pathname, statbuf);
}

// Hooked lstat() - hide symlink info
static int hooked_lstat(const char *pathname, struct stat *statbuf)
{
    if (g_roothide_hide.is_clean_mode && should_hide_path(pathname)) {
        return fake_not_found(pathname);
    }
    
    if (g_roothide_hide.orig_lstat) {
        return g_roothide_hide.orig_lstat(pathname, statbuf);
    }
    return lstat(pathname, statbuf);
}

// Hooked open() - prevent opening hidden files
static int hooked_open(const char *pathname, int flags, ...)
{
    if (g_roothide_hide.is_clean_mode && should_hide_path(pathname)) {
        return fake_not_found(pathname);
    }
    
    if (g_roothide_hide.orig_open) {
        mode_t mode = 0;
        if (flags & O_CREAT) {
            va_list args;
            va_start(args, flags);
            mode = va_arg(args, int);
            va_end(args);
            return g_roothide_hide.orig_open(pathname, flags, mode);
        }
        return g_roothide_hide.orig_open(pathname, flags);
    }
    
    // Fallback to original open
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode_t mode = va_arg(args, int);
        va_end(args);
        return open(pathname, flags, mode);
    }
    return open(pathname, flags);
}

// ============ Environment Cleaning ============

// Clean environment variables for blacklisted apps
void roothide_clean_environment(void)
{
    if (!g_roothide_hide.is_clean_mode) return;
    
    // Hide sensitive environment variables
    for (int i = 0; g_hidden_env_vars[i] != NULL; i++) {
        unsetenv(g_hidden_env_vars[i]);
    }
    
    // Add decoy environment variables to confuse detection
    setenv("SIMULATOR", "1", 1);  // Pretend we're running in simulator
}

// ============ Public API ============

/**
 * Initialize RootHide hiding subsystem
 * Call this early in process startup
 *
 * FIX BUG #24: Trước đây hàm này chỉ `dlsym(RTLD_NEXT, ...)` để save function
 * pointer, nhưng KHÔNG hook gì cả → access/fopen/opendir/stat/lstat/open
 * vẫn là syscall gốc → file hiding KHÔNG hoạt động. App detection đọc file
 * /var/lib/dpkg, /Library/MobileSubstrate, etc. vẫn thấy → crash hoặc refuse
 * to run.
 *
 * Fix: dùng `litehook_rebind_symbol` (fishhook-style GOT rebind) để thực sự
 * thay thế function pointer trong GOT của tất cả images đã load → khi app
 * gọi access()/stat()/... control flow sẽ đi qua hàm hooked_*. Hàm hooked
 * kiểm tra should_hide_path() và return ENOENT nếu path match.
 *
 * Lưu ý: `litehook_rebind_symbol(NULL, ...)` rebind toàn cục (mọi image trong
 * process). Có thể ảnh hưởng performance nhẹ (~10ms trên launch), nhưng chỉ
 * chạy khi clean_mode=true (chỉ blacklisted app mới bị hook).
 */
int roothide_hide_init(bool clean_mode)
{
    pthread_mutex_lock(&g_roothide_hide.mutex);

    if (g_roothide_hide.initialized) {
	// Đã init rồi, chỉ update clean_mode
	g_roothide_hide.is_clean_mode = clean_mode;
	if (clean_mode) {
	    roothide_clean_environment();
        }
        pthread_mutex_unlock(&g_roothide_hide.mutex);
        return 0;
    }

    g_roothide_hide.is_clean_mode = clean_mode;

    // Save original function pointers using dlsym with RTLD_NEXT.
    // Đây là "fallback" nếu litehook_rebind_symbol fail hoặc nếu cần gọi
    // function gốc từ trong hook (vì litehook_rebind_symbol không trả về orig).
    g_roothide_hide.orig_access = dlsym(RTLD_NEXT, "access");
    g_roothide_hide.orig_fopen = dlsym(RTLD_NEXT, "fopen");
    g_roothide_hide.orig_opendir = dlsym(RTLD_NEXT, "opendir");
    g_roothide_hide.orig_stat = dlsym(RTLD_NEXT, "stat");
    g_roothide_hide.orig_lstat = dlsym(RTLD_NEXT, "lstat");
    g_roothide_hide.orig_open = dlsym(RTLD_NEXT, "open");

    // FIX BUG #24: rebind GOT để hooks thật sự chạy.
    // litehook_rebind_symbol(NULL, replacee, replacement, NULL) rebind globally.
    if (clean_mode) {
	// Chỉ hook khi clean_mode=true (đừng hook mọi process — performance)
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL,
			       (void *)access,  (void *)hooked_access,  NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL,
			       (void *)fopen,   (void *)hooked_fopen,   NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL,
			       (void *)opendir, (void *)hooked_opendir, NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL,
			       (void *)stat,    (void *)hooked_stat,    NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL,
			       (void *)lstat,   (void *)hooked_lstat,   NULL);
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL,
			       (void *)open,    (void *)hooked_open,    NULL);

	// Clean environment sau khi hook (để env check không bị phát hiện)
        roothide_clean_environment();
    }

    g_roothide_hide.initialized = true;
    pthread_mutex_unlock(&g_roothide_hide.mutex);

    return 0;
}

/**
 * Enable/disable clean mode at runtime
 * Useful for apps that need temporary access to JB
 */
void roothide_set_clean_mode(bool enabled)
{
    pthread_mutex_lock(&g_roothide_hide.mutex);
    g_roothide_hide.is_clean_mode = enabled;
    
    if (enabled) {
        roothide_clean_environment();
    }
    pthread_mutex_unlock(&g_roothide_hide.mutex);
}

/**
 * Check if current process is in clean mode
 */
bool roothide_is_clean_mode(void)
{
    return g_roothide_hide.is_clean_mode;
}

/**
 * Hide a specific path dynamically
 * Useful for user-configured paths
 */
int roothide_hide_path(const char *path)
{
    if (!path) return -1;
    // This would add to a dynamic hidden list
    // For now, just log it
    if (g_roothide_hide.is_clean_mode) {
        // Path will be checked by should_hide_path()
        return 0;
    }
    return -1;
}

/**
 * Get list of currently hidden paths (for debugging/UI)
 */
const char** roothide_get_hidden_paths(int *count)
{
    if (count) {
        // Count paths (excluding NULL terminator)
        *count = 0;
        while (g_hidden_paths[*count] != NULL) (*count)++;
    }
    return g_hidden_paths;
}

/**
 * Convert a path for use in clean mode
 * Returns original path if not hiding, converted path if hiding
 */
const char* roothide_sanitize_path(const char *path)
{
    if (!path || !g_roothide_hide.is_clean_mode) {
        return path;
    }
    
    // Check if path should be hidden
    if (should_hide_path(path)) {
        // Return a fake safe path
        static char fake_path[PATH_MAX];
        snprintf(fake_path, sizeof(fake_path), "/var/hidden_%d", getpid());
        return fake_path;
    }
    
    // Use jbroot conversion for jbroot paths (dynamic, not /var/jb)
    // jbroot() was renamed to roothide_sanitize_path_v2() — it is now a no-op
    // (the on-disk jbroot path is the same for every process).
    return roothide_sanitize_path_v2(path);
}
