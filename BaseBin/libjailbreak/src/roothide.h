// roothide.h - RootHide Public Interface
// Header for RootHide jailbreak hiding functionality

#ifndef ROOTHIDE_H
#define ROOTHIDE_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/param.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============ Configuration Constants ============
#define ROOTHIDE_MAX_BLACKLIST_ENTRIES 256
#define ROOTHIDE_RANDOM_STRING_LENGTH  16
#define ROOTHIDE_JBROOT_PATH_MAX       PATH_MAX

// ============ Environment Variable Names ============
#define ROOTHIDE_CLEAN_MODE_ENV "ROOTHIDE_CLEAN_MODE"
#define ROOTHIDE_JBROOT_ENV     "JBROOT"
#define ROOTHIDE_MODE_ENV       "ROOTHIDE_MODE"

// ============ Core Initialization ============

/**
 * Initialize the RootHide subsystem
 * Must be called before using any other RootHide functions
 * @return 0 on success, negative on error
 */
int roothide_init(void);

// ============ Path Management ============

/**
 * Get the randomized jbroot path (e.g., /private/preboot/UUID/jb_XXXX)
 * @return The randomized jbroot path string, or NULL on error
 */
const char* rothide_get_jbroot(void);

/**
 * Convert a standard jailbreak path to a RootHide path
 * Replaces jbroot prefix with randomized jbroot path
 * 
 * @param input  Input path (e.g., "/private/preboot/UUID/jb_XXXX/basebin/jbserver")
 * @param output Output buffer for converted path
 * @param outsize Size of output buffer
 * @return 0 on success, -1 on error
 */
int rothide_convert_path(const char* input, char* output, size_t outsize);

// ============ Blacklist Management ============

/**
 * Add an app bundle ID to the blacklist
 * Blacklisted apps will not receive tweak injection or jailbreak environment
 * 
 * @param bundleID The bundle identifier (e.g., "com.example.app")
 * @return 0 on success, -1 on invalid input, -2 if blacklist is full
 */
int rothide_add_blacklist(const char* bundleID);

/**
 * Remove an app bundle ID from the blacklist
 * 
 * @param bundleID The bundle identifier to remove
 * @return 0 on success, -1 if not found or invalid input
 */
int rothide_remove_blacklist(const char* bundleID);

/**
 * Check if an app is blacklisted
 * 
 * @param bundleID The bundle identifier to check
 * @return true if blacklisted, false otherwise
 */
bool roothide_is_blacklisted(const char* bundleID);

/**
 * Get the current number of blacklisted apps
 * @return Number of entries in blacklist
 */
int rothide_get_blacklist_count(void);

/**
 * Get a specific blacklist entry by index
 * Used for UI display of current blacklist
 * 
 * @param index Index into blacklist array (0-based)
 * @return Bundle ID string at index, or NULL if index out of range
 */
const char* rothide_get_blacklist_entry(int index);

// ============ Clean Mode Detection ============

/**
 * Determine if a process should run in clean mode (no jailbreak traces)
 * Checks both blacklist and inherited environment variables
 * 
 * @param executable_path Path to the executable (optional, can be NULL)
 * @param bundle_id Bundle ID of the app (optional, can be NULL)
 * @return true if process should be clean, false otherwise
 */
bool rothide_should_be_clean(const char* executable_path, const char* bundle_id);

// ============ Session Information ============

/**
 * Get unique session identifier for this jailbreak instance
 * Useful for identifying which jbroot belongs to this session
 * 
 * @return 64-bit session identifier
 */
unsigned long long jbrand(void);

// ============ Path Conversion Helpers ============

/**
 * Sanitize a path for use inside a clean-mode process.
 * With the current design, the on-disk jbroot path is the same for every process
 * (it is the path returned by jbserver at jailbreak time), so this function
 * just returns `path` unchanged.
 *
 * Renamed from `jbroot()` to avoid a name collision with `jbroot.c::get_jbroot()`
 * (different signature, different meaning).
 *
 * @param path Input path
 * @return The same pointer as `path` (no allocation, no copy)
 */
const char* roothide_sanitize_path_v2(const char* path);

// === Backward compatibility shims ===
// These keep older call sites (if any) compiling. They are thin wrappers
// over roothide_sanitize_path_v2() and behave identically.
static inline const char* roothide_jbroot_path(const char* path)
{
        return roothide_sanitize_path_v2(path);
}
static inline const char* roothide_rootfs(const char* path)
{
        return roothide_sanitize_path_v2(path);
}

// ============ Advanced Hiding Functions (arm64e optimized) ============

/**
 * Initialize RootHide hiding subsystem with syscall-level hooks
 * Must be called early in process startup for blacklisted apps
 * 
 * @param clean_mode If true, enable full jailbreak hiding
 * @return 0 on success, negative on error
 */
int roothide_hide_init(bool clean_mode);

/**
 * Dynamically enable/disable clean mode at runtime
 * Useful for apps that need temporary JB access
 * 
 * @param enabled true to enable hiding, false to disable
 */
void roothide_set_clean_mode(bool enabled);

/**
 * Check if current process is running in clean mode
 * @return true if clean mode is active
 */
bool roothide_is_clean_mode(void);

/**
 * Sanitize a path for use in clean mode
 * Converts hidden paths to safe alternatives
 * 
 * @param path Input path to sanitize
 * @return Sanitized path, or original if not hiding
 */
const char* roothide_sanitize_path(const char* path);

/**
 * Clean all jailbreak-related environment variables
 * Call this after setting clean mode
 */
void roothide_clean_environment(void);

#ifdef __cplusplus
}
#endif

#endif // ROOTHIDE_H
