// roothide.h - RootHide Public Interface
// Header for RootHide jailbreak hiding functionality
//
// This header provides the FULL set of RootHide APIs needed for compatibility
// with the RootHide IPA app (com.roothide.manager). The RootHide app expects:
//   - jbroot(NSString*) — C++ function exported by libroothide.dylib
//   - roothide_* C APIs for blacklist, path translation, hiding
//
// All public APIs are listed below. Implementation in roothide.c and
// roothide_hide.c.

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

/**
 * Clear all blacklist entries
 * @return 0 on success, -1 on error
 */
int rothide_clear_blacklist(void);

/**
 * Get the full blacklist as a comma-separated string
 * Caller must NOT free the returned buffer (owned by RootHide subsystem)
 * 
 * @param outBuf Output buffer to fill
 * @param outSize Size of output buffer
 * @return 0 on success, -1 on error
 */
int rothide_get_blacklist_string(char* outBuf, size_t outSize);

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

/**
 * Get the current session ID (alias for jbrand())
 * @return 64-bit session identifier
 */
unsigned long long rothide_get_session_id(void);

/**
 * Get the jbroot UUID (preboot UUID)
 * @param uuid_out Output buffer for UUID (must be at least 37 bytes)
 * @param uuid_len Size of output buffer
 * @return 0 on success, -1 on error
 */
int rothide_get_jbroot_uuid(char* uuid_out, size_t uuid_len);

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

/**
 * Translate a path - replaces /var/jb prefix with jbroot path
 * (compatibility with RootHide Bootstrap apps that expect /var/jb style paths)
 * 
 * @param path Input path (e.g., "/var/jb/usr/bin/dpkg")
 * @param outBuf Output buffer
 * @param outSize Size of output buffer
 * @return 0 on success, -1 on error
 */
int rothide_translate_path(const char* path, char* outBuf, size_t outSize);

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

// ============ App Hiding Detection ============

/**
 * Check if an app should be hidden (alias for rothide_should_be_clean)
 * Used by systemhook to decide whether to inject tweaks
 * 
 * @param bundleID The bundle identifier to check
 * @return true if app should be hidden, false otherwise
 */
bool rothide_is_app_hidden(const char* bundleID);

/**
 * Check if current process is running in clean mode
 * @return true if clean mode is active
 */
bool roothide_is_clean_mode(void);

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

/**
 * Hide a specific path dynamically
 * Useful for user-configured paths
 * 
 * @param path Path to hide
 * @return 0 on success, -1 on error
 */
int roothide_hide_path(const char* path);

/**
 * Get list of currently hidden paths (for debugging/UI)
 * 
 * @param count Output: number of hidden paths
 * @return Array of hidden path strings (NULL-terminated)
 */
const char** roothide_get_hidden_paths(int *count);

#ifdef __cplusplus
} // extern "C"

// ============ C++ API for RootHide app compatibility ============
//
// The RootHide app (com.roothide.manager) is a pre-compiled IPA that links
// against libroothide.dylib via @loader_path/.jbroot/usr/lib/libroothide.dylib
// and calls the C++ function `jbroot(NSString*)` (mangled: __Z6jbrootP8NSString).
//
// To make the RootHide app work WITHOUT modification, we export this exact
// symbol from our libroothide.dylib (which is loaded as a replacement for
// the original). The implementation simply calls our get_jbroot() C function
// and wraps the result in an NSString.
//
// This is declared here (in the C++ section) so that any translation unit
// compiled as C++ will see the declaration and emit the mangled symbol.

#ifdef __OBJC__
#import <Foundation/Foundation.h>

// C++ function exported to match RootHide app's expected symbol.
// Returns the jbroot path as an autoreleased NSString.
// Implemented in roothide.cpp (or roothide_objc.mm).
NSString* jbroot(NSString* path);

#endif // __OBJC__

#endif // __cplusplus

#endif // ROOTHIDE_H

