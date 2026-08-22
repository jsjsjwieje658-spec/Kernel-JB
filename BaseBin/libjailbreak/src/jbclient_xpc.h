#ifndef JBCLIENT_XPC_H
#define JBCLIENT_XPC_H

#include <xpc/xpc.h>
#include <xpc_private.h>
#include <stdint.h>
#include "signatures.h"

void jbclient_xpc_set_custom_port(mach_port_t serverPort);

xpc_object_t jbserver_xpc_send_dict(xpc_object_t xdict);
xpc_object_t jbserver_xpc_send(uint64_t domain, uint64_t action, xpc_object_t xargs);

char *jbclient_get_jbroot(void);
char *jbclient_get_boot_uuid(void);
int jbclient_trust_file(int fd, struct siginfo *siginfo, bool attach);
int jbclient_trust_file_by_path(const char *path);
int jbclient_process_checkin(char **rootPathOut, char **bootUUIDOut, char **sandboxExtensionsOut, bool *fullyDebuggedOut, bool *forceCSAdhocOut);
int jbclient_fork_fix(uint64_t childPid);
int jbclient_cs_revalidate(void);
int jbclient_jbsettings_get(const char *key, xpc_object_t *valueOut);
bool jbclient_jbsettings_get_bool(const char *key);
uint64_t jbclient_jbsettings_get_uint64(const char *key);
double jbclient_jbsettings_get_double(const char *key);
int jbclient_persona_fix(int childPid, uid_t overwriteUid, gid_t overwriteGid);
int jbclient_platform_set_process_debugged(uint64_t pid, bool fullyDebugged);
int jbclient_platform_stage_jailbreak_update(const char *updateTar);
int jbclient_platform_jbsettings_set(const char *key, xpc_object_t value);
int jbclient_platform_jbsettings_set_bool(const char *key, bool boolValue);
int jbclient_platform_jbsettings_set_uint64(const char *key, uint64_t uint64Value);
int jbclient_platform_jbsettings_set_double(const char *key, double doubleValue);
int jbclient_platform_set_systemwide_domain_enabled(bool enabled);
int jbclient_watchdog_intercept_userspace_panic(const char *panicMessage);
int jbclient_watchdog_get_last_userspace_panic(char **panicMessage);
int jbclient_root_get_physrw(bool singlePTE, uint64_t *singlePTEAsidPtr);
int jbclient_root_sign_thread(mach_port_t threadPort);
int jbclient_root_get_sysinfo(xpc_object_t *sysInfoOut);
int jbclient_root_steal_ucred(uint64_t ucredToSteal, uint64_t *orgUcred);
int jbclient_root_set_mac_label(uint64_t slot, uint64_t label, uint64_t *orgLabel);
int jbclient_root_trustcache_info(xpc_object_t *infoOut);
int jbclient_root_trustcache_add_cdhash(uint8_t *cdhashData, size_t cdhashLen);
int jbclient_root_trustcache_clear(void);
int jbclient_boomerang_done(void);
bool jbclient_dopamine_is_jailbroken(char **version);
int jbclient_dopamine_get_root(void);
int jbclient_dopamine_drop_root(void);

// ========== ROOTHIDE CONTROL FUNCTIONS ==========
// These functions allow controlling RootHide from userspace (Dopamine app)

/**
 * Initialize RootHide subsystem on jbserver side
 * @return 0 on success
 */
int jbclient_roothide_init(void);

/**
 * Enable or disable RootHide mode globally
 * @param enabled YES to enable, NO to disable
 * @return 0 on success
 */
int jbclient_roothide_set_enabled(bool enabled);

/**
 * Check if RootHide is currently enabled
 * @return YES if enabled, NO otherwise
 */
bool jbclient_roothide_is_enabled(void);

/**
 * Add an app bundle ID to the RootHide blacklist
 * @param bundleID The bundle identifier to blacklist
 * @return 0 on success
 */
int jbclient_roothide_add_blacklist(const char *bundleID);

/**
 * Remove an app bundle ID from the RootHide blacklist
 * @param bundleID The bundle identifier to remove
 * @return 0 on success
 */
int jbclient_roothide_remove_blacklist(const char *bundleID);

/**
 * Get the current randomized jbroot path from RootHide
 * @return The path string (must be freed by caller), or NULL on error
 */
char *jbclient_roothide_get_jbroot_path(void);

/**
 * Apply RootHide settings and optionally reboot userspace
 * @param shouldReboot If YES, triggers userspace reboot after applying
 * @return 0 on success
 */
int jbclient_roothide_apply_settings(bool shouldReboot);

/**
 * FIX LỖI 1: Query blacklist động từ launchdjbserver.
 * Systemhook gọi hàm này để quyết định có inject tweak vào app hay không.
 * Tránh việc chỉ check env var (env var có thể không được set đúng).
 *
 * @param bundleID Bundle identifier của app sắp spawn
 * @return true nếu app nằm trong blacklist (skip injection), false nếu OK
 */
bool jbclient_roothide_is_blacklisted(const char *bundleID);

// ========== ROOTHIDE FIX LỖI 2: Full APIs for RootHide app compatibility ==========

/**
 * Get the current number of blacklisted apps
 * @return Number of entries in blacklist, or -1 on error
 */
int jbclient_roothide_get_blacklist_count(void);

/**
 * Get a specific blacklist entry by index
 * @param index Index into blacklist array (0-based)
 * @return Bundle ID string (must be freed by caller), or NULL if out of range
 */
char *jbclient_roothide_get_blacklist_entry(int index);

/**
 * Get the full blacklist as a comma-separated string
 * @return Comma-separated string (must be freed by caller), or NULL on error
 */
char *jbclient_roothide_get_blacklist_string(void);

/**
 * Clear all blacklist entries
 * @return 0 on success, -1 on error
 */
int jbclient_roothide_clear_blacklist(void);

/**
 * Get the jailbreak session ID
 * @return 64-bit session identifier
 */
uint64_t jbclient_roothide_get_session_id(void);

/**
 * Get the jbroot preboot UUID
 * @return UUID string (must be freed by caller), or NULL on error
 */
char *jbclient_roothide_get_jbroot_uuid(void);

/**
 * Translate a /var/jb style path to the actual jbroot path
 * @param path Input path (e.g., "/var/jb/usr/bin/dpkg")
 * @return Translated path (must be freed by caller), or NULL on error
 */
char *jbclient_roothide_translate_path(const char *path);

/**
 * Check if an app should be hidden (alias for is_blacklisted)
 * @param bundleID The bundle identifier to check
 * @return true if app should be hidden, false otherwise
 */
bool jbclient_roothide_is_app_hidden(const char *bundleID);

#endif
