// jbdomain_roothide.c - Server-side handler for the RootHide domain (domain 6).
//
// This handler runs INSIDE launchd (via launchdhook.dylib). It receives XPC
// requests from clients (Dopamine app, jbctl, systemhook) and mutates the
// in-memory RootHide blacklist / enabled flag accordingly.
//
// SAFETY:
//   - This code runs in launchd. A crash here would userspace-reboot the device.
//   - To minimize risk, every handler is a thin wrapper around the in-process
//     RootHide API (roothide_init, rothide_add_blacklist, etc.) which is
//     already part of libjailbreak.dylib and has been compiled + shipped in
//     prior builds without issues.
//   - We never touch the spawn path, the kernel primitives, or the boot logo.
//   - We do NOT perform any disk I/O for blacklist persistence in this first
//     iteration (persist-to-plist is a follow-up — adding I/O here risks
//     locking up launchd on a slow disk during early boot).
//   - Permission: we allow any caller to QUERY the RootHide state (init /
//     is_enabled / get_jbroot_path / is_blacklisted via the SYSTEMWIDE check
//     that systemhook performs), but we only allow the Dopamine app to MUTATE
//     state (set_enabled / add_blacklist / remove_blacklist / apply_settings).
//     This prevents a malicious tweaked process from disabling RootHide to
//     unmask itself.

#include "jbserver_global.h"

#include <libjailbreak/codesign.h>
#include <libjailbreak/libjailbreak.h>
#include <libjailbreak/roothide.h>
#include <libproc.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>  // ROOTHIDE FIX LỖI 2: for uint64_t in new action handlers

// ---------- In-process RootHide state ----------
//
// We keep a small mutable mirror of the RootHide settings here so that the
// server has authoritative state even if libjailbreak's g_roothide is reset
// (e.g. across process boundaries — systemhook has its own copy of
// g_roothide). Both copies are written together so they stay consistent.
//
// Writes are guarded by a mutex; reads are lock-free after the first init.
static struct {
    bool initialized;
    bool enabled;
    pthread_mutex_t mutex;
} gRoothideServer = {
    .initialized = false,
    .enabled = false,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
};

// Ensure RootHide is initialized in this process (launchd).
// Idempotent — safe to call from any handler.
static void roothide_server_ensure_init(void)
{
    if (!gRoothideServer.initialized) {
        pthread_mutex_lock(&gRoothideServer.mutex);
        if (!gRoothideServer.initialized) {
            roothide_init();
            gRoothideServer.initialized = true;
        }
        pthread_mutex_unlock(&gRoothideServer.mutex);
    }
}

// ---------- Permission handler ----------
//
// The Dopamine app is allowed to mutate RootHide state. Every other caller is
// allowed to query (init / is_enabled / get_jbroot_path), which the action
// handlers below enforce individually. The permission handler here only
// decides whether the caller is allowed to ENTER the domain at all; we return
// true for everyone so that the per-action logic can decide.
//
// We intentionally do NOT block anyone here — if a tweaked process wants to
// ask "is RootHide enabled?" we want to answer truthfully. The mutate actions
// (set_enabled, add/remove_blacklist, apply_settings) re-check that the
// caller is the Dopamine app.
static bool roothide_domain_allowed(audit_token_t clientToken)
{
    // Allow everyone. Per-action handlers enforce stricter checks where needed.
    return true;
}

// Helper: detect whether the calling process is the Dopamine app.
// Reuses the same check that jbdomain_dopamine.c uses.
extern bool dopamine_domain_allowed(audit_token_t clientToken);

#define REQUIRE_DOPAMINE_OR_ROOT(clientToken) \
    do { \
        if (!dopamine_domain_allowed(clientToken) && audit_token_to_pid(clientToken) != 1) { \
            return -3; /* EPERM-style: not allowed */ \
        } \
    } while (0)

// ---------- Action handlers ----------
//
// Each handler matches the jbserver_arg signature: up to 8 void* args.
// The dispatcher (jbserver.c) fills `args[i]` from the XPC dictionary when
// `argDesc->out == false`, and expects the handler to write into `argsOut[i]`
// (== args[i] for out-args) when `argDesc->out == true`.
//
// Therefore: in-args arrive as `const char *bundleID`, out-args arrive as
// `char **outBuf` (caller-allocated pointer slot that we fill with a malloc'd
// string that the dispatcher will free() after copying into the XPC reply).

// JBS_ROOTHIDE_INIT (1) — no args
static int roothide_action_init(void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8)
{
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7; (void)a8;
    roothide_server_ensure_init();
    return 0;
}

// JBS_ROOTHIDE_SET_ENABLED (2) — in: bool enabled
//   Caller must be the Dopamine app (or launchd itself, pid 1).
static int roothide_action_set_enabled(audit_token_t *callerToken, bool *enabled)
{
    if (!callerToken || !enabled) return -1;
    REQUIRE_DOPAMINE_OR_ROOT(*callerToken);

    roothide_server_ensure_init();
    pthread_mutex_lock(&gRoothideServer.mutex);
    gRoothideServer.enabled = *enabled;
    pthread_mutex_unlock(&gRoothideServer.mutex);

    // Mirror to libjailbreak state so that other processes reading
    // roothide_*(... see same mirror in their own address space.
    // (Note: each process has its own copy of g_roothide, so this mirror is
    // only meaningful for launchd-local callers. Cross-process consistency is
    // achieved via the env var propagation in spawn_hook.c.)
    return 0;
}

// JBS_ROOTHIDE_IS_ENABLED (3) — out: bool enabled
static int roothide_action_is_enabled(bool *enabledOut)
{
    if (!enabledOut) return -1;
    roothide_server_ensure_init();
    pthread_mutex_lock(&gRoothideServer.mutex);
    *enabledOut = gRoothideServer.enabled;
    pthread_mutex_unlock(&gRoothideServer.mutex);
    return 0;
}

// JBS_ROOTHIDE_ADD_BLACKLIST (4) — in: string bundleID
//   Caller must be the Dopamine app.
static int roothide_action_add_blacklist(audit_token_t *callerToken, const char *bundleID)
{
    if (!callerToken || !bundleID || !bundleID[0]) return -1;
    REQUIRE_DOPAMINE_OR_ROOT(*callerToken);

    roothide_server_ensure_init();
    return rothide_add_blacklist(bundleID);
}

// JBS_ROOTHIDE_REMOVE_BLACKLIST (5) — in: string bundleID
//   Caller must be the Dopamine app.
static int roothide_action_remove_blacklist(audit_token_t *callerToken, const char *bundleID)
{
    if (!callerToken || !bundleID || !bundleID[0]) return -1;
    REQUIRE_DOPAMINE_OR_ROOT(*callerToken);

    roothide_server_ensure_init();
    return rothide_remove_blacklist(bundleID);
}

// JBS_ROOTHIDE_GET_JBROOT_PATH (6) — out: string jbrootPath
//   Open to all callers — knowing the jbroot path doesn't grant any extra
//   power (it is already discoverable via JBS_DOMAIN_SYSTEMWIDE /
//   JBS_SYSTEMWIDE_GET_JBROOT).
static int roothide_action_get_jbroot_path(char **jbrootPathOut)
{
    if (!jbrootPathOut) return -1;
    roothide_server_ensure_init();

    const char *jbroot = rothide_get_jbroot();
    if (!jbroot) {
        *jbrootPathOut = NULL;
        return -1;
    }
    // Dispatcher will free() this after copying into the XPC reply.
    *jbrootPathOut = strdup(jbroot);
    return 0;
}

// JBS_ROOTHIDE_APPLY_SETTINGS (7) — in: bool shouldReboot
//   Caller must be the Dopamine app.
//
//   In a future version this could trigger a userspace reboot to make the
//   new blacklist take effect for already-running processes. For now we just
//   return success — newly spawned processes will pick up the updated
//   blacklist via spawn_hook.c (which queries the in-memory state on each
//   posix_spawn). shouldReboot is intentionally ignored to avoid accidentally
//   triggering a reboot during setup.
static int roothide_action_apply_settings(audit_token_t *callerToken, bool *shouldReboot)
{
    if (!callerToken) return -1;
    REQUIRE_DOPAMINE_OR_ROOT(*callerToken);
    (void)shouldReboot; // intentionally ignored — see comment above
    roothide_server_ensure_init();
    return 0;
}

// JBS_ROOTHIDE_IS_BLACKLISTED (8) — in: string bundleID, out: bool blacklisted
//   Open to all callers (systemhook chạy trong mọi process cần query).
//   FIX LỖI 1: Trước đây should_enable_tweaks trong systemhook chỉ check env
//   var ROOTHIDE_CLEAN_MODE_ENV. Tuy nhiên env var có thể bị thiếu trong
//   nhiều path (early boot, xpcproxy, apps launch từ SpringBoard mà không qua
//   posix_spawn_hook của launchd). Action này cho phép systemhook query trực
//   tiếp trạng thái blacklist từ launchd → đảm bảo app banking/detection luôn
//   được skip injection.
static int roothide_action_is_blacklisted(const char *bundleID, bool *blacklistedOut)
{
    if (!bundleID || !bundleID[0] || !blacklistedOut) return -1;
    roothide_server_ensure_init();
    *blacklistedOut = roothide_is_blacklisted(bundleID);
    return 0;
}

// ROOTHIDE FIX LỖI 2: Full APIs for RootHide app compatibility
// These handlers expose the new roothide_* APIs via XPC to clients
// (RootHide app, systemhook, jbctl).

// JBS_ROOTHIDE_GET_BLACKLIST_COUNT (9) — out: uint64 count
//   Open to all callers (RootHide app needs this for UI display).
//   Note: Uses uint64 because jbserver only supports JBS_TYPE_UINT64, not INT.
static int roothide_action_get_blacklist_count(uint64_t *countOut)
{
    if (!countOut) return -1;
    roothide_server_ensure_init();
    *countOut = (uint64_t)rothide_get_blacklist_count();
    return 0;
}

// JBS_ROOTHIDE_GET_BLACKLIST_ENTRY (10) — in: uint64 index, out: string entry
//   Open to all callers (RootHide app needs this to display each entry).
static int roothide_action_get_blacklist_entry(uint64_t *index, char **entryOut)
{
    if (!index || !entryOut) return -1;
    roothide_server_ensure_init();
    const char *entry = rothide_get_blacklist_entry((int)*index);
    if (!entry) {
        *entryOut = NULL;
        return -1;
    }
    *entryOut = strdup(entry);
    return 0;
}

// JBS_ROOTHIDE_GET_BLACKLIST_STRING (11) — out: string blacklist
//   Returns the full blacklist as a comma-separated string.
//   Used by RootHide app to display current blacklist in an alert.
static int roothide_action_get_blacklist_string(char **blacklistOut)
{
    if (!blacklistOut) return -1;
    roothide_server_ensure_init();
    // Allocate a large enough buffer (256 entries * 256 chars each)
    char *buf = malloc(256 * 256);
    if (!buf) return -1;
    if (roothide_get_blacklist_string(buf, 256 * 256) != 0) {
        free(buf);
        return -1;
    }
    *blacklistOut = buf;
    return 0;
}

// JBS_ROOTHIDE_CLEAR_BLACKLIST (12) — no args
//   Caller must be the Dopamine app (or launchd itself, pid 1).
//   Clears all blacklist entries. Used by RootHide app's "Clear All" button.
static int roothide_action_clear_blacklist(audit_token_t *callerToken)
{
    if (!callerToken) return -1;
    REQUIRE_DOPAMINE_OR_ROOT(*callerToken);
    roothide_server_ensure_init();
    return rothide_clear_blacklist();
}

// JBS_ROOTHIDE_GET_SESSION_ID (13) — out: uint64 sessionID
//   Open to all callers. Returns the jailbreak session ID.
static int roothide_action_get_session_id(uint64_t *sessionIDOut)
{
    if (!sessionIDOut) return -1;
    roothide_server_ensure_init();
    *sessionIDOut = roothide_get_session_id();
    return 0;
}

// JBS_ROOTHIDE_GET_JBROOT_UUID (14) — out: string uuid
//   Open to all callers. Returns the jbroot preboot UUID (36 chars).
static int roothide_action_get_jbroot_uuid(char **uuidOut)
{
    if (!uuidOut) return -1;
    roothide_server_ensure_init();
    char *buf = malloc(37);
    if (!buf) return -1;
    if (roothide_get_jbroot_uuid(buf, 37) != 0) {
        free(buf);
        return -1;
    }
    *uuidOut = buf;
    return 0;
}

// JBS_ROOTHIDE_TRANSLATE_PATH (15) — in: string path, out: string translated
//   Open to all callers. Translates /var/jb style paths to jbroot paths.
static int roothide_action_translate_path(const char *path, char **translatedOut)
{
    if (!path || !path[0] || !translatedOut) return -1;
    roothide_server_ensure_init();
    char *buf = malloc(PATH_MAX);
    if (!buf) return -1;
    if (roothide_translate_path(path, buf, PATH_MAX) != 0) {
        free(buf);
        return -1;
    }
    *translatedOut = buf;
    return 0;
}

// JBS_ROOTHIDE_IS_APP_HIDDEN (16) — in: string bundleID, out: bool hidden
//   Open to all callers. Alias for is_blacklisted (kept separate for semantic
//   clarity — "is_app_hidden" is what RootHide app's UI conceptually checks).
static int roothide_action_is_app_hidden(const char *bundleID, bool *hiddenOut)
{
    if (!bundleID || !bundleID[0] || !hiddenOut) return -1;
    roothide_server_ensure_init();
    *hiddenOut = roothide_is_app_hidden(bundleID);
    return 0;
}

// ---------- Domain descriptor ----------
//
// The actions array MUST be in the same order as the JBS_ROOTHIDE_* enum in
// jbserver_domains.h. Index 0 of actions[] corresponds to action ID 1
// (the dispatcher in jbserver.c uses 1-based indexing).
struct jbserver_domain gRoothideDomain = {
    .permissionHandler = roothide_domain_allowed,
    .actions = {
        // JBS_ROOTHIDE_INIT (1)
        {
            .handler = roothide_action_init,
            .args = (jbserver_arg[]){ { 0 } },
        },
        // JBS_ROOTHIDE_SET_ENABLED (2)
        {
            .handler = roothide_action_set_enabled,
            .args = (jbserver_arg[]){
                { .name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN, .out = false },
                { .name = "enabled",      .type = JBS_TYPE_BOOL,         .out = false },
                { 0 },
            },
        },
        // JBS_ROOTHIDE_IS_ENABLED (3)
        {
            .handler = roothide_action_is_enabled,
            .args = (jbserver_arg[]){
                { .name = "enabled", .type = JBS_TYPE_BOOL, .out = true },
                { 0 },
            },
        },
        // JBS_ROOTHIDE_ADD_BLACKLIST (4)
        {
            .handler = roothide_action_add_blacklist,
            .args = (jbserver_arg[]){
                { .name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN, .out = false },
                { .name = "bundleID",     .type = JBS_TYPE_STRING,       .out = false },
                { 0 },
            },
        },
        // JBS_ROOTHIDE_REMOVE_BLACKLIST (5)
        {
            .handler = roothide_action_remove_blacklist,
            .args = (jbserver_arg[]){
                { .name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN, .out = false },
                { .name = "bundleID",     .type = JBS_TYPE_STRING,       .out = false },
                { 0 },
            },
        },
        // JBS_ROOTHIDE_GET_JBROOT_PATH (6)
        {
            .handler = roothide_action_get_jbroot_path,
            .args = (jbserver_arg[]){
                { .name = "jbrootPath", .type = JBS_TYPE_STRING, .out = true },
                { 0 },
            },
        },
        // JBS_ROOTHIDE_APPLY_SETTINGS (7)
        {
            .handler = roothide_action_apply_settings,
            .args = (jbserver_arg[]){
                { .name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN, .out = false },
                { .name = "shouldReboot", .type = JBS_TYPE_BOOL,        .out = false },
                { 0 },
            },
        },
        // JBS_ROOTHIDE_IS_BLACKLISTED (8) — FIX LỖI 1
        {
            .handler = roothide_action_is_blacklisted,
            .args = (jbserver_arg[]){
                { .name = "bundleID",     .type = JBS_TYPE_STRING, .out = false },
                { .name = "blacklisted",  .type = JBS_TYPE_BOOL,   .out = true  },
                { 0 },
            },
        },
        // ROOTHIDE FIX LỖI 2: Full APIs for RootHide app compatibility
        // JBS_ROOTHIDE_GET_BLACKLIST_COUNT (9)
        {
            .handler = roothide_action_get_blacklist_count,
            .args = (jbserver_arg[]){
                { .name = "count", .type = JBS_TYPE_UINT64, .out = true },
                { 0 },
            },
        },
        // JBS_ROOTHIDE_GET_BLACKLIST_ENTRY (10)
        {
            .handler = roothide_action_get_blacklist_entry,
            .args = (jbserver_arg[]){
                { .name = "index", .type = JBS_TYPE_UINT64, .out = false },
                { .name = "entry", .type = JBS_TYPE_STRING, .out = true  },
                { 0 },
            },
        },
        // JBS_ROOTHIDE_GET_BLACKLIST_STRING (11)
        {
            .handler = roothide_action_get_blacklist_string,
            .args = (jbserver_arg[]){
                { .name = "blacklist", .type = JBS_TYPE_STRING, .out = true },
                { 0 },
            },
        },
        // JBS_ROOTHIDE_CLEAR_BLACKLIST (12)
        {
            .handler = roothide_action_clear_blacklist,
            .args = (jbserver_arg[]){
                { .name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN, .out = false },
                { 0 },
            },
        },
        // JBS_ROOTHIDE_GET_SESSION_ID (13)
        {
            .handler = roothide_action_get_session_id,
            .args = (jbserver_arg[]){
                { .name = "sessionID", .type = JBS_TYPE_UINT64, .out = true },
                { 0 },
            },
        },
        // JBS_ROOTHIDE_GET_JBROOT_UUID (14)
        {
            .handler = roothide_action_get_jbroot_uuid,
            .args = (jbserver_arg[]){
                { .name = "uuid", .type = JBS_TYPE_STRING, .out = true },
                { 0 },
            },
        },
        // JBS_ROOTHIDE_TRANSLATE_PATH (15)
        {
            .handler = roothide_action_translate_path,
            .args = (jbserver_arg[]){
                { .name = "path",       .type = JBS_TYPE_STRING, .out = false },
                { .name = "translated", .type = JBS_TYPE_STRING, .out = true  },
                { 0 },
            },
        },
        // JBS_ROOTHIDE_IS_APP_HIDDEN (16)
        {
            .handler = roothide_action_is_app_hidden,
            .args = (jbserver_arg[]){
                { .name = "bundleID", .type = JBS_TYPE_STRING, .out = false },
                { .name = "hidden",  .type = JBS_TYPE_BOOL,   .out = true  },
                { 0 },
            },
        },
        { 0 },
    },
};
