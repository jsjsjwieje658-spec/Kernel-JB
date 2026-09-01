#include <spawn.h>
#include "../systemhook/src/common/common.h"
#include "boomerang.h"
#include "crashreporter.h"
#include "update.h"
#include <libjailbreak/util.h>
#include <substrate.h>
#include <mach-o/dyld.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <litehook.h>
#include "jbserver/jbserver_local.h"
#include "hookd_provider.h"
// RootHide integration for selective injection
#include <libjailbreak/libjailbreak.h>
// Env buffer manipulation (strip jailbreak env vars from blacklisted apps)
#include "../systemhook/src/envbuf.h"

// RootHide: isBlacklistedPath() — direct call inside launchd (no XPC round-trip).
// Defined in roothider/blacklist.m, linked via libjailbreak.dylib.
// Forward-declared here to avoid pulling roothider.h which conflicts with
// launchdhook's own crashreporter.h (both define kCrashReporterStateActive).
extern bool isBlacklistedPath(const char *path);
// PID-based blacklist tracking (roothider/blacklist.cpp)
extern pid_t *allocBlacklistProcessId(void);
extern void commitBlacklistProcessId(pid_t *pidp);

extern char **environ;

void abort_with_reason(uint32_t reason_namespace, uint64_t reason_code, const char *reason_string, uint64_t reason_flags);

extern int systemwide_trust_file_by_path(const char *path);
extern int platform_set_process_debugged(uint64_t pid, bool fullyDebugged);
extern void systemwide_domain_set_enabled(bool enabled);
// RootHide port (Relaxin upstream, roothider.m:197-199): recursive trust for
// spawned binaries. When called the function walks the executable AND its
// dependency tree, normalizes signatures (roothide randomized-cdhash scheme)
// and adds every missing cdhash to the kernel trustcache. This is what makes
// dev-cert signed apps survive AMFI (the flat systemwide trust only covered
// the main binary and never normalized anything).
//
// Safety notes (Build 2):
// - The return value of trust_binary is IGNORED by posix_spawn_hook_shared,
//   so a failed trust can never block a spawn -> no boot-hang vector.
// - Apple system daemons live on the sealed FS: signature normalization
//   attempts fail with EROFS and are skipped; those daemons are covered by
//   Apple's static trustcache exactly as before.
// - Everything runs locally inside launchd (no XPC, no jailbreakd needed):
//   roothide_trust_executable_recurse lives in jbdomain_roothide.c which is
//   compiled into launchdhook.dylib, and its callees (recurse_collect_
//   untrusted_cdhashes, ensure_randomized_cdhash_for_slice, is_cdhash_
//   trustcached, jb_trustcache_add_cdhashes) are the same libjailbreak
//   functions the flat flow already exercises on every boot.
extern int roothide_launchd_trust_executable(const char *path);

#define LOG_PROCESS_LAUNCHES 0

extern bool gInEarlyBoot;
extern bool gFreeBootLogoBeforeBackboardd;
void free_boot_logo(void);

// RootHide port: the old `g_roothide_initialized` static bool has been removed.
// In the Relaxin upstream fork, per-process init is handled by `roothider.m`
// (roothide_launchd_preinit / roothide_launchd_postinit) at launchd start.

void early_boot_done(void)
{
        gInEarlyBoot = false;
}

void ensure_fakelib_mounted(void)
{
        struct statfs fsb;
        if (statfs("/usr/lib", &fsb) != 0) return;
        if (strcmp(fsb.f_mntonname, "/usr/lib") != 0) {
                systemwide_domain_set_enabled(true);

                // The jailbreak server is not reachable at this point in the launchd lifecycle
                // So we need to host our own, just so that jbctl can talk to it
                mach_port_t serverPort = jbserver_local_start();
                jbctl_earlyboot(serverPort, "internal", "fakelib", "mount", NULL);
                jbserver_local_stop();

                // Note down that the jailbreak was hidden
                // So that after the userspace reboot, we can unmount fakelib again
                setenv("DOPAMINE_IS_HIDDEN", "1", true);
        }
}

int __posix_spawn_orig_wrapper(pid_t *restrict pid, const char *restrict path,
                                           struct _posix_spawn_args_desc *desc,
                                           char *const argv[restrict],
                                           char *const envp[restrict])
{
        // we need to disable the crash reporter during the orig call
        // otherwise the child process inherits the exception ports
        // and this would trip jailbreak detections
        crashreporter_pause();  
        int r = __posix_spawn_inline(pid, path, desc, argv, envp);
        crashreporter_resume();

        return r;
}

int __posix_spawn_hook(pid_t *restrict pid, const char *restrict path,
                                           struct _posix_spawn_args_desc *desc,
                                           char *const argv[restrict],
                                           char *const envp[restrict])
{
        if (path) {
                char executablePath[1024];
                uint32_t bufsize = sizeof(executablePath);
                _NSGetExecutablePath(&executablePath[0], &bufsize);
                if (!strcmp(path, executablePath)) {
                        // This spawn will perform a userspace reboot...
                        // Instead of the ordinary hook, we want to reinsert this dylib
                        // This has already been done in envp so we only need to call the original posix_spawn

                        // We are back in "early boot" for the remainder of this launchd instance
                        // Mainly so we don't lock up while spawning boomerang
                        gInEarlyBoot = true;

                        hookd_provider_teardown();

                        // RootHide port Build 3: the fakelib bindfs mount is GONE. The patched
                        // dyld published into /usr/lib via kernel namecache injection survives
                        // the userspace reboot (the namecache is kernel state), so the new
                        // launchd still honors DYLD_INSERT_LIBRARIES and re-injects
                        // launchdhook.dylib without any mount. Re-mounting here would recreate
                        // the "Unknown Bindfs Mount(s)" detection vector this build removes.
                        // ensure_fakelib_mounted();

#if LOG_PROCESS_LAUNCHES
                        FILE *f = fopen("/var/mobile/launch_log.txt", "a");
                        fprintf(f, "==== USERSPACE REBOOT ====\n");
                        fclose(f);
#endif

                        // Before the userspace reboot, we want to stash the primitives into boomerang
                        boomerang_stashPrimitives();

                        // Fix Xcode debugging being broken after the userspace reboot
                        unmount("/Developer", MNT_FORCE);

                        // If there is a pending jailbreak update, apply it now
                        const char *stagedJailbreakUpdate = getenv("STAGED_JAILBREAK_UPDATE");
                        if (stagedJailbreakUpdate) {
                                int r = jbupdate_basebin(stagedJailbreakUpdate);
                                if (r != 0) {
                                        char msg[1000];
                                        snprintf(msg, 1000, "Failed updating basebin (error %d).", r);
                                        abort_with_reason(7, 1, msg, 0);
                                }
                                unsetenv("STAGED_JAILBREAK_UPDATE");
                        }

                        // Always use environ instead of envp, as boomerang_stashPrimitives calls setenv
                        // setenv / unsetenv can sometimes cause environ to get reallocated
                        // In that case envp may point to garbage or be empty
                        // Say goodbye to this process
                        return __posix_spawn_orig_wrapper(pid, path, desc, argv, environ);
                }
        }

#if LOG_PROCESS_LAUNCHES
        if (path) {
                FILE *f = fopen("/var/mobile/launch_log.txt", "a");
                fprintf(f, "%s", path);
                int ai = 0;
                while (argv) {
                        if (argv[ai]) {
                                if (ai >= 1) {
                                        fprintf(f, " %s", argv[ai]);
                                }
                                ai++;
                        }
                        else {
                                break;
                        }
                }
                fprintf(f, "\n");
                fclose(f);

                // if (!strcmp(path, "/usr/libexec/xpcproxy")) {
                //      const char *tmpBlacklist[] = {
                //              "com.apple.logd"
                //      };
                //      size_t blacklistCount = sizeof(tmpBlacklist) / sizeof(tmpBlacklist[0]);
                //      for (size_t i = 0; i < blacklistCount; i++)
                //      {
                //              if (!strcmp(tmpBlacklist[i], firstArg)) {
                //                      FILE *f = fopen("/var/mobile/launch_log.txt", "a");
                //                      fprintf(f, "blocked injection %s\n", firstArg);
                //                      fclose(f);
                //                      return __posix_spawn_orig_wrapper(pid, path, file_actions, desc, envp);
                //              }
                //      }
                // }
        }
#endif

        // We can't support injection into processes that get spawned before the launchd XPC server is up
        // (Technically we could but there is little reason to, since it requires additional work)
        if (gInEarlyBoot) {
                if (!strcmp(path, "/usr/libexec/xpcproxy")) {
                        // The spawned process being xpcproxy indicates that the launchd XPC server is up
                        // All processes spawned including this one should be injected into
                        early_boot_done();
                }
                else {
                        return __posix_spawn_orig_wrapper(pid, path, desc, argv, envp);
                }
        }

        // If we're drawing a boot logo, free up it's resources before backboardd starts
        if (gFreeBootLogoBeforeBackboardd) {
                if (!strcmp(path, "/usr/libexec/xpcproxy")) {
                        if (argv[0]) {
                                if (argv[1]) {
                                        // FIX BUG #4: typo "com.apple.backboardd\n" → "com.apple.backboardd"
                                        // Trước đây: strcmp luôn fail → free_boot_logo() không bao giờ gọi
                                        // → boot logo memory leak, có thể gây hiện tượng glow/stuck màn hình.
                                        if (!strcmp(argv[1], "com.apple.backboardd")) {
                                                free_boot_logo();
                                                gFreeBootLogoBeforeBackboardd = false;
                                        }
                                }
                        }
                }
        }

        // ========== ROOTHIDE SELECTIVE INJECTION ==========
        // Decide whether this child should be spawned completely clean (no
        // systemhook injection, no jailbreak-related env modifications).
        bool shouldHideForChild = false;

        // FIX BUG #28: defer any roothide logic until the launchd XPC server is
        // up (i.e. after early_boot_done / first xpcproxy spawn). Before that,
        // the jbserver is not reachable, so blacklist queries would fail anyway.
        //
        // RootHide port: per-process init is handled by the Relaxin launchdhook
        // roothider.m (roothide_launchd_preinit / postinit). We retain only the
        // env-var propagation check + the dynamic blacklist lookup below.
        if (!gInEarlyBoot) {

                // Check if current process is already in clean mode (propagate to children)
                if (getenv(ROOTHIDE_CLEAN_MODE_ENV)) {
                        const char *parentCleanMode = getenv(ROOTHIDE_CLEAN_MODE_ENV);
                        if (parentCleanMode && strcmp(parentCleanMode, "1") == 0) {
                                shouldHideForChild = true;
                        }
                }

                // RootHide port (Dopamine2-roothide parity): DIRECT blacklist
                // check — calls isBlacklistedPath(path) in-process. This
                // function lives in roothider/blacklist.m compiled into
                // launchdhook.dylib. It reads RootHideConfig.plist from disk
                // and resolves path → Info.plist → CFBundleIdentifier → appconfig.
                //
                // SAFETY: We do NOT use jbclient_blacklist_check_path() here
                // because that would send an XPC message to the jbserver,
                // which also runs inside launchd — a synchronous self-XPC
                // call inside a posix_spawn hook causes XPC deadlock on some
                // iOS versions (launchd's XPC dispatch cannot re-enter).
                // Direct call is both faster and crash-free.
                if (!shouldHideForChild && path && strstr(path, ".app/")) {
                        if (isBlacklistedPath(path)) {
                                shouldHideForChild = true;
                        }
                }
        }

        if (shouldHideForChild) {
#if LOG_PROCESS_LAUNCHES
                FILE *f = fopen("/var/mobile/launch_log.txt", "a");
                fprintf(f, "RootHide: Spawning clean (no injection): %s\n", path);
                fclose(f);
#endif
                // Spawn completely clean: strip ALL jailbreak env vars so the
                // banking app sees a fully stock environment.  Without this,
                // launchd's persistently set env vars (DYLD_INSERT_LIBRARIES,
                // DOPAMINE_INITIALIZED, LAUNCHD_UUID) leak into the child,
                // enabling detection via getenv() and _dyld_image_count().
                //
                // Parity with Dopamine2-roothide (roothider.m:395-399) which
                // creates envc = envbuf_mutcopy(envp) and strips _SafeMode /
                // _MSSafeMode.  We extend that to also strip the variables
                // Kernel-JB sets at launchd init (main.m:211-218).
                //
                // CRITICAL: stripping DYLD_INSERT_LIBRARIES means dyld will
                // NOT inject systemhook into the child — the app runs truly
                // clean with no jailbreak dylibs loaded.  Children spawned
                // by the clean app are also clean (no systemhook hooks to
                // intercept their posix_spawn).
                //
                // RootHide port (official roothider.m:409-425 parity): register the
                // clean-spawned child in the blacklist process registry
                // (blacklist.cpp) so that pid-based lookups work for it:
                //   - isBlacklistedPid()/isBlacklistedToken() → used by
                //     roothide_handle_xpc_msg() to filter launchd XPC queries
                //     (service lookups, process info) coming from this app
                //   - jbclient_blacklist_check_pid() → used by the lsd.m /
                //     springboard.m hooks to hide jailbreak URL schemes and
                //     bundle info from this app
                // allocBlacklistProcessId() gives us a pid slot the kernel fills
                // in even when the caller passed pidp=NULL; commit moves it into
                // the pid+pidversion-keyed cache. This runs entirely inside
                // launchd (no XPC, no jailbreakd) — it cannot hang or fail boot.
                {
                        // Create a clean copy of envp with all jailbreak vars stripped
                        char **envc = envbuf_mutcopy((const char **)envp);
                        envbuf_unsetenv(&envc, "DYLD_INSERT_LIBRARIES");
                        envbuf_unsetenv(&envc, "DOPAMINE_INITIALIZED");
                        envbuf_unsetenv(&envc, "LAUNCHD_UUID");
                        envbuf_unsetenv(&envc, "DOPAMINE_IS_HIDDEN");
                        envbuf_unsetenv(&envc, "_SafeMode");
                        envbuf_unsetenv(&envc, "_MSSafeMode");
                        envbuf_unsetenv(&envc, "STAGED_JAILBREAK_UPDATE");
                        envbuf_unsetenv(&envc, "BOOMERANG_PID");
                        envbuf_unsetenv(&envc, "WATCHDOG_PANIC_MESSAGE");

                        volatile pid_t *blacklistedPidp = allocBlacklistProcessId();
                        int ret = __posix_spawn_orig_wrapper((pid_t *)blacklistedPidp, path, desc, argv, envc);
                        pid_t blacklistedPid = *blacklistedPidp;
                        if (pid)
                                *pid = blacklistedPid;
                        commitBlacklistProcessId((pid_t *)blacklistedPidp);
                        blacklistedPidp = NULL;

                        envbuf_free(envc);
                        return ret;
                }
        }

        return posix_spawn_hook_shared(pid, path, desc, argv, envp,
                                       __posix_spawn_orig_wrapper,
                                       // RootHide port (Relaxin spawn_hook.c:97-105):
                                       // recursive trust instead of the flat
                                       // systemwide trust. Fixes dev-cert app
                                       // crashes (dependency tree is trusted and
                                       // signatures get roothide-normalized).
                                       // Keep __posix_spawn_orig_wrapper as orig:
                                       // Relaxin's posthook variant requires
                                       // jailbreakd (jbdSpawnPatchChild) which is
                                       // not built in Kernel-JB — wiring it would
                                       // SIGKILL every spawned process.
                                       roothide_launchd_trust_executable,
                                       platform_set_process_debugged,
                                       jbsetting(jetsamMultiplier));
        // ========== END ROOTHIDE SELECTIVE INJECTION ==========
}

void initSpawnHooks(void)
{
        litehook_hook_function(__posix_spawn, __posix_spawn_hook);
}