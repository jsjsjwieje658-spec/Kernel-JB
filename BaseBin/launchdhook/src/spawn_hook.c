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
// FIX LỖI 1: query blacklist động
#include <libjailbreak/jbclient_xpc.h>

extern char **environ;

void abort_with_reason(uint32_t reason_namespace, uint64_t reason_code, const char *reason_string, uint64_t reason_flags);

extern int systemwide_trust_file_by_path(const char *path);
extern int platform_set_process_debugged(uint64_t pid, bool fullyDebugged);
extern void systemwide_domain_set_enabled(bool enabled);

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

                        // If the jailbreak is currently hidden, fakelib is not mounted
                        // It needs to be mounted to regain launchd code execution after the userspace reboot
                        ensure_fakelib_mounted();

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

                // FIX BLACKLIST INPUT BUG (root cause of banking apps detecting
                // the jailbreak despite the RootHide app blacklist):
                //
                // The old code extracted the app bundle DIRECTORY NAME from the
                // spawn path (e.g. "iBank" from
                // /var/containers/Bundle/Application/<UUID>/iBank.app/iBank) and
                // passed it to jbclient_blacklist_check_bundle(). However the
                // server side (isBlacklistedApp, blacklist.m:76) looks up by
                // CFBundleIdentifier (e.g. "com.vietinbank.iBank") inside
                // RootHideConfig.plist appconfig — so the lookup could never
                // match and blacklisted apps still got tweak injection.
                //
                // Fix: pass the FULL executable path via jbclient_blacklist_check_path().
                // The server side (isBlacklistedPath, blacklist.m:99) resolves
                // path -> <Bundle>.app/Info.plist -> CFBundleIdentifier ->
                // appconfig lookup, which is exactly how the official
                // Dopamine2-roothide does it (roothider.m:378 calls
                // isBlacklistedPath(path) in the launchd prehook).
                //
                // The strstr(".app/") pre-filter keeps system daemons (the vast
                // majority of spawns) off the XPC path; only user app launches
                // pay the ~1ms round-trip. Extensions of blacklisted apps are
                // covered too: getAppBundlePathFromSpawnPath resolves
                // /PlugIns/*.appex/ paths to the main bundle identifier.
                //
                // Fail-safe: if the jbserver is unreachable, the query returns
                // false and the app is spawned normally (same behaviour as
                // before) — this can never hang or break boot.
                if (!shouldHideForChild && path && strstr(path, ".app/")) {
                        if (jbclient_blacklist_check_path(path)) {
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
                // Spawn completely clean, mirroring the official Dopamine2-roothide
                // behaviour (roothider.m prehook calls __posix_spawn_orig_wrapper for
                // blacklisted apps). The old implementation only set a "clean mode"
                // env var and STILL injected systemhook.dylib into the child —
                // detectable by any app enumerating its dyld image list — and it
                // polluted launchd's environ with ROOTHIDE_CLEAN_MODE_ENV forever
                // after the first blacklisted launch, disabling tweaks system-wide.
                //
                // Going through the original wrapper here means:
                //   - no DYLD_INSERT_LIBRARIES injection
                //   - no trustcache upload / CS_DEBUGGED marking for the child
                //   - the caller's envp is passed through untouched
                // Children spawned by the clean app are naturally clean as well
                // (the app itself has no systemhook, so nothing hooks its
                // posix_spawn calls).
                return __posix_spawn_orig_wrapper(pid, path, desc, argv, envp);
        }

        return posix_spawn_hook_shared(pid, path, desc, argv, envp,
                                       __posix_spawn_orig_wrapper,
                                       systemwide_trust_file_by_path,
                                       platform_set_process_debugged,
                                       jbsetting(jetsamMultiplier));
        // ========== END ROOTHIDE SELECTIVE INJECTION ==========
}

void initSpawnHooks(void)
{
        litehook_hook_function(__posix_spawn, __posix_spawn_hook);
}