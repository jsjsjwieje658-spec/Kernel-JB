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
        // RootHide port (CRITICAL FIX): COMMENTED OUT to match Dopamine2-roothide.
        //
        // The Dopamine2-roothide reference implementation has this entire function
        // commented out. The reason:
        //
        //   setenv("DOPAMINE_IS_HIDDEN", "1", true);
        //
        // sets an environment variable on launchd's environ. Because launchd is
        // pid 1 and the parent of EVERY process on the system, every spawned
        // process INHERITS this env var unless explicitly unset. The spawn_hook
        // in this file tries to unset it on the child envp before posix_spawn,
        // but that only works for the immediate child — grandchildren spawned by
        // the child via posix_spawn_hook_shared will re-inherit it from the
        // child's environ (which still has it).
        //
        // Banking apps that read /proc/self/environ via sysctl(KERN_PROCARGS2)
        // or via proc_pidinfo(PROC_PIDPATHINFO) + manual environ parsing can
        // detect the presence of DOPAMINE_IS_HIDDEN and flag the device as
        // jailbroken. The env var name is unique enough that no legitimate iOS
        // process would ever set it.
        //
        // The fakelib mount itself (which is what ensure_fakelib_mounted is
        // trying to set up before userspace reboot) is already handled by the
        // jailbreak flow in DOJailbreaker.m::createFakeLib, which mounts
        // fakelib BEFORE the userspace reboot happens. The post-reboot
        // re-mount that this function was doing was only needed in the
        // original Dopamine (non-roothide) to handle the case where the
        // jailbreak was "hidden" (fakelib unmounted) before the reboot.
        //
        // In the roothide port, we never "hide" the jailbreak by unmounting
        // fakelib — we hide it by NOT injecting into blacklisted apps. So
        // ensure_fakelib_mounted is dead code, and the DOPAMINE_IS_HIDDEN
        // env var it sets is a pure leak vector.
        //
        // Match Dopamine2-roothide: leave the function defined but empty
        // (callers still reference it, so we can't just delete it without
        // also editing the call site in __posix_spawn_hook below).
#if 0
        struct statfs fsb;
        if (statfs("/usr/lib", &fsb) != 0) return;
        if (strcmp(fsb.f_mntonname, "/usr/lib") != 0) {
                systemwide_domain_set_enabled(true);

                // The jailbreak server is not reachable at this point in the launchd lifecycle
                // So we need to host our own, just so that jb ctl can talk to it
                mach_port_t serverPort = jbserver_local_start();
                jbctl_earlyboot(serverPort, "internal", "fakelib", "mount", NULL);
                jbserver_local_stop();

                // Note down that the jailbreak was hidden
                // So that after the userspace reboot, we can unmount fakelib again
                setenv("DOPAMINE_IS_HIDDEN", "1", true);
        }
#endif
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

        // ========== ROOTHIDE ENVIRONMENT PROPAGATION ==========
        // Check if the spawned process should run in clean mode
        // This is the key mechanism for RootHide's selective injection
        bool shouldHideForChild = false;

        // FIX BUG #28: defer roothide_init() đến khi launchd XPC server đã up.
        // Trước đây roothide_init() được gọi ở đây ngay khi launchd spawn bất kỳ
        // process nào, kể cả khi jbserver chưa ready. Khi đó get_jbroot() trả về
        // NULL → fallback "/private/preboot" → g_roothide.base_jbroot bị set
        // sai → mọi check should_hide_path() sau đó fail.
        //
        // Fix: chỉ init sau early_boot_done (sau khi thấy xpcproxy spawn).
        // Trước đó, không check blacklist (trả về shouldHideForChild=false).
        //
        // RootHide port: the old `roothide_init()` call has been removed because
        // the patchwork libjailbreak/src/roothide.c was deleted. The Relaxin
        // upstream equivalent (`roothider/common.m::roothide_patch_proc`,
        // `roothider/main.m::roothide_init_with_checkin`) is invoked from the
        // Relaxin launchdhook roothider.m (roothide_launchd_preinit / postinit)
        // at process startup. We retain only the env-var propagation + the
        // dynamic `jbclient_blacklist_check_bundle()` lookup below.
        if (!gInEarlyBoot) {

                // Check if current process is already in clean mode (propagate to children)
                if (getenv(ROOTHIDE_CLEAN_MODE_ENV)) {
                        const char *parentCleanMode = getenv(ROOTHIDE_CLEAN_MODE_ENV);
                        if (parentCleanMode && strcmp(parentCleanMode, "1") == 0) {
                                shouldHideForChild = true;
                        }
                }

                // FIX LỖI 1 (bonus): nếu path có chứa app name (vd /var/containers/Bundle/Application/.../Foo.app/Foo)
                // thì cũng check blacklist động để đảm bảo app banking/detection được skip injection
                // kể cả khi parent chưa set env var (vd SpringBoard launch trực tiếp).
                if (!shouldHideForChild && path && strstr(path, ".app/")) {
                        // Extract bundle ID từ path: lấy substring giữa "/" cuối cùng trước ".app/" và "/<binary>" sau .app/
                        char bundleBuf[256];
                        const char *appMarker = strstr(path, ".app/");
                        if (appMarker) {
                                // Tìm "/" trước ".app/"
                                const char *p = appMarker - 1;
                                while (p >= path && *p != '/') p--;
                                if (p >= path && *p == '/') {
                                        p++; // skip '/'
                                        size_t len = appMarker - p;
                                        if (len > 0 && len < sizeof(bundleBuf)) {
                                                memcpy(bundleBuf, p, len);
                                                bundleBuf[len] = '\0';
                                                // Query động blacklist
                                                // Chỉ dùng nếu launchd đã up (đã check ở trên)
                                                // RootHide port: switched from jbclient_roothide_is_blacklisted (old patchwork API)
                                                // to jbclient_blacklist_check_bundle (Relaxin upstream API, declared in jbclient_xpc.h).
                                                if (jbclient_blacklist_check_bundle(bundleBuf)) {
                                                        shouldHideForChild = true;
                                                }
                                        }
                                }
                        }
                }
        }

        // If we need to hide this child, modify envp to include clean mode flag
        // We do this by using environ instead of envp and setting the env var
        if (shouldHideForChild) {
#if LOG_PROCESS_LAUNCHES
                FILE *f = fopen("/var/mobile/launch_log.txt", "a");
                fprintf(f, "RootHide: Hiding child process %s\n", path);
                fclose(f);
#endif
                setenv(ROOTHIDE_CLEAN_MODE_ENV, "1", 1); // Propagate to child
        }

        // FIX BUG #23 + #propagation: trước đây setenv(ROOTHIDE_CLEAN_MODE_ENV)
        // được gọi trên `environ` của launchd, nhưng posix_spawn_hook_shared vẫn
        // truyền `envp` gốc → child KHÔNG thấy env var → app banking vẫn được
        // inject tweak → crash.
        //
        // Fix:
        // 1) Nếu shouldHideForChild=true → truyền envp=NULL để spawn dùng environ
        //    (đã có ROOTHIDE_CLEAN_MODE_ENV=1 set ở trên).
        // 2) Tạm thời unset DOPAMINE_IS_HIDDEN trên environ để child không thấy
        //    env var này (anti-detection). Sau spawn, set lại để launchd giữ state.
        bool isHidden = (getenv("DOPAMINE_IS_HIDDEN") != NULL);
        const char *hiddenVal = isHidden ? strdup(getenv("DOPAMINE_IS_HIDDEN")) : NULL;
        if (isHidden) {
                unsetenv("DOPAMINE_IS_HIDDEN");
        }
        char *const *childEnvp = shouldHideForChild ? NULL : envp;
        int r = posix_spawn_hook_shared(pid, path, desc, argv, childEnvp,
                                       __posix_spawn_orig_wrapper,
                                       systemwide_trust_file_by_path,
                                       platform_set_process_debugged,
                                       jbsetting(jetsamMultiplier));
        // Restore launchd env (cho launchd tiếp tục biết trạng thái hide)
        if (isHidden && hiddenVal) {
                setenv("DOPAMINE_IS_HIDDEN", hiddenVal, 1);
                free((void *)hiddenVal);
        }
        return r;
        // ========== END ROOTHIDE PROPAGATION ==========
}

void initSpawnHooks(void)
{
        // RootHide port (CRITICAL FIX):
        //
        // The Dopamine2-roothide reference implementation installs the spawn hook by
        // pointing `__posix_spawn` at `roothide_launchd___posix_spawn_prehook` (defined
        // in roothider.m). That prehook implements the *real* spawn-bypass:
        //
        //   if (isBlacklistedPath(path)) {
        //       // BLACKLISTED APP: spawn with __posix_spawn_orig_wrapper (NO injection)
        //       // → banking app process has NO systemhook.dylib in DYLD_INSERT_LIBRARIES
        //       // → banking app sees a completely stock environment, no hooks installed.
        //       __posix_spawn_orig_wrapper(blacklistedPidp, path, desc, argv, envc);
        //       commitBlacklistProcessId(blacklistedPidp);
        //   } else {
        //       // NORMAL APP / DAEMON: spawn through posix_spawn_hook_shared (with injection)
        //       __posix_spawn_hook(pidp, path, desc, argv, envp);
        //   }
        //
        // The previous Kernel-JB code instead installed `__posix_spawn_hook` (the local
        // function in this file) as the hook target. That local function then set
        // ROOTHIDE_CLEAN_MODE_ENV=1 on the child envp but STILL called
        // posix_spawn_hook_shared, which ALWAYS inserts systemhook.dylib into
        // DYLD_INSERT_LIBRARIES. The result was that banking apps got systemhook.dylib
        // injected (with all its hooks: csops, necp_*, posix_spawn, fcntl, dlsym, etc.)
        // AND got the ROOTHIDE_CLEAN_MODE_ENV=1 env var set. The env var caused
        // systemhook's constructor to early-return (so no TweakLoader), but the
        // syscall hooks (posix_spawn, fcntl, sandbox_apply, dlsym, csops, necp_*) were
        // ALREADY installed by the time the env-var check ran — because the env-var
        // check was moved to the TOP of the constructor in commit 1c823a8, but the
        // dyldhook (which installs csops/necp_* hooks at the dyld level, BEFORE
        // systemhook.dylib is even loaded) had already installed its hooks.
        //
        // The net effect: banking apps could still detect the jailbreak by:
        //   - Reading /proc/self/environ and seeing ROOTHIDE_CLEAN_MODE_ENV (leak)
        //   - Calling csops(getpid(), CS_OPS_STATUS, ...) and seeing CS_DEBUGGED flipped
        //   - Calling sysctl(KERN_BOOT_ARGS, ...) and seeing modified bootargs
        //   - Comparing dlsym(RTLD_DEFAULT, "csops") vs dlsym(RTLD_NEXT, "csops")
        //   - Listing /usr/lib via getmntinfo and seeing the fakelib bind mount
        //
        // Switching to roothide_launchd___posix_spawn_prehook eliminates ALL of these
        // leak vectors for blacklisted apps because the process never even loads
        // systemhook.dylib.
        //
        // For non-blacklisted processes (system daemons, normal user apps, tweaks)
        // the prehook falls through to __posix_spawn_hook (the local function in this
        // file) which calls posix_spawn_hook_shared — same behavior as before.
        extern int roothide_launchd___posix_spawn_prehook(pid_t *restrict pidp,
                                                          const char *restrict path,
                                                          struct _posix_spawn_args_desc *desc,
                                                          char *const argv[restrict],
                                                          char *const envp[restrict]);
        MSHookFunction(&__posix_spawn, (void *)roothide_launchd___posix_spawn_prehook, NULL);
}