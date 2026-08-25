// roothide_systemhook_shims.c
//
// RootHide port (Relaxin upstream): shims for symbols referenced by the
// Relaxin systemhook roothider_main.c that are NOT implemented natively in
// Kernel-JB's systemhook:
//
//   - __posix_spawn_orig  — Kernel-JB's common/common.h declares it but
//                           no .c file implements it. Relaxin's common.c:84
//                           implements it as syscall(SYS_posix_spawn, ...).
//
//   - __execve_orig       — same situation; Relaxin's common.c:92 implements
//                           it as syscall(SYS_execve, ...).
//
//   - spawn_config_for_executable — Kernel-JB's common/common.c:121 declares
//                           it as `static`, so it's invisible to other
//                           translation units (roothider_main.c references
//                           it). Relaxin's version is non-static.
//
// Rather than modify Kernel-JB's common.c (which would change the visibility
// of an existing internal helper), this shim file provides new implementations
// that the linker can resolve.

#include <sys/syscall.h>
#include <spawn.h>
#include <string.h>
#include <stdlib.h>
#include <xpc/xpc.h>

// Relaxin's kSpawnConfig values (must match common/common.h's enum):
//   kSpawnConfigInject        = 1 << 0
//   kSpawnConfigTrust         = 1 << 1
//   kSpawnConfigPatchProcess  = 1 << 2  (defined as macro in wrapper common.h)
//
// We use raw integer arithmetic here to avoid pulling in the kSpawnConfig enum
// (which might differ between Kernel-JB and Relaxin).

// Shim: __posix_spawn_orig — invoke the underlying posix_spawn syscall directly.
// This is what Relaxin's common.c:84-90 does.
struct _posix_spawn_args_desc;
int __posix_spawn_orig(pid_t *restrict pid,
                       const char *restrict path,
                       struct _posix_spawn_args_desc *desc,
                       char *const argv[restrict],
                       char *const envp[restrict]) {
    return syscall(SYS_posix_spawn, pid, path, desc, argv, envp);
}

// Shim: __execve_orig — invoke the underlying execve syscall directly.
int __execve_orig(const char *path, char *const argv[], char *const envp[]) {
    return syscall(SYS_execve, path, argv, envp);
}

// Shim: spawn_config_for_executable — non-static re-export of the helper.
// Kernel-JB's common.c has a static version; we provide a non-static wrapper
// that delegates to a local implementation (matching Relaxin's semantics).
//
// Returns a bitmask:
//   bit 0 (kSpawnConfigInject)        — set if path is not blacklisted
//   bit 1 (kSpawnConfigTrust)         — always set in our port (trust everything;
//                                        Relaxin gates this on bundle path checks)
//   bit 2 (kSpawnConfigPatchProcess)  — always set in our port (Relaxin gates
//                                        this on the executable being patchable)
//
// This conservative bitmask means "always inject + always trust + always patch"
// which is the previous behavior of Kernel-JB's existing systemhook before the
// Relaxin port. A future commit will port Relaxin's full spawn_config_for_executable
// logic (including its xpc_dictionary_get_value("ProcessBlacklist") user-config
// check) once the appropriate header plumbing is in place.
int spawn_config_for_executable(const char *path, char *const argv[restrict]) {
    (void)argv;
    if (!path) return 0;

    // Minimal blacklist matching Relaxin's defaults — prevents crashes for
    // processes that are known to misbehave when injected.
    static const char *kBlacklist[] = {
        "/System/Library/Frameworks/GSS.framework/Helpers/GSSCred",
        "/System/Library/PrivateFrameworks/DataAccess.framework/Support/dataaccessd",
        "/System/Library/PrivateFrameworks/IDSBlastDoorSupport.framework/XPCServices/IDSBlastDoorService.xpc/IDSBlastDoorService",
        "/System/Library/PrivateFrameworks/MessagesBlastDoorSupport.framework/XPCServices/MessagesBlastDoorService.xpc/MessagesBlastDoorService",
    };
    for (size_t i = 0; i < sizeof(kBlacklist)/sizeof(kBlacklist[0]); i++) {
        if (strcmp(kBlacklist[i], path) == 0) return 0;
    }

    // Default: inject + trust + patch (all three bits set).
    return (1 << 0) | (1 << 1) | (1 << 2);
}
