// RootHide port: wrapper that redirects to Kernel-JB's existing common/common.h
// (Kernel-JB has common/ subdir; Relaxin's roothider_*.{c,m} expect common.h at parent level).
//
// Build 3 update: HOOK_DYLIB_PATH is now declared as an extern runtime
// variable directly inside common/common.h (the "/usr/lib/systemhook.dylib"
// macro is gone). This wrapper therefore no longer needs the #undef dance —
// files including it simply see the extern declaration. The runtime
// definition lives in roothider_main.c (systemhook) / roothider.m (launchdhook).
#ifndef KJ_SYSTEMHOOK_COMMON_WRAPPER_H
#define KJ_SYSTEMHOOK_COMMON_WRAPPER_H

#include "common/common.h"

// NOTE: kSpawnConfigPatchProcess is not part of Kernel-JB's kSpawnConfig enum
// in common/common.h (the third Relaxin value needed by roothider_main.c:268).
// Define it here as a macro so it doesn't conflict with the typedef.
#ifndef kSpawnConfigPatchProcess
#define kSpawnConfigPatchProcess (1 << 2)
#endif

#endif
