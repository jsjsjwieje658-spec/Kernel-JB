// RootHide port: wrapper that redirects to Kernel-JB's existing common/common.h
// (Kernel-JB has common/ subdir; Relaxin's roothider_*.{c,m} expect common.h at parent level).
//
// IMPORTANT: Kernel-JB's common/common.h defines HOOK_DYLIB_PATH as a macro
// (`#define HOOK_DYLIB_PATH "/usr/lib/systemhook.dylib"`). Relaxin's
// roothider_main.c declares HOOK_DYLIB_PATH as a runtime variable
// (`const char *HOOK_DYLIB_PATH = NULL;` then assigns at init). These
// conflict at the preprocessor level. To bridge:
//   1. Include common/common.h (which defines the macro).
//   2. #undef HOOK_DYLIB_PATH (so the macro doesn't replace the variable name).
//   3. Declare `extern const char *HOOK_DYLIB_PATH;` so files including this
//      wrapper see it as an extern variable. The actual definition lives in
//      roothider_main.c.
//   4. Add Relaxin's kSpawnConfig enum (referenced by roothider_main.c).
//
// NOTE: Kernel-JB's own common/common.c and main.c continue to include
// common/common.h directly (not this wrapper), so they still see HOOK_DYLIB_PATH
// as the macro. This means common.c and roothider_main.c have DIFFERENT views of
// HOOK_DYLIB_PATH — common.c uses the compile-time string literal, while
// roothider_main.c uses the runtime variable. The linker resolves main.c's
// references to the variable (defined in roothider_main.c), and common.c's
// references resolve to the inline string literal. This dual-view is a known
// limitation of the partial port and should be cleaned up in a future commit
// by either (a) making HOOK_DYLIB_PATH a runtime variable everywhere, or
// (b) removing the variable assignment in roothider_main.c.
#ifndef KJ_SYSTEMHOOK_COMMON_WRAPPER_H
#define KJ_SYSTEMHOOK_COMMON_WRAPPER_H

#include "common/common.h"

// Undef the macro so roothider_main.c can declare HOOK_DYLIB_PATH as a variable.
#undef HOOK_DYLIB_PATH

// Declare HOOK_DYLIB_PATH as an extern variable (defined in roothider_main.c).
extern const char *HOOK_DYLIB_PATH;

// NOTE: kSpawnConfig enum (kSpawnConfigInject, kSpawnConfigTrust) is inherited
// from common/common.h via the #include above. Kernel-JB's common/common.h
// does NOT define kSpawnConfigPatchProcess (the third Relaxin enum value
// needed by roothider_main.c:268). Define it here as a macro so it doesn't
// conflict with the typedef in common/common.h.
#ifndef kSpawnConfigPatchProcess
#define kSpawnConfigPatchProcess (1 << 2)
#endif

#endif
