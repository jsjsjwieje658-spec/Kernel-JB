// roothide_objc.mm - Objective-C++ implementation of RootHide C++ API
//
// This file provides the C++ function `jbroot(NSString*)` that the RootHide
// app (com.roothide.manager) imports from libroothide.dylib at runtime
// via @loader_path/.jbroot/usr/lib/libroothide.dylib.
//
// The RootHide app is a pre-compiled IPA — we cannot modify it. The only
// way to make it work with our jailbreak is to provide the exact same
// exported symbol it expects: `__Z6jbrootP8NSString` (mangled name of
// `jbroot(NSString*)`).
//
// Implementation:
//   - Calls our internal `get_jbroot()` C function to get the jbroot path.
//   - Wraps the result in an NSString and returns it.
//   - If the input `path` argument is non-nil, prepends the jbroot to it
//     (matching the behavior of the original RootHide jbroot() function,
//     which acts as a path translator).
//   - If `path` is nil, returns just the jbroot path as an NSString.
//
// Compilation:
//   This file MUST be compiled as Objective-C++ (.mm) so that the C++
// name mangling produces the correct symbol `__Z6jbrootP8NSString`.
//   The Makefile should include `src/*.mm` in its source list.

#import <Foundation/Foundation.h>
#include "roothide.h"

// External declaration of the C function that returns the jbroot path.
// Implemented in jbroot.c. Returns NULL if not jailbroken.
extern "C" char *get_jbroot(void);

// C++ function exported for RootHide app compatibility.
// Mangled symbol: __Z6jbrootP8NSString
//
// Behavior matches the original RootHide jbroot(NSString*) function:
//   - If `path` is nil: return the jbroot path as an NSString.
//   - If `path` is non-nil: return jbroot + path (path translation).
//   - If not jailbroken (jbroot is NULL): return nil.
//
// The returned NSString is autoreleased (under ARC) so the caller does
// not need to release it explicitly.
NSString* jbroot(NSString* path) {
    @autoreleasepool {
        const char *jbroot_c = get_jbroot();
        if (!jbroot_c) {
            return nil;
        }
        NSString *jbroot_str = [NSString stringWithUTF8String:jbroot_c];
        if (!jbroot_str) {
            return nil;
        }
        if (path == nil) {
            return jbroot_str;
        }
        // Path translation: prepend jbroot to the input path
        // (e.g., jbroot("/usr/bin/dpkg") -> "/var/containers/Bundle/Application/.jbroot-XXX/usr/bin/dpkg")
        NSString *result = [jbroot_str stringByAppendingPathComponent:path];
        return result;
    }
}
