// RootHide Manager app fix (Kernel-JB).
//
// ROOT CAUSE (reverse-engineered from the shipped RootHide Manager 1.3.9 binary,
// both arm64 and arm64e slices produce identical logic):
//
//   +[AppDelegate getDefaultsForKey:] (imp 0x100007dfc arm64 / 0x1000074d8 arm64e)
//   reads <jbroot>/var/mobile/Library/RootHide/RootHideConfig.plist with
//   +[NSDictionary dictionaryWithContentsOfFile:] — which ALWAYS returns an
//   IMMUTABLE NSDictionary — and returns [dict objectForKey:key] verbatim.
//
//   -[BlacklistViewController switchChanged:] (crash PC RootHide+62236 = 0xF31C
//   in the .ips, inside the imp at 0x10000ed84 arm64) does:
//       x22 = [AppDelegate getDefaultsForKey:@"appconfig"];
//       if (!x22) x22 = [NSMutableDictionary dictionary];   // only when nil!
//       [x22 setObject:[NSNumber numberWithBool:sw.isOn]
//               forKey:app.bundleIdentifier];                // ← CRASH
//       [AppDelegate setDefaults:x22 forKey:@"appconfig"];
//
//   When the config file EXISTS (Kernel-JB seeds an empty appconfig plist on
//   first jailbreak via DOJailbreaker seedRootHideConfigIfAbsent), x22 is the
//   immutable NSDictionary sub-object and setObject:forKey: hits
//   ___forwarding___ → objc_exception_throw → SIGABRT ("abort() called").
//   When the file does NOT exist, x22 is nil, the nil-fallback produces a
//   mutable dictionary and the toggle works — which is exactly why the crash
//   only appeared after Kernel-JB started seeding the plist.
//
// FIX (server-side, no app binary modification): swizzle
// +[AppDelegate getDefaultsForKey:] to return a MUTABLE dictionary for
// dictionary values. The manager then mutates the copy and setDefaults:forKey:
// writes it back with writeToFile:atomically: — the file keeps its format, so
// libjailbreak's isBlacklistedApp() (blacklist.m) parses it unchanged.
//
// This hook lives in roothidehooks.dylib (loaded into the manager app from
// systemhook's constructor), keeping the change out of every other process.
// The hook is registered only when the process is actually the RootHide
// Manager (see main.m / systemhook main.c gate), so the class hook is a no-op
// everywhere else — AppDelegate only exists in that app anyway.

#import <Foundation/Foundation.h>
#import <objc/runtime.h>

#import "Hooking.h"
#import "common.h"

// The manager app's own class. Resolved late: the app binary's classes are
// registered by the ObjC runtime before any constructor runs, but we must not
// reference the symbol statically (it does not exist in other processes).
CHDeclareClass(AppDelegate);

// NOTE on the mutable-copy semantics: the original implementation returns the
// object stored in the plist (possibly a nested NSDictionary under "appconfig"
// or a NSNumber under "blacklistDisabled"). switchChanged: mutates the returned
// dictionary and passes it straight to setDefaults:forKey: — so converting the
// nested dictionaries to NSMutableDictionary here is exactly what the app
// expects and preserves every other key/value pair on write-back.
CHClassMethod1(id, AppDelegate, getDefaultsForKey, NSString *, key) {
    id value = CHSuper1(AppDelegate, getDefaultsForKey, key);
    if ([value isKindOfClass:[NSDictionary class]] &&
        ![value isKindOfClass:[NSMutableDictionary class]]) {
        value = [NSMutableDictionary dictionaryWithDictionary:value];
    }
    return value;
}

void rootHideManagerInit(void)
{
    Class appDelegateClass = objc_getClass("AppDelegate");
    if (!appDelegateClass) {
        // Not the RootHide Manager process (defensive: the caller already
        // gates on the executable path, but keep the hook harmless even if
        // the gate changes later).
        RHLogDebug(@"rootHideManagerInit: AppDelegate not found, skipping");
        return;
    }

    // Guard against double registration (constructor re-entry, reload etc.)
    Method orig = class_getClassMethod(appDelegateClass, @selector(getDefaultsForKey:));
    if (!orig) {
        RHLogDebug(@"rootHideManagerInit: getDefaultsForKey: not found, skipping");
        return;
    }
    static BOOL alreadyHooked = NO;
    if (alreadyHooked) return;
    alreadyHooked = YES;

    CHLoadLateClass(AppDelegate);
    CHClassHook1(AppDelegate, getDefaultsForKey);
    RHLogDebug(@"rootHideManagerInit: getDefaultsForKey: hooked (mutable fix)");
}
