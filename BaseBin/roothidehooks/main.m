#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#include "common.h"

NSString *safe_getExecutablePath() {
    char executablePathC[PATH_MAX];
    uint32_t executablePathCSize = sizeof(executablePathC);
    _NSGetExecutablePath(&executablePathC[0], &executablePathCSize);
    return [NSString stringWithUTF8String:executablePathC];
}

NSString *getProcessName() {
    return safe_getExecutablePath().lastPathComponent;
}

// RootHide Manager app compatibility hook (Kernel-JB).
//
// The shipped RootHide Manager 1.3.9 binary has an upstream bug:
// +[AppDelegate getDefaultsForKey:] returns the IMMUTABLE NSDictionary read
// from RootHideConfig.plist via dictionaryWithContentsOfFile:, and
// -[BlacklistViewController switchChanged:] calls setObject:forKey: on it →
// unrecognized selector → SIGABRT the moment the user toggles a blacklist
// switch (and the config file exists, which Kernel-JB seeds on first
// jailbreak). See rootmanager.m for the full reverse-engineering write-up.
//
// systemhook only dlopen's roothidehooks.dylib into the manager app when it
// sees the manager executable (see systemhook main.c), so this hook never
// affects any other process.
void rootHideManagerCompatInit(void) {
    NSString *processName = getProcessName();
    if ([processName isEqualToString:@"RootHide"]) {
        extern void rootHideManagerInit(void);
        rootHideManagerInit();
    }
}

__attribute__((constructor)) static void roothideHooksInitialize(void) {
    RHLogDebug(@"roothidehooks initialization status=begin");
    rootHideManagerCompatInit();
    NSString *processName = getProcessName();
    if ([processName isEqualToString:@"cfprefsd"]) {
        extern void cfprefsdInit(void);
        cfprefsdInit();
    } else if ([processName isEqualToString:@"lsd"]) {
        extern void lsdInit(void);
        lsdInit();
    } else if ([processName isEqualToString:@"SpringBoard"]) {
        extern void sbInit(void);
        sbInit();
    } else if ([processName isEqualToString:@"runningboardd"]) {
        extern void runningboarddInit(void);
        runningboarddInit();
    }
}
