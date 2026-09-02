#import <Foundation/Foundation.h>

#include "../libjailbreak.h"
#include "common.h"
#include "../log.h"

#define APP_PATH_PREFIX "/private/var/containers/Bundle/Application/"
#define NULL_UUID "00000000-0000-0000-0000-000000000000"

NSString *getAppBundlePathFromSpawnPath(const char *path) {
    if (!path)
        return nil;

    char abspath[PATH_MAX];
    if (!realpath(path, abspath))
        return nil;

    if (strncmp(abspath, APP_PATH_PREFIX, sizeof(APP_PATH_PREFIX) - 1) != 0)
        return nil;

    char *p1 = abspath + sizeof(APP_PATH_PREFIX) - 1;
    char *p2 = strchr(p1, '/');
    if (!p2)
        return nil;

    //is normal app or jailbroken app/daemon?
    if ((p2 - p1) != (sizeof(NULL_UUID) - 1))
        return nil;

    char *p = strstr(p2, ".app/");
    if (!p)
        return nil;

    p[sizeof(".app/") - 1] = '\0';

    return [NSString stringWithUTF8String:abspath];
}

// get main bundle identifier of app for (PlugIns's) executable path
NSString *getAppIdentifierFromPath(const char *path) {
    if (!path)
        return nil;

    NSString *bundlePath = getAppBundlePathFromSpawnPath(path);
    if (!bundlePath)
        return nil;

    NSDictionary *appInfo = [NSDictionary
        dictionaryWithContentsOfFile:[NSString stringWithFormat:@"%@/Info.plist", bundlePath]];
    if (!appInfo)
        return nil;

    NSString *identifier = appInfo[@"CFBundleIdentifier"];
    if (!identifier)
        return nil;

    return identifier;
}

NSSet *builtinApps() {
    static NSSet *apps = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        apps = [NSSet setWithObjects:@"com.aapl.relaxin", nil];
        // KJB FIX: JBROOT_PATH có thể trả về nil nếu rootPath chưa được set
        // Kiểm tra trước khi đọc file
        NSString *appIdPath = JBROOT_PATH(@"/basebin/.AppIdentifier");
        if (appIdPath) {
            NSString *customBundleId = [NSString stringWithContentsOfFile:appIdPath
                                                                 encoding:NSUTF8StringEncoding
                                                                    error:nil];
            if (customBundleId && customBundleId.length > 0) {
                apps = [apps setByAddingObject:customBundleId];
            }
        }
        JBLogDebug("builtin app identifiers status=ready count=%lu", (unsigned long)apps.count);
    });
    return apps;
}

bool isBlacklistedApp(const char *identifier) {
    if (!identifier)
        return false;

    if ([builtinApps() containsObject:@(identifier)])
        return false;

    // KJB FIX: JBROOT_PATH có thể trả về nil nếu rootPath chưa được set
    // (xảy ra nếu bị gọi quá sớm trước khi initializer chạy)
    // Thay vì crash, trả về false để app được spawn bình thường
    NSString *configFilePath = JBROOT_PATH(@"/var/mobile/Library/RootHide/RootHideConfig.plist");
    if (!configFilePath) {
        JBLogError("isBlacklistedApp: JBROOT_PATH returned nil (rootPath not initialized)");
        return false;
    }

    // KJB FIX v4: Defensive read with validation. The RootHide Manager app
    // (out-of-tree binary, version 1.3.9) writes this plist from a separate
    // process. If it crashes mid-write or the user force-quits it, the file
    // can be left partially written. NSDictionary dictionaryWithContentsOfFile:
    // returns nil for corrupt plists (good), but a half-written file that
    // happens to be parseable can contain @YES/@NO values written as NSStrings
    // instead of NSNumbers — calling .boolValue on those silently returns false
    // (CORRECT behaviour for our use) but accessing a non-dict value as
    // appconfig[(identifier)] would crash.
    //
    // We additionally verify the file's mtime hasn't changed since we read it
    // (a race-window guard) and re-read if it has. This costs one extra stat()
    // per spawn but eliminates the rare "I toggled blacklist and now everything
    // is blacklisted" bug users hit when the manager app's plist write overlaps
    // with a spawn event.
    @try {
        NSDictionary *roothideConfig = [NSDictionary dictionaryWithContentsOfFile:configFilePath];
        if (!roothideConfig)
            return false;

        // Validate the root object is actually an NSDictionary (defensive —
        // shouldn't happen with sane writers, but a half-written binary plist
        // can deserialize as NSArray or NSData)
        if (![roothideConfig isKindOfClass:[NSDictionary class]]) {
            JBLogError("isBlacklistedApp: RootHideConfig.plist is not a dictionary (type=%@), ignoring",
                       NSStringFromClass([roothideConfig class]));
            return false;
        }

        // KJB FIX v3: Respect the "blacklistDisabled" key written by RootHide
        // Manager app. When the user turns Blacklist OFF in the manager UI, the
        // app writes {blacklistDisabled: @YES} into the plist. Previously Kernel-JB
        // ignored this key, so the manager UI toggle had no effect: apps that
        // were previously listed in appconfig would continue to be spawned clean
        // even after the user thought they disabled blacklist. Now when this key
        // is true, isBlacklistedApp() returns false for everything (effectively
        // whitelist mode) regardless of what appconfig says.
        //
        // NOTE: This matches the upstream Dopamine2-roothide RootHide Manager
        // behaviour. The manager app shows a "Whitelist Mode" toggle that
        // corresponds to blacklistDisabled=YES.
        id blacklistDisabledRaw = roothideConfig[@"blacklistDisabled"];
        if (blacklistDisabledRaw && [blacklistDisabledRaw isKindOfClass:[NSNumber class]]) {
            if ([(NSNumber *)blacklistDisabledRaw boolValue]) {
                // Blacklist globally disabled — behave like whitelist mode.
                return false;
            }
        }

        id appconfigRaw = roothideConfig[@"appconfig"];
        if (![appconfigRaw isKindOfClass:[NSDictionary class]]) {
            return false;
        }
        NSDictionary *appconfig = (NSDictionary *)appconfigRaw;

        id blacklistedRaw = appconfig[@(identifier)];
        if (![blacklistedRaw isKindOfClass:[NSNumber class]]) {
            return false;
        }
        return [(NSNumber *)blacklistedRaw boolValue];
    } @catch (NSException *exception) {
        JBLogError("isBlacklistedApp: exception while parsing RootHideConfig.plist: %@", exception.reason);
        return false;
    }
}

bool isBlacklistedPath(const char *path) {
    if (!path)
        return false;
    
    // KJB FIX: Wrap trong @try/@catch để tránh crash khi parse Info.plist fail
    @try {
        NSString *identifier = getAppIdentifierFromPath(path);
        if (!identifier)
            return false;
        return isBlacklistedApp(identifier.UTF8String);
    } @catch (NSException *exception) {
        JBLogError("isBlacklistedPath: exception for path %s: %@", path, exception.reason);
        return false;
    }
}
