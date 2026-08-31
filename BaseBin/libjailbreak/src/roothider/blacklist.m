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
    
    NSDictionary *roothideConfig = [NSDictionary dictionaryWithContentsOfFile:configFilePath];
    if (!roothideConfig)
        return false;

    NSDictionary *appconfig = roothideConfig[@"appconfig"];
    if (!appconfig)
        return false;

    NSNumber *blacklisted = appconfig[@(identifier)];
    if (!blacklisted)
        return false;

    return blacklisted.boolValue;
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
