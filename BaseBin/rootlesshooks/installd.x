#import <Foundation/Foundation.h>

// BOOTLOOP RISK, DO NOT TOUCH
/*%hook MIGlobalConfiguration

- (NSMutableDictionary *)_bundleIDMapForBundlesInDirectory:(NSURL *)directoryURL
                                                                                         withExtension:(NSString *)extension
                                                                         loadingAdditionalKeys:(NSSet *)additionalKeys
{
        NSLog(@"_bundleIDMapForBundlesInDirectory(%@, %@, %@)", directoryURL, extension, additionalKeys);

        if ([directoryURL.path isEqualToString:@"/Applications"] && [extension isEqualToString:@"app"]) {
                NSMutableDictionary *origMap = %orig;

                // RootHide: Use JBROOT_PATH instead of /var/jb
                NSURL *rootlessAppDir = [NSURL fileURLWithPath:JBROOT_PATH(@"/Applications") isDirectory:YES];
                NSMutableDictionary *rootlessAppsMap = %orig(rootlessAppDir, extension, additionalKeys);
                [origMap addEntriesFromDictionary:rootlessAppsMap];
                return origMap;
        }

        return %orig;
}

%end*/

void installdInit(void)
{
        %init();
}
