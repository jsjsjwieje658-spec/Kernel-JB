//
//  DORootHideManager.h
//  Dopamine
//
//  RootHide App Manager — manages the AppHide blacklist
//  (apps that are spawned 100% clean: no systemhook injection, no tweaks).
//
//  Build 3.3 rewrite:
//  - Subclasses DOPSListController (proven themed base) instead of raw
//    PSListController with custom cells (old version crashed Settings).
//  - Persists directly to <jbroot>/var/mobile/Library/RootHide/RootHideConfig.plist
//    key "appconfig" — the exact file isBlacklistedApp() (libjailbreak
//    roothider/blacklist.m) reads from launchd on every app spawn.
//  - No jbclient_roothide_* calls (those functions do not exist in this fork).
//

#import "DOPSListController.h"
#import <Preferences/PSSpecifier.h>

NS_ASSUME_NONNULL_BEGIN

@interface DORootHideManager : DOPSListController

// Button actions (invoked by DOButtonCell with the specifier as argument)
- (void)addBankingAppsPressed:(PSSpecifier *)specifier;
- (void)addAppPressed:(PSSpecifier *)specifier;
- (void)removeAllPressed:(PSSpecifier *)specifier;

// Row action (invoked by PSListController on row selection)
- (void)removeAppPressed:(PSSpecifier *)specifier;

// Config I/O (read/write RootHideConfig.plist as root+unsandboxed)
- (NSDictionary *)loadAppConfig;
- (BOOL)saveAppConfig:(NSDictionary *)appconfig;

@end

NS_ASSUME_NONNULL_END
