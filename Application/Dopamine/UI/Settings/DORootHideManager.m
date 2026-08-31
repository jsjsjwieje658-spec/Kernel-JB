//
//  DORootHideManager.m
//  Dopamine
//
//  RootHide App Manager implementation (Build 3.3).
//
//  WHAT THIS DOES
//  ==============
//  Apps listed here are added to RootHideConfig.plist -> appconfig.
//  On every app launch, launchd's spawn hook (spawn_hook.c) and systemhook's
//  tweak loader (main.c enableTweakLoading) query the blacklist via
//  jbclient_blacklist_check_path() -> isBlacklistedPath() (libjailbreak
//  roothider/blacklist.m), which resolves the spawn path to a bundle ID and
//  looks it up in appconfig. Blacklisted apps are spawned completely clean:
//    - no DYLD_INSERT_LIBRARIES (no systemhook-<jbrand>.dylib in the dyld
//      image list — the #1 thing bank SDKs check via _dyld_image_count())
//    - no trustcache upload / CS_DEBUGGED marking for the child
//    - no tweak injection of any kind
//
//  WHY THE OLD UI WAS REMOVED (and what is different now)
//  ======================================================
//  The old DORootHideManager (removed in c790271 / abe0290) crashed Settings
//  because it mixed custom cells (DOHeaderCell inside a PSSpecifier group,
//  DOButtonCell wired through set:/get: selectors) into a raw PSListController.
//  It also called jbclient_roothide_add_blacklist / set_enabled /
//  clear_blacklist / apply_settings — functions that DO NOT EXIST in this
//  fork's libjailbreak — and persisted the blacklist into NSUserDefaults,
//  which nothing on the jailbreak side ever reads.
//
//  This rewrite:
//    - subclasses DOPSListController (same base as the theme/exploit pages)
//    - uses only the two cell patterns proven in DOSettingsController:
//        a) DOButtonCell rows (cellClass + "action" selector-name property)
//        b) plain PSStaticTextCell rows
//    - reads/writes the REAL config file via DOEnvironmentManager
//      runAsRoot + runUnsandboxed (same pattern as refreshJailbreakApps)
//

#import "DORootHideManager.h"
#import "DOPSListItemsController.h"
#import "DOButtonCell.h"
#import "DOEnvironmentManager.h"
#import "DOUIManager.h"
#import <Preferences/PSListController.h>
#import <Preferences/PSSpecifier.h>
#import <libjailbreak/jbroot.h>

// NOTE: Preset banking app bundle IDs were removed because they were incorrect,
// causing isBlacklistedApp() to return false (silent failure). Use instead:
//   - "Select Apps to Hide" button to auto-detect installed apps
//   - "Add App by Bundle ID" to manually add any app

@interface DORootHideManager ()
@property (nonatomic, strong) NSMutableArray<NSString *> *blacklist;
@property (nonatomic, copy) NSString *statusText;
@end

@implementation DORootHideManager

#pragma mark - Lifecycle

- (instancetype)init
{
    self = [super init];
    if (self) {
        _blacklist = [NSMutableArray new];
        _statusText = @"";
    }
    return self;
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    [self reloadBlacklist];
    _table.tableHeaderView = [DOPSListItemsController makeHeader:@"RootHide App Manager" withTarget:self];
}

- (void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];
    // Refresh in case the config changed elsewhere (e.g. re-jailbreak seeded it)
    [self reloadBlacklist];
    [self reloadSpecifiers];
}

#pragma mark - Config I/O (root + unsandboxed)

- (NSString *)configPath
{
    return JBROOT_PATH(@"/var/mobile/Library/RootHide/RootHideConfig.plist");
}

// Read the appconfig dictionary from RootHideConfig.plist.
// Runs as root+unsandboxed because the jbroot lives outside the app sandbox.
- (NSDictionary *)loadAppConfig
{
    __block NSDictionary *result = nil;
    [[DOEnvironmentManager sharedManager] runAsRoot:^{
        [[DOEnvironmentManager sharedManager] runUnsandboxed:^{
            NSDictionary *config = [NSDictionary dictionaryWithContentsOfFile:[self configPath]];
            NSDictionary *appconfig = config[@"appconfig"];
            if ([appconfig isKindOfClass:[NSDictionary class]]) {
                result = appconfig;
            }
        }];
    }];
    return result;
}

// Write the appconfig dictionary back into RootHideConfig.plist,
// preserving any other keys already present in the file.
- (BOOL)saveAppConfig:(NSDictionary *)appconfig
{
    __block BOOL ok = NO;
    [[DOEnvironmentManager sharedManager] runAsRoot:^{
        [[DOEnvironmentManager sharedManager] runUnsandboxed:^{
            NSString *path = [self configPath];
            NSMutableDictionary *config = [NSMutableDictionary dictionaryWithDictionary:([NSDictionary dictionaryWithContentsOfFile:path] ?: @{})];
            config[@"appconfig"] = appconfig;
            // Ensure the directory exists (first write ever)
            NSString *dir = [path stringByDeletingLastPathComponent];
            [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:NULL];
            ok = [config writeToFile:path atomically:YES];
            if (!ok) {
                NSLog(@"[RootHide] saveAppConfig failed to write %@", path);
            }
        }];
    }];
    return ok;
}

- (void)reloadBlacklist
{
    NSMutableArray *ids = [NSMutableArray new];
    for (NSString *key in [[self loadAppConfig] allKeys]) {
        if ([key isKindOfClass:[NSString class]] && key.length > 0) {
            [ids addObject:key];
        }
    }
    [ids sortUsingSelector:@selector(localizedCaseInsensitiveCompare:)];
    self.blacklist = ids;

    if (![DOEnvironmentManager sharedManager].isJailbroken) {
        self.statusText = @"Jailbreak required. Hidden apps start completely clean (no tweaks, no injection).";
    }
    else {
        self.statusText = [NSString stringWithFormat:@"%lu app(s) hidden. Hidden apps start completely clean — no tweaks, no injection.\nKill an app from the app switcher and reopen it to apply.", (unsigned long)ids.count];
    }
}

#pragma mark - Specifiers

- (NSArray *)specifiers
{
    if (_specifiers != nil) return _specifiers;

    NSMutableArray *specifiers = [NSMutableArray new];
    SEL defGetter = @selector(readPreferenceValue:);
    SEL defSetter = @selector(setPreferenceValue:specifier:);
    NSNumber *buttonHeight = @(44);

    // Status group
    PSSpecifier *statusGroup = [PSSpecifier emptyGroupSpecifier];
    if (statusGroup) {
        statusGroup.name = @"APP HIDING";
        [statusGroup setProperty:self.statusText forKey:@"footerText"];
        [specifiers addObject:statusGroup];
    }

    // Buttons
    NSArray *buttons = @[
        @{ @"title": @"Select Apps to Hide",
           @"image": @"apps.iphone",
           @"action": @"selectAppsPressed:" },
        @{ @"title": @"Add App by Bundle ID",
           @"image": @"plus.circle",
           @"action": @"addAppPressed:" },
    ];
    if (self.blacklist.count > 0) {
        buttons = [buttons arrayByAddingObject:
            @{ @"title": @"Remove All",
               @"image": @"trash",
               @"action": @"removeAllPressed:" }];
    }
    for (NSDictionary *button in buttons) {
        PSSpecifier *spec = [PSSpecifier preferenceSpecifierNamed:@"" target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
        if (!spec) continue;
        [spec setProperty:[DOButtonCell class] forKey:@"cellClass"];
        [spec setProperty:buttonHeight forKey:@"height"];
        [spec setProperty:button[@"image"] forKey:@"image"];
        [spec setProperty:button[@"action"] forKey:@"action"];
        [spec setProperty:button[@"title"] forKey:@"title"];
        [specifiers addObject:spec];
    }

    // Hidden apps list
    if (self.blacklist.count > 0) {
        PSSpecifier *listGroup = [PSSpecifier emptyGroupSpecifier];
        if (listGroup) {
            listGroup.name = @"HIDDEN APPS";
            [listGroup setProperty:@"Tap an app to remove it from the hidden list." forKey:@"footerText"];
            [specifiers addObject:listGroup];
        }
        for (NSString *bundleID in self.blacklist) {
            PSSpecifier *spec = [PSSpecifier preferenceSpecifierNamed:bundleID target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
            if (!spec) continue;
            [spec setProperty:bundleID forKey:@"title"];
            [spec setProperty:@"removeAppPressed:" forKey:@"action"];
            [specifiers addObject:spec];
        }
    }

    _specifiers = specifiers;
    return _specifiers;
}

// Rebuild the specifier list after every change
- (void)reloadSpecifiers
{
    _specifiers = nil;
    [super reloadSpecifiers];
}

#pragma mark - Actions

- (void)addAppPressed:(PSSpecifier *)specifier
{
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Add App to Hidden List"
                                                                   message:@"Enter the Bundle ID of the app to hide (e.g. com.vcb.IB)"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = @"com.example.app";
        textField.autocorrectionType = UITextAutocorrectionTypeNo;
        textField.autocapitalizationType = UITextAutocapitalizationTypeNone;
    }];
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Add" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        NSString *bundleID = [[alert.textFields firstObject].text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (bundleID.length == 0 || [bundleID containsString:@" "]) {
            [self showAlertWithTitle:@"Invalid Bundle ID" message:@"Bundle IDs look like com.company.app (no spaces)."];
            return;
        }
        NSMutableDictionary *appconfig = [NSMutableDictionary dictionaryWithDictionary:[self loadAppConfig]];
        if ([appconfig[bundleID] boolValue]) {
            [self showAlertWithTitle:@"Already Hidden" message:[NSString stringWithFormat:@"%@ is already in the hidden list.", bundleID]];
            return;
        }
        appconfig[bundleID] = @YES;
        if ([self saveAppConfig:appconfig]) {
            [self reloadBlacklist];
            [self reloadSpecifiers];
            [self showAlertWithTitle:@"App Hidden" message:[NSString stringWithFormat:@"%@ will start completely clean from its next launch. Kill it from the app switcher first.", bundleID]];
        }
        else {
            [self showAlertWithTitle:@"Error" message:@"Failed to write RootHideConfig.plist."];
        }
    }]];
    [self presentViewController:alert animated:YES completion:nil];
}

// Auto-detect installed apps and show a list for user to select
- (void)selectAppsPressed:(PSSpecifier *)specifier
{
    // Enumerate all installed apps from /var/containers/Bundle/Application/
    NSMutableArray *installedApps = [NSMutableArray new];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *appsPath = @"/var/containers/Bundle/Application";
    NSDirectoryEnumerator *enumerator = [fm enumeratorAtPath:appsPath];
    NSString *item;
    while ((item = [enumerator nextObject])) {
        if (![item hasSuffix:@".app"]) continue;
        NSString *appPath = [appsPath stringByAppendingPathComponent:item];
        NSString *infoPlistPath = [appPath stringByAppendingPathComponent:@"Info.plist"];
        NSDictionary *infoPlist = [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
        if (!infoPlist) continue;
        
        NSString *bundleID = infoPlist[@"CFBundleIdentifier"];
        NSString *displayName = infoPlist[@"CFBundleDisplayName"];
        if (!bundleID) continue;
        if (!displayName) displayName = infoPlist[@"CFBundleName"];
        if (!displayName) displayName = bundleID;
        
        [installedApps addObject:@{
            @"bundleID": bundleID,
            @"displayName": displayName,
            @"path": appPath
        }];
    }
    
    // Sort alphabetically by display name
    [installedApps sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        return [a[@"displayName"] localizedCaseInsensitiveCompare:b[@"displayName"]];
    }];
    
    if (installedApps.count == 0) {
        [self showAlertWithTitle:@"No Apps Found" message:@"Could not find any installed apps."];
        return;
    }
    
    // Show action sheet with app list
    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:@"Select Apps to Hide"
                                                                 message:@"Tap an app to add it to the hidden list."
                                                          preferredStyle:UIAlertControllerStyleActionSheet];
    
    // Add each app as an action
    for (NSDictionary *app in installedApps) {
        NSString *bundleID = app[@"bundleID"];
        NSString *displayName = app[@"displayName"];
        BOOL alreadyHidden = [self.blacklist containsObject:bundleID];
        
        NSString *title = alreadyHidden 
            ? [NSString stringWithFormat:@"%@ ✓", displayName]
            : displayName;
        
        UIAlertActionStyle style = alreadyHidden ? UIAlertActionStyleDestructive : UIAlertActionStyleDefault;
        
        // Capture by reference for the block
        NSString *bundleIDCopy = bundleID;
        NSString *displayNameCopy = displayName;
        
        [sheet addAction:[UIAlertAction actionWithTitle:title style:style handler:^(UIAlertAction *action) {
            if (alreadyHidden) {
                // Unhide the app
                NSMutableDictionary *appconfig = [NSMutableDictionary dictionaryWithDictionary:[self loadAppConfig]];
                [appconfig removeObjectForKey:bundleIDCopy];
                if ([self saveAppConfig:appconfig]) {
                    [self reloadBlacklist];
                    [self reloadSpecifiers];
                    [self showAlertWithTitle:@"App Unhidden" message:[NSString stringWithFormat:@"%@ will have tweaks and injection active again.", displayNameCopy]];
                }
            } else {
                // Hide the app
                NSMutableDictionary *appconfig = [NSMutableDictionary dictionaryWithDictionary:[self loadAppConfig]];
                appconfig[bundleIDCopy] = @YES;
                if ([self saveAppConfig:appconfig]) {
                    [self reloadBlacklist];
                    [self reloadSpecifiers];
                    [self showAlertWithTitle:@"App Hidden" message:[NSString stringWithFormat:@"%@ will start completely clean. Kill it from the app switcher first.", displayNameCopy]];
                }
            }
        }]];
    }
    
    [sheet addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    
    // iPad support
    if (UIDevice.currentDevice.userInterfaceIdiom == UIUserInterfaceIdiomPad) {
        sheet.popoverPresentationController.sourceView = self.view;
        sheet.popoverPresentationController.sourceRect = CGRectMake(self.view.bounds.size.width / 2, self.view.bounds.size.height / 2, 0, 0);
        sheet.popoverPresentationController.permittedArrowDirections = 0;
    }
    
    [self presentViewController:sheet animated:YES completion:nil];
}

- (void)removeAllPressed:(PSSpecifier *)specifier
{
    if (self.blacklist.count == 0) return;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Remove All"
                                                                   message:[NSString stringWithFormat:@"Remove all %lu app(s) from the hidden list?", (unsigned long)self.blacklist.count]
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Remove All" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
        if ([self saveAppConfig:@{}]) {
            [self reloadBlacklist];
            [self reloadSpecifiers];
        }
    }]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)removeAppPressed:(PSSpecifier *)specifier
{
    NSString *bundleID = [specifier propertyForKey:@"title"];
    if (![bundleID isKindOfClass:[NSString class]] || bundleID.length == 0) return;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Remove From Hidden List"
                                                                   message:[NSString stringWithFormat:@"Unhide %@? Tweaks and injection will be active again on its next launch.", bundleID]
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Unhide" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        NSMutableDictionary *appconfig = [NSMutableDictionary dictionaryWithDictionary:[self loadAppConfig]];
        [appconfig removeObjectForKey:bundleID];
        if ([self saveAppConfig:appconfig]) {
            [self reloadBlacklist];
            [self reloadSpecifiers];
        }
    }]];
    [self presentViewController:alert animated:YES completion:nil];
}

#pragma mark - Preference value stubs (never invoked for static/button cells,
// implemented defensively so PS internals can always resolve the selectors)

- (id)readPreferenceValue:(PSSpecifier *)specifier
{
    return nil;
}

- (void)setPreferenceValue:(id)value specifier:(PSSpecifier *)specifier
{
}

#pragma mark - Helpers

- (void)showAlertWithTitle:(NSString *)title message:(NSString *)message
{
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title message:message preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

@end
