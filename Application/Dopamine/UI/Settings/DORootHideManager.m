//
//  DORootHideManager.m
//  Dopamine
//
//  RootHide Manager Implementation
//  Manages jailbreak hiding, blacklist, and path randomization
//

#import "DORootHideManager.h"
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import "DOUIManager.h"
#import "DOButtonCell.h"
#import "DOHeaderCell.h"

static NSString * const kRootHideEnabledKey = @"RootHideEnabled";
static NSString * const kRootHideBlacklistKey = @"RootHideBlacklist";

@interface DORootHideManager ()
@property (nonatomic, strong) NSMutableArray *mutableBlacklist;
@end

@implementation DORootHideManager

#pragma mark - Initialization Safety

- (instancetype)init
{
    self = [super init];
    if (self) {
        _mutableBlacklist = [NSMutableArray new];
    }
    return self;
}

- (void)viewDidLoad
{
    @try {
        [super viewDidLoad];
        [self refreshBlacklist];
    }
    @catch (NSException *exception) {
        NSLog(@"[RootHide] viewDidLoad error: %@", exception.reason);
        if (!_mutableBlacklist) {
            _mutableBlacklist = [NSMutableArray new];
        }
    }
}

- (void)viewWillAppear:(BOOL)animated
{
    @try {
        [super viewWillAppear:animated];
    }
    @catch (NSException *exception) {
        NSLog(@"[RootHide] viewWillAppear error: %@", exception.reason);
    }
}

#pragma mark - Safe Blacklist Accessor

- (NSMutableArray *)mutableBlacklist
{
    if (!_mutableBlacklist) {
        _mutableBlacklist = [NSMutableArray new];
    }
    return _mutableBlacklist;
}

#pragma mark - Specifiers (UI Layout)

- (NSArray *)specifiers
{
    @try {
        if (_specifiers == nil) {
            NSMutableArray *specifiers = [NSMutableArray new];
            
            // ========== HEADER SECTION ==========
            PSSpecifier *headerGroup = [PSSpecifier emptyGroupSpecifier];
            if (headerGroup) {
                [headerGroup setProperty:@"DOHeaderCell" forKey:@"headerCellClass"];
                [headerGroup setProperty:@"RootHide Manager" forKey:@"title"];
                [specifiers addObject:headerGroup];
            }
            
            // ========== TOGGLE SECTION ==========
            PSSpecifier *toggleGroup = [PSSpecifier emptyGroupSpecifier];
            if (toggleGroup) {
                toggleGroup.name = @"JAILBREAK HIDING";
                [specifiers addObject:toggleGroup];
            }
            
            // Enable/Disable RootHide toggle
            PSSpecifier *enableSpec = [PSSpecifier 
                preferenceSpecifierNamed:@"Enable RootHide"
                target:self
                set:@selector(setRootHideEnabled:specifier:)
                get:@selector(isRootHideEnabled)
                detail:Nil
                cell:PSSwitchCell
                edit:Nil];
            if (enableSpec) {
                [enableSpec setProperty:kRootHideEnabledKey forKey:@"key"];
                [enableSpec setProperty:@YES forKey:@"enabled"];
                [specifiers addObject:enableSpec];
            }
            
            // Status text
            PSSpecifier *statusSpec = [PSSpecifier 
                preferenceSpecifierNamed:@"Status"
                target:self
                set:NULL
                get:@selector(rootHideInfoString)
                detail:Nil
                cell:PSStaticTextCell
                edit:Nil];
            if (statusSpec) {
                [specifiers addObject:statusSpec];
            }
            
            // ========== BLACKLIST SECTION ==========
            PSSpecifier *blacklistGroup = [PSSpecifier emptyGroupSpecifier];
            if (blacklistGroup) {
                blacklistGroup.name = @"BLACKLIST MANAGEMENT";
                [specifiers addObject:blacklistGroup];
            }
            
            // Blacklist count
            PSSpecifier *countSpec = [PSSpecifier 
                preferenceSpecifierNamed:@"Blacklisted Apps"
                target:self
                set:NULL
                get:@selector(blacklistCountString)
                detail:Nil
                cell:PSStaticTextCell
                edit:Nil];
            if (countSpec) {
                [specifiers addObject:countSpec];
            }
            
            // Add to blacklist button - WITH ALL REQUIRED PROPERTIES
            PSSpecifier *addSpec = [self createButtonSpecifierWithTitle:@"Add App to Blacklist"
                action:@selector(addToBlacklist:)
                key:@"add_to_blacklist"
                image:@"plus.circle"];
            if (addSpec) {
                [specifiers addObject:addSpec];
            }
            
            // View blacklist button
            PSSpecifier *viewSpec = [self createButtonSpecifierWithTitle:@"View Current Blacklist"
                action:@selector(viewBlacklist:)
                key:@"view_blacklist"
                image:@"eye"];
            if (viewSpec) {
                [specifiers addObject:viewSpec];
            }
            
            // Clear blacklist button  
            PSSpecifier *clearSpec = [self createButtonSpecifierWithTitle:@"Clear All Blacklist"
                action:@selector(clearBlacklist:)
                key:@"clear_blacklist"
                image:@"trash"];
            if (clearSpec) {
                [specifiers addObject:clearSpec];
            }
            
            // ========== PRESET SECTION ==========
            PSSpecifier *presetGroup = [PSSpecifier emptyGroupSpecifier];
            if (presetGroup) {
                presetGroup.name = @"PRESET BLACKLISTS";
                [specifiers addObject:presetGroup];
            }
            
            // Add banking apps button
            PSSpecifier *bankingSpec = [self createButtonSpecifierWithTitle:@"Add Vietnamese Banking Apps"
                action:@selector(addBankingApps:)
                key:@"add_banking"
                image:@"building.columns.fill"];
            if (bankingSpec) {
                [specifiers addObject:bankingSpec];
            }
            
            // Add detection apps button
            PSSpecifier *detectionSpec = [self createButtonSpecifierWithTitle:@"Add Detection/Security Apps"
                action:@selector(addDetectionApps:)
                key:@"add_detection"
                image:@"shield"];
            if (detectionSpec) {
                [specifiers addObject:detectionSpec];
            }
            
            // ========== APPLY SECTION ==========
            PSSpecifier *applyGroup = [PSSpecifier emptyGroupSpecifier];
            if (applyGroup) {
                applyGroup.name = @"APPLY CHANGES";
                [specifiers addObject:applyGroup];
            }
            
            // Apply button
            PSSpecifier *applySpec = [self createButtonSpecifierWithTitle:@"Apply & Reboot Userspace"
                action:@selector(applyRootHideSettings:)
                key:@"apply_settings"
                image:@"checkmark.circle"];
            if (applySpec) {
                [specifiers addObject:applySpec];
            }
            
            _specifiers = [specifiers copy];
        }
        
        return _specifiers;
    }
    @catch (NSException *exception) {
        NSLog(@"[RootHide] specifiers error: %@", exception.reason);
        return @[];
    }
}

#pragma mark - Button Specifier Factory (Fixes crash on scroll)

- (PSSpecifier *)createButtonSpecifierWithTitle:(NSString *)title 
    action:(SEL)action 
    key:(NSString *)key 
    image:(NSString *)imageName
{
    @try {
        PSSpecifier *specifier = [PSSpecifier 
            preferenceSpecifierNamed:title
            target:self
            set:NULL
            get:NULL
            detail:Nil
            cell:PSStaticTextCell
            edit:Nil];
        
        if (!specifier) return nil;
        
        // CRITICAL: All properties DOButtonCell needs
        [specifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
        [specifier setProperty:NSStringFromSelector(action) forKey:@"action"];
        [specifier setProperty:key forKey:@"key"];           // Required by DOButtonCell
        [specifier setProperty:imageName forKey:@"image"];     // Required by DOButtonCell
        [specifier setProperty:title forKey:@"title"];         // Ensure title is set
        
        return specifier;
    }
    @catch (NSException *exception) {
        NSLog(@"[RootHide] createButtonSpecifier error: %@", exception.reason);
        return nil;
    }
}

#pragma mark - Property Getters/Setters

- (BOOL)isRootHideEnabled
{
    @try {
        return [[NSUserDefaults standardUserDefaults] boolForKey:kRootHideEnabledKey];
    }
    @catch (NSException *exception) {
        NSLog(@"[RootHide] isRootHideEnabled error: %@", exception.reason);
        return NO;
    }
}

- (void)setRootHideEnabled:(BOOL)enabled specifier:(PSSpecifier *)specifier
{
    @try {
        [[NSUserDefaults standardUserDefaults] setBool:enabled forKey:kRootHideEnabledKey];
        [[NSUserDefaults standardUserDefaults] synchronize];
        
        if (specifier) {
            [self reloadSpecifier:specifier];
        }
    }
    @catch (NSException *exception) {
        NSLog(@"[RootHide] setRootHideEnabled error: %@", exception.reason);
    }
}

- (NSString *)rootHideInfoString
{
    @try {
        BOOL enabled = self.isRootHideEnabled;
        return enabled ? 
            @"✅ RootHide Mode: Enabled" : 
            @"⚪ RootHide Mode: Disabled";
    }
    @catch (NSException *exception) {
        NSLog(@"[RootHide] rootHideInfoString error: %@", exception.reason);
        return @"RootHide Mode: Unknown";
    }
}

- (NSString *)blacklistCountString
{
    @try {
        NSUInteger count = self.mutableBlacklist.count;
        return [NSString stringWithFormat:@"%lu app(s) in blacklist", (unsigned long)count];
    }
    @catch (NSException *exception) {
        NSLog(@"[RootHide] blacklistCountString error: %@", exception.reason);
        return @"0 app(s) in blacklist";
    }
}

#pragma mark - Helper Methods

- (void)refreshBlacklist
{
    @try {
        NSArray *saved = [[NSUserDefaults standardUserDefaults] arrayForKey:kRootHideBlacklistKey];
        if (saved && [saved isKindOfClass:[NSArray class]]) {
            _mutableBlacklist = [saved mutableCopy];
        } else {
            _mutableBlacklist = [NSMutableArray new];
        }
    }
    @catch (NSException *exception) {
        NSLog(@"[RootHide] refreshBlacklist error: %@", exception.reason);
        _mutableBlacklist = [NSMutableArray new];
    }
}

- (void)saveBlacklist
{
    @try {
        if (_mutableBlacklist) {
            [[NSUserDefaults standardUserDefaults] setObject:_mutableBlacklist forKey:kRootHideBlacklistKey];
            [[NSUserDefaults standardUserDefaults] synchronize];
        }
    }
    @catch (NSException *exception) {
        NSLog(@"[RootHide] saveBlacklist error: %@", exception.reason);
    }
}

#pragma mark - Action Handlers (Receive PSSpecifier from DOButtonCell)

- (void)addToBlacklist:(PSSpecifier *)specifier
{
    @try {
        UIAlertController *alert = [UIAlertController 
            alertControllerWithTitle:@"Add to Blacklist" 
            message:@"Enter the Bundle ID of the app to hide\n(e.g., com.vcb.IB)" 
            preferredStyle:UIAlertControllerStyleAlert];
        
        [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
            textField.placeholder = @"com.example.app";
            textField.autocapitalizationType = UITextAutocapitalizationTypeNone;
            textField.autocorrectionType = UITextAutocorrectionTypeNo;
        }];
        
        [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
        [alert addAction:[UIAlertAction actionWithTitle:@"Add" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            @try {
                NSString *bundleID = alert.textFields.firstObject.text;
                bundleID = [bundleID stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
                
                if (bundleID.length > 0 && ![self.mutableBlacklist containsObject:bundleID]) {
                    [self.mutableBlacklist addObject:bundleID];
                    [self saveBlacklist];
                    [self reloadSpecifiers];
                    
                    // Show success feedback
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                        UIAlertController *successAlert = [UIAlertController 
                            alertControllerWithTitle:@"Added" 
                            message:[NSString stringWithFormat:@"%@ added to blacklist", bundleID]
                            preferredStyle:UIAlertControllerStyleAlert];
                        [successAlert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
                        [self presentViewController:successAlert animated:YES completion:nil];
                    });
                } else if ([self.mutableBlacklist containsObject:bundleID]) {
                    UIAlertController *dupAlert = [UIAlertController 
                        alertControllerWithTitle:@"Already Exists" 
                        message:@"This app is already in the blacklist."
                        preferredStyle:UIAlertControllerStyleAlert];
                    [dupAlert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
                    [self presentViewController:dupAlert animated:YES completion:nil];
                }
            }
            @catch (NSException *ex) {
                NSLog(@"[RootHide] addToBlacklist action error: %@", ex.reason);
            }
        }]];
        
        [self presentViewController:alert animated:YES completion:nil];
    }
    @catch (NSException *exception) {
        NSLog(@"[RootHide] addToBlacklist error: %@", exception.reason);
    }
}

- (void)viewBlacklist:(PSSpecifier *)specifier
{
    @try {
        NSArray *blacklist = [self.mutableBlacklist copy];
        
        if (blacklist.count == 0) {
            UIAlertController *alert = [UIAlertController 
                alertControllerWithTitle:@"Blacklist Empty" 
                message:@"No apps are currently blacklisted.\n\nTap 'Add App to Blacklist' or use preset buttons to add apps."
                preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
            [self presentViewController:alert animated:YES completion:nil];
            return;
        }
        
        NSMutableString *message = [NSMutableString string];
        [message appendFormat:@"Total: %lu app(s)\n\n", (unsigned long)blacklist.count];
        
        for (NSUInteger i = 0; i < blacklist.count; i++) {
            [message appendFormat:@"%lu. %@\n", (unsigned long)(i + 1), blacklist[i]];
        }
        
        UIAlertController *alert = [UIAlertController 
            alertControllerWithTitle:@"Current Blacklist" 
            message:message 
            preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
    }
    @catch (NSException *exception) {
        NSLog(@"[RootHide] viewBlacklist error: %@", exception.reason);
    }
}

- (void)clearBlacklist:(PSSpecifier *)specifier
{
    @try {
        NSUInteger count = self.mutableBlacklist.count;
        
        if (count == 0) {
            UIAlertController *alert = [UIAlertController 
                alertControllerWithTitle:@"Already Empty" 
                message:@"The blacklist is already empty."
                preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
            [self presentViewController:alert animated:YES completion:nil];
            return;
        }
        
        UIAlertController *alert = [UIAlertController 
            alertControllerWithTitle:@"⚠️ Clear Blacklist?" 
            message:[NSString stringWithFormat:@"Remove all %lu app(s) from blacklist?\n\nThis cannot be undone!", (unsigned long)count]
            preferredStyle:UIAlertControllerStyleAlert];
        
        [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
        [alert addAction:[UIAlertAction actionWithTitle:@"Clear All" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
            @try {
                [self.mutableBlacklist removeAllObjects];
                [self saveBlacklist];
                [self reloadSpecifiers];
                
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                    UIAlertController *clearedAlert = [UIAlertController 
                        alertControllerWithTitle:@"Cleared" 
                        message:@"All apps removed from blacklist."
                        preferredStyle:UIAlertControllerStyleAlert];
                    [clearedAlert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
                    [self presentViewController:clearedAlert animated:YES completion:nil];
                });
            }
            @catch (NSException *ex) {
                NSLog(@"[RootHide] clearBlacklist action error: %@", ex.reason);
            }
        }]];
        
        [self presentViewController:alert animated:YES completion:nil];
    }
    @catch (NSException *exception) {
        NSLog(@"[RootHide] clearBlacklist error: %@", exception.reason);
    }
}

- (void)addBankingApps:(PSSpecifier *)specifier
{
    @try {
        NSArray *vietnameseBankingApps = @[
            @"com.vietinbank.iBank",      // VietinBank
            @"com.vcb.IB",                 // Vietcombank
            @"com.techcombank.business",   // Techcombank
            @"com.mbmobile",               // MB Bank
            @"com.acb.ACBMobileBanking",  // ACB
            @"com.vib.VIBMobileBanking",  // VIB
            @"com.babk.BABMobileBanking", // BAOVIET Bank
            @"com.agribank.DigiBank",     // Agribank
            @"vnpay.NapAsVnPay",          // VNPay
        ];
        
        int added = 0;
        NSMutableArray *addedNames = [NSMutableArray new];
        
        for (NSString *bundleID in vietnameseBankingApps) {
            if (![self.mutableBlacklist containsObject:bundleID]) {
                [self.mutableBlacklist addObject:bundleID];
                added++;
                [addedNames addObject:bundleID];
            }
        }
        
        [self saveBlacklist];
        [self reloadSpecifiers];
        
        NSString *message;
        if (added > 0) {
            message = [NSString stringWithFormat:@"Added %d Vietnamese banking apps:\n\n%@", added, [addedNames componentsJoinedByString:@"\n"]];
        } else {
            message = @"All banking apps are already in the blacklist.";
        }
        
        UIAlertController *alert = [UIAlertController 
            alertControllerWithTitle:@"🏦 Banking Apps" 
            message:message
            preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
    }
    @catch (NSException *exception) {
        NSLog(@"[RootHide] addBankingApps error: %@", exception.reason);
    }
}

- (void)addDetectionApps:(PSSpecifier *)specifier
{
    @try {
        NSArray *detectionApps = @[
            @"com.apple.dt.Xcode",         // Xcode Debugger
            @"com.bugsnag.Bugsnag",        // Bugsnag SDK
            @"io.fabric.sdk.ios",          // Fabric/Crashlytics
            @"com.microsoft.IntuneMAM",    // Microsoft Intune
            @"com.vmware.horizon",         // VMware Horizon
        ];
        
        int added = 0;
        NSMutableArray *addedNames = [NSMutableArray new];
        
        for (NSString *bundleID in detectionApps) {
            if (![self.mutableBlacklist containsObject:bundleID]) {
                [self.mutableBlacklist addObject:bundleID];
                added++;
                [addedNames addObject:bundleID];
            }
        }
        
        [self saveBlacklist];
        [self reloadSpecifiers];
        
        NSString *message;
        if (added > 0) {
            message = [NSString stringWithFormat:@"Added %d detection/security apps:\n\n%@", added, [addedNames componentsJoinedByString:@"\n"]];
        } else {
            message = @"All detection apps are already in the blacklist.";
        }
        
        UIAlertController *alert = [UIAlertController 
            alertControllerWithTitle:@"🛡️ Detection Apps" 
            message:message
            preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
    }
    @catch (NSException *exception) {
        NSLog(@"[RootHide] addDetectionApps error: %@", exception.reason);
    }
}

- (void)applyRootHideSettings:(PSSpecifier *)specifier
{
    @try {
        [self saveBlacklist];
        
        NSUInteger count = self.mutableBlacklist.count;
        BOOL enabled = self.isRootHideEnabled;
        
        NSString *message = [NSString stringWithFormat: 
            @"RootHide Settings Saved!\n\n"
            @"• Mode: %@\n"
            @"• Blacklisted: %lu app(s)\n\n"
            @"Restart SpringBoard to apply changes.",
            enabled ? @"ENABLED ✅" : @"DISABLED ⚪",
            (unsigned long)count];
        
        UIAlertController *alert = [UIAlertController 
            alertControllerWithTitle:@"💾 Settings Saved" 
            message:message
            preferredStyle:UIAlertControllerStyleAlert];
        
        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [alert addAction:[UIAlertAction actionWithTitle:@"Respring Now" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            // Trigger respring via notification
            CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(), 
                CFSTR("com.opa334.dopamine.respring"), NULL, NULL, TRUE);
        }]];
        
        [self presentViewController:alert animated:YES completion:nil];
    }
    @catch (NSException *exception) {
        NSLog(@"[RootHide] applyRootHideSettings error: %@", exception.reason);
    }
}

@end
