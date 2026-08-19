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
        // Initialize blacklist immediately to prevent nil access crashes
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
        // Ensure blacklist is initialized even if refresh fails
        if (!_mutableBlacklist) {
            _mutableBlacklist = [NSMutableArray new];
        }
    }
}

- (void)viewWillAppear:(BOOL)animated
{
    @try {
        [super viewWillAppear:animated];
        // Only reload if specifiers are already loaded
        if (_specifiers != nil) {
            [self reloadSpecifiers];
        }
    }
    @catch (NSException *exception) {
        NSLog(@"[RootHide] viewWillAppear error: %@", exception.reason);
    }
}

#pragma mark - Safe Blacklist Accessor

- (NSMutableArray *)mutableBlacklist
{
    // Lazy initialization with nil safety
    if (!_mutableBlacklist) {
        _mutableBlacklist = [NSMutableArray new];
    }
    return _mutableBlacklist;
}

#pragma mark - Specifiers (UI Layout)

- (id)specifiers
{
    @try {
        if (_specifiers == nil) {
            NSMutableArray *specifiers = [NSMutableArray new];
            
            // Header
            PSSpecifier *headerSpecifier = [PSSpecifier emptyGroupSpecifier];
            if (headerSpecifier) {
                [headerSpecifier setProperty:@"DOHeaderCell" forKey:@"headerCellClass"];
                [headerSpecifier setProperty:@"RootHide Manager" forKey:@"title"];
                [specifiers addObject:headerSpecifier];
            }
            
            // RootHide Mode Toggle Group
            PSSpecifier *modeGroup = [PSSpecifier emptyGroupSpecifier];
            if (modeGroup) {
                modeGroup.name = @"JAILBREAK HIDING";
                [specifiers addObject:modeGroup];
            }
            
            // Enable/Disable RootHide toggle
            PSSpecifier *enableSpecifier = [PSSpecifier 
                preferenceSpecifierNamed:@"Enable RootHide"
                target:self
                set:@selector(setRootHideEnabled:specifier:)
                get:@selector(isRootHideEnabled)
                detail:Nil
                cell:PSSwitchCell
                edit:Nil];
            if (enableSpecifier) {
                [enableSpecifier setProperty:kRootHideEnabledKey forKey:@"key"];
                [enableSpecifier setProperty:@YES forKey:@"enabled"];
                [specifiers addObject:enableSpecifier];
            }
            
            // Info text
            PSSpecifier *infoSpecifier = [PSSpecifier 
                preferenceSpecifierNamed:@"RootHide Mode"
                target:self
                set:NULL
                get:@selector(rootHideInfoString)
                detail:Nil
                cell:PSStaticTextCell
                edit:Nil];
            if (infoSpecifier) {
                [specifiers addObject:infoSpecifier];
            }
            
            // Blacklist Management Group
            PSSpecifier *blacklistGroup = [PSSpecifier emptyGroupSpecifier];
            if (blacklistGroup) {
                blacklistGroup.name = @"BLACKLIST MANAGEMENT";
                [specifiers addObject:blacklistGroup];
            }
            
            // Blacklisted apps count
            NSUInteger count = self.mutableBlacklist.count;
            PSSpecifier *countSpecifier = [PSSpecifier 
                preferenceSpecifierNamed:@"Blacklisted Apps"
                target:self
                set:NULL
                get:@selector(blacklistCountString)
                detail:Nil
                cell:PSStaticTextCell
                edit:Nil];
            if (countSpecifier) {
                [countSpecifier setProperty:[NSString stringWithFormat:@"%lu apps", (unsigned long)count] forKey:@"default"];
                [specifiers addObject:countSpecifier];
            }
            
            // Add to blacklist button
            PSSpecifier *addSpecifier = [PSSpecifier 
                preferenceSpecifierNamed:@"Add App to Blacklist"
                target:self
                set:NULL
                get:NULL
                detail:Nil
                cell:PSStaticTextCell
                edit:Nil];
            if (addSpecifier) {
                [addSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
                [addSpecifier setProperty:@"addToBlacklist:" forKey:@"action"];
                [specifiers addObject:addSpecifier];
            }
            
            // View current blacklist button
            PSSpecifier *viewSpecifier = [PSSpecifier 
                preferenceSpecifierNamed:@"View Current Blacklist"
                target:self
                set:NULL
                get:NULL
                detail:Nil
                cell:PSStaticTextCell
                edit:Nil];
            if (viewSpecifier) {
                [viewSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
                [viewSpecifier setProperty:@"viewBlacklist:" forKey:@"action"];
                [specifiers addObject:viewSpecifier];
            }
            
            // Clear blacklist button
            PSSpecifier *clearSpecifier = [PSSpecifier 
                preferenceSpecifierNamed:@"Clear All Blacklist"
                target:self
                set:NULL
                get:NULL
                detail:Nil
                cell:PSStaticTextCell
                edit:Nil];
            if (clearSpecifier) {
                [clearSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
                [clearSpecifier setProperty:@"clearBlacklist:" forKey:@"action"];
                [specifiers addObject:clearSpecifier];
            }
            
            // Default Blacklists Group
            PSSpecifier *defaultsGroup = [PSSpecifier emptyGroupSpecifier];
            if (defaultsGroup) {
                defaultsGroup.name = @"PRESET BLACKLISTS";
                [specifiers addObject:defaultsGroup];
            }
            
            // Add banking apps
            PSSpecifier *bankingSpecifier = [PSSpecifier 
                preferenceSpecifierNamed:@"Add Vietnamese Banking Apps"
                target:self
                set:NULL
                get:NULL
                detail:Nil
                cell:PSStaticTextCell
                edit:Nil];
            if (bankingSpecifier) {
                [bankingSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
                [bankingSpecifier setProperty:@"addBankingApps:" forKey:@"action"];
                [specifiers addObject:bankingSpecifier];
            }
            
            // Add detection apps
            PSSpecifier *detectionSpecifier = [PSSpecifier 
                preferenceSpecifierNamed:@"Add Detection/Security Apps"
                target:self
                set:NULL
                get:NULL
                detail:Nil
                cell:PSStaticTextCell
                edit:Nil];
            if (detectionSpecifier) {
                [detectionSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
                [detectionSpecifier setProperty:@"addDetectionApps:" forKey:@"action"];
                [specifiers addObject:detectionSpecifier];
            }
            
            // Apply button group
            PSSpecifier *applyGroup = [PSSpecifier emptyGroupSpecifier];
            if (applyGroup) {
                applyGroup.name = @"APPLY CHANGES";
                [specifiers addObject:applyGroup];
            }
            
            // Apply now button
            PSSpecifier *applySpecifier = [PSSpecifier 
                preferenceSpecifierNamed:@"Apply & Reboot Userspace"
                target:self
                set:NULL
                get:NULL
                detail:Nil
                cell:PSStaticTextCell
                edit:Nil];
            if (applySpecifier) {
                [applySpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
                [applySpecifier setProperty:@"applyRootHideSettings:" forKey:@"action"];
                [specifiers addObject:applySpecifier];
            }
            
            _specifiers = specifiers;
        }
        
        return _specifiers;
    }
    @catch (NSException *exception) {
        NSLog(@"[RootHide] specifiers error: %@", exception.reason);
        // Return empty array to prevent null crash
        return [NSArray new];
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
        if (enabled) {
            return @"RootHide Mode: Enabled (Jailbreak hidden from blacklisted apps)";
        }
        return @"RootHide Mode: Disabled";
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
        return [NSString stringWithFormat:@"%lu apps blacklisted", (unsigned long)count];
    }
    @catch (NSException *exception) {
        NSLog(@"[RootHide] blacklistCountString error: %@", exception.reason);
        return @"0 apps blacklisted";
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
        // Ensure we have a valid array
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

#pragma mark - Action Handlers

- (void)addToBlacklist:(id)sender
{
    @try {
        UIAlertController *alert = [UIAlertController 
            alertControllerWithTitle:@"Add to Blacklist" 
            message:@"Enter the Bundle ID of the app to hide (e.g., com.example.app)" 
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
                if (bundleID.length > 0 && ![self.mutableBlacklist containsObject:bundleID]) {
                    [self.mutableBlacklist addObject:bundleID];
                    [self saveBlacklist];
                    [self reloadSpecifiers];
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

- (void)viewBlacklist:(id)sender
{
    @try {
        if (self.mutableBlacklist.count == 0) {
            UIAlertController *alert = [UIAlertController 
                alertControllerWithTitle:@"Blacklist Empty" 
                message:@"No apps are currently blacklisted." 
                preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
            [self presentViewController:alert animated:YES completion:nil];
            return;
        }
        
        NSMutableString *message = [NSMutableString string];
        for (NSString *bundleID in self.mutableBlacklist) {
            [message appendFormat:@"• %@\n", bundleID];
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

- (void)clearBlacklist:(id)sender
{
    @try {
        UIAlertController *alert = [UIAlertController 
            alertControllerWithTitle:@"Clear Blacklist?" 
            message:@"Remove all apps from blacklist? This cannot be undone." 
            preferredStyle:UIAlertControllerStyleAlert];
        
        [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
        [alert addAction:[UIAlertAction actionWithTitle:@"Clear" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
            @try {
                [self.mutableBlacklist removeAllObjects];
                [self saveBlacklist];
                [self reloadSpecifiers];
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

- (void)addBankingApps:(id)sender
{
    @try {
        NSArray *vietnameseBankingApps = @[
            @"com.vietinbank.iBank",
            @"com.vcb.IB",
            @"com.techcombank.business",
            @"com.mbmobile",
            @"com.timb.VCBMobileBanking",
            @"com.acb.ACBMobileBanking",
            @"com.vib.VIBMobileBanking",
            @"com.babk.BABMobileBanking",
            @"com.vietcombank.MobileBanking",
            @"com.agribank.DigiBank",
            @"vnpay.NapAsVnPay",
        ];
        
        int added = 0;
        for (NSString *bundleID in vietnameseBankingApps) {
            if (![self.mutableBlacklist containsObject:bundleID]) {
                [self.mutableBlacklist addObject:bundleID];
                added++;
            }
        }
        
        [self saveBlacklist];
        [self reloadSpecifiers];
        
        UIAlertController *alert = [UIAlertController 
            alertControllerWithTitle:@"Banking Apps Added" 
            message:[NSString stringWithFormat:@"Added %d Vietnamese banking apps to blacklist.", added] 
            preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
    }
    @catch (NSException *exception) {
        NSLog(@"[RootHide] addBankingApps error: %@", exception.reason);
    }
}

- (void)addDetectionApps:(id)sender
{
    @try {
        NSArray *detectionApps = @[
            @"com.apple.dt.Xcode",
            @"com.bugsnag.Bugsnag",
            @"io.fabric.sdk.ios",
            @"com.microsoft.IntuneMAM",
            @"com.vmware.horizon",
        ];
        
        int added = 0;
        for (NSString *bundleID in detectionApps) {
            if (![self.mutableBlacklist containsObject:bundleID]) {
                [self.mutableBlacklist addObject:bundleID];
                added++;
            }
        }
        
        [self saveBlacklist];
        [self reloadSpecifiers];
        
        UIAlertController *alert = [UIAlertController 
            alertControllerWithTitle:@"Detection Apps Added" 
            message:[NSString stringWithFormat:@"Added %d detection/security apps to blacklist.", added] 
            preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
    }
    @catch (NSException *exception) {
        NSLog(@"[RootHide] addDetectionApps error: %@", exception.reason);
    }
}

- (void)applyRootHideSettings:(id)sender
{
    @try {
        [self saveBlacklist];
        
        UIAlertController *alert = [UIAlertController 
            alertControllerWithTitle:@"Settings Saved" 
            message:@"RootHide settings have been saved. Restart SpringBoard to apply changes." 
            preferredStyle:UIAlertControllerStyleAlert];
        
        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
    }
    @catch (NSException *exception) {
        NSLog(@"[RootHide] applyRootHideSettings error: %@", exception.reason);
    }
}

@end
