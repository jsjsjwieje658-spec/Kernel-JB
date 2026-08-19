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

- (void)viewDidLoad
{
    [super viewDidLoad];
    [self refreshBlacklist];
}

- (void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];
    [self reloadSpecifiers];
}

#pragma mark - Specifiers (UI Layout)

- (id)specifiers
{
    if (_specifiers == nil) {
        NSMutableArray *specifiers = [NSMutableArray new];
        
        // Header
        PSSpecifier *headerSpecifier = [PSSpecifier emptyGroupSpecifier];
        [headerSpecifier setProperty:@"DOHeaderCell" forKey:@"headerCellClass"];
        [headerSpecifier setProperty:@"RootHide Manager" forKey:@"title"];
        [specifiers addObject:headerSpecifier];
        
        // RootHide Mode Toggle Group
        PSSpecifier *modeGroup = [PSSpecifier emptyGroupSpecifier];
        modeGroup.name = @"JAILBREAK HIDING";
        [specifiers addObject:modeGroup];
        
        // Enable/Disable RootHide toggle
        PSSpecifier *enableSpecifier = [PSSpecifier 
            preferenceSpecifierNamed:@"Enable RootHide"
            target:self
            set:@selector(setRootHideEnabled:specifier:)
            get:@selector(isRootHideEnabled)
            detail:Nil
            cell:PSSwitchCell
            edit:Nil];
        [enableSpecifier setProperty:kRootHideEnabledKey forKey:@"key"];
        [enableSpecifier setProperty:@YES forKey:@"enabled"];
        [specifiers addObject:enableSpecifier];
        
        // Info text
        PSSpecifier *infoSpecifier = [PSSpecifier 
            preferenceSpecifierNamed:@"RootHide Mode"
            target:self
            set:NULL
            get:@selector(rootHideInfoString)
            detail:Nil
            cell:PSStaticTextCell
            edit:Nil];
        [specifiers addObject:infoSpecifier];
        
        // Blacklist Management Group
        PSSpecifier *blacklistGroup = [PSSpecifier emptyGroupSpecifier];
        blacklistGroup.name = @"BLACKLIST MANAGEMENT";
        [specifiers addObject:blacklistGroup];
        
        // Blacklisted apps count
        PSSpecifier *countSpecifier = [PSSpecifier 
            preferenceSpecifierNamed:@"Blacklisted Apps"
            target:self
            set:NULL
            get:@selector(blacklistCountString)
            detail:Nil
            cell:PSStaticTextCell
            edit:Nil];
        [countSpecifier setProperty:[NSString stringWithFormat:@"%lu apps", (unsigned long)_mutableBlacklist.count] forKey:@"default"];
        [specifiers addObject:countSpecifier];
        
        // Add to blacklist button
        PSSpecifier *addSpecifier = [PSSpecifier 
            preferenceSpecifierNamed:@"Add App to Blacklist"
            target:self
            set:NULL
            get:NULL
            detail:Nil
            cell:PSStaticTextCell
            edit:Nil];
        [addSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
        [addSpecifier setProperty:@"addToBlacklist:" forKey:@"action"];
        [specifiers addObject:addSpecifier];
        
        // View current blacklist button
        PSSpecifier *viewSpecifier = [PSSpecifier 
            preferenceSpecifierNamed:@"View Current Blacklist"
            target:self
            set:NULL
            get:NULL
            detail:Nil
            cell:PSStaticTextCell
            edit:Nil];
        [viewSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
        [viewSpecifier setProperty:@"viewBlacklist:" forKey:@"action"];
        [specifiers addObject:viewSpecifier];
        
        // Clear blacklist button
        PSSpecifier *clearSpecifier = [PSSpecifier 
            preferenceSpecifierNamed:@"Clear All Blacklist"
            target:self
            set:NULL
            get:NULL
            detail:Nil
            cell:PSStaticTextCell
            edit:Nil];
        [clearSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
        [clearSpecifier setProperty:@"clearBlacklist:" forKey:@"action"];
        [specifiers addObject:clearSpecifier];
        
        // Default Blacklists Group
        PSSpecifier *defaultsGroup = [PSSpecifier emptyGroupSpecifier];
        defaultsGroup.name = @"PRESET BLACKLISTS";
        [specifiers addObject:defaultsGroup];
        
        // Add banking apps
        PSSpecifier *bankingSpecifier = [PSSpecifier 
            preferenceSpecifierNamed:@"Add Vietnamese Banking Apps"
            target:self
            set:NULL
            get:NULL
            detail:Nil
            cell:PSStaticTextCell
            edit:Nil];
        [bankingSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
        [bankingSpecifier setProperty:@"addBankingApps:" forKey:@"action"];
        [specifiers addObject:bankingSpecifier];
        
        // Add detection apps
        PSSpecifier *detectionSpecifier = [PSSpecifier 
            preferenceSpecifierNamed:@"Add Detection/Security Apps"
            target:self
            set:NULL
            get:NULL
            detail:Nil
            cell:PSStaticTextCell
            edit:Nil];
        [detectionSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
        [detectionSpecifier setProperty:@"addDetectionApps:" forKey:@"action"];
        [specifiers addObject:detectionSpecifier];
        
        // Apply button group
        PSSpecifier *applyGroup = [PSSpecifier emptyGroupSpecifier];
        applyGroup.name = @"APPLY CHANGES";
        [specifiers addObject:applyGroup];
        
        // Apply now button
        PSSpecifier *applySpecifier = [PSSpecifier 
            preferenceSpecifierNamed:@"Apply & Reboot Userspace"
            target:self
            set:NULL
            get:NULL
            detail:Nil
            cell:PSStaticTextCell
            edit:Nil];
        [applySpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
        [applySpecifier setProperty:@"applyRootHideSettings:" forKey:@"action"];
        [specifiers addObject:applySpecifier];
        
        _specifiers = specifiers;
    }
    
    return _specifiers;
}

#pragma mark - Property Getters/Setters

- (BOOL)isRootHideEnabled
{
    return [[NSUserDefaults standardUserDefaults] boolForKey:kRootHideEnabledKey];
}

- (void)setRootHideEnabled:(BOOL)enabled specifier:(PSSpecifier *)specifier
{
    [[NSUserDefaults standardUserDefaults] setBool:enabled forKey:kRootHideEnabledKey];
    [[NSUserDefaults standardUserDefaults] synchronize];
    
    [self reloadSpecifier:specifier];
}

- (NSString *)rootHideInfoString
{
    BOOL enabled = self.isRootHideEnabled;
    if (enabled) {
        return @"RootHide Mode: Enabled (Jailbreak hidden from blacklisted apps)";
    }
    return @"RootHide Mode: Disabled";
}

- (NSString *)blacklistCountString
{
    return [NSString stringWithFormat:@"%lu apps blacklisted", (unsigned long)_mutableBlacklist.count];
}

#pragma mark - Helper Methods

- (void)refreshBlacklist
{
    NSArray *saved = [[NSUserDefaults standardUserDefaults] arrayForKey:kRootHideBlacklistKey];
    _mutableBlacklist = saved ? [saved mutableCopy] : [NSMutableArray new];
}

- (void)saveBlacklist
{
    [[NSUserDefaults standardUserDefaults] setObject:_mutableBlacklist forKey:kRootHideBlacklistKey];
    [[NSUserDefaults standardUserDefaults] synchronize];
}

#pragma mark - Action Handlers

- (void)addToBlacklist:(id)sender
{
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
        NSString *bundleID = alert.textFields.firstObject.text;
        if (bundleID.length > 0 && ![self->_mutableBlacklist containsObject:bundleID]) {
            [self->_mutableBlacklist addObject:bundleID];
            [self saveBlacklist];
            [self reloadSpecifiers];
        }
    }]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)viewBlacklist:(id)sender
{
    if (_mutableBlacklist.count == 0) {
        UIAlertController *alert = [UIAlertController 
            alertControllerWithTitle:@"Blacklist Empty" 
            message:@"No apps are currently blacklisted." 
            preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
        return;
    }
    
    NSMutableString *message = [NSMutableString string];
    for (NSString *bundleID in _mutableBlacklist) {
        [message appendFormat:@"• %@\n", bundleID];
    }
    
    UIAlertController *alert = [UIAlertController 
        alertControllerWithTitle:@"Current Blacklist" 
        message:message 
        preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)clearBlacklist:(id)sender
{
    UIAlertController *alert = [UIAlertController 
        alertControllerWithTitle:@"Clear Blacklist?" 
        message:@"Remove all apps from blacklist? This cannot be undone." 
        preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Clear" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
        [self->_mutableBlacklist removeAllObjects];
        [self saveBlacklist];
        [self reloadSpecifiers];
    }]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)addBankingApps:(id)sender
{
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
        if (![_mutableBlacklist containsObject:bundleID]) {
            [_mutableBlacklist addObject:bundleID];
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

- (void)addDetectionApps:(id)sender
{
    NSArray *detectionApps = @[
        @"com.apple.dt.Xcode",
        @"com.bugsnag.Bugsnag",
        @"io.fabric.sdk.ios",
        @"com.microsoft.IntuneMAM",
        @"com.vmware.horizon",
    ];
    
    int added = 0;
    for (NSString *bundleID in detectionApps) {
        if (![_mutableBlacklist containsObject:bundleID]) {
            [_mutableBlacklist addObject:bundleID];
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

- (void)applyRootHideSettings:(id)sender
{
    [self saveBlacklist];
    
    UIAlertController *alert = [UIAlertController 
        alertControllerWithTitle:@"Settings Saved" 
        message:@"RootHide settings have been saved. Restart SpringBoard to apply changes." 
        preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

@end
