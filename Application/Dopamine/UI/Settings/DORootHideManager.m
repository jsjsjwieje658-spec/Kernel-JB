//
//  DORootHideManager.m
//  Dopamine
//
//  RootHide Manager Implementation
//  Manages jailbreak hiding, blacklist, and path randomization
//

#import "DORootHideManager.h"
#import <libjailbreak/jbclient_xpc.h>
#import <libjailbreak/roothide.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import "DOUIManager.h"
#import "DOButtonCell.h"
#import "DOHeaderCell.h"

// Localization helper
#define RHLocalizedString(key) [[NSBundle bundleWithPath:@"/Library PreferenceBundles/DopamineSettings.bundle"] localizedStringForKey:(key) value:(key) table:nil]

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
        
        // Current JBRoot Path (read-only info)
        PSSpecifier *pathSpecifier = [PSSpecifier 
            preferenceSpecifierNamed:@"Randomized Path"
            target:self
            set:NULL
            get:@selector(currentJBRootPath)
            detail:Nil
            cell:PSStaticTextCell
            edit:Nil];
        [pathSpecifier setProperty:[self getActualJBRootPath] forKey:@"default"];
        [specifiers addObject:pathSpecifier];
        
        // Session ID
        PSSpecifier *sessionSpecifier = [PSSpecifier 
            preferenceSpecifierNamed:@"Session ID"
            target:self
            set:NULL
            get:@selector(sessionIDString)
            detail:Nil
            cell:PSStaticTextCell
            edit:Nil];
        unsigned long long sessionID = jbrand();
        [sessionSpecifier setProperty:[NSString stringWithFormat:@"%016llX", sessionID] forKey:@"default"];
        [specifiers addObject:sessionSpecifier];
        
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
            cell:DOButtonCell
            edit:Nil];
        [addSpecifier setProperty:@"addToBlacklist:" forKey:@"action"];
        [specifiers addObject:addSpecifier];
        
        // View/Edit blacklist
        PSSpecifier *viewSpecifier = [PSSpecifier 
            preferenceSpecifierNamed:@"View / Edit Blacklist"
            target:self
            set:NULL
            get:NULL
            detail:[DORootHideBlacklistController class]
            cell:PSLinkCell
            edit:Nil];
        [specifiers addObject:viewSpecifier];
        
        // Clear blacklist button
        PSSpecifier *clearSpecifier = [PSSpecifier 
            preferenceSpecifierNamed:@"Clear All Blacklist"
            target:self
            set:NULL
            get:NULL
            detail:Nil
            cell:DOButtonCell
            edit:Nil];
        [clearSpecifier setProperty:@"clearBlacklist:" forKey:@"action"];
        [clearSpecifier setProperty:@"Remove all apps from blacklist?" forKey:@"confirmationTitle"];
        [clearSpecifier setProperty:@"This cannot be undone." forKey:@"confirmationMessage"];
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
            cell:DOButtonCell
            edit:Nil];
        [bankingSpecifier setProperty:@"addBankingApps:" forKey:@"action"];
        [specifiers addObject:bankingSpecifier];
        
        // Add detection apps
        PSSpecifier *detectionSpecifier = [PSSpecifier 
            preferenceSpecifierNamed:@"Add Detection/Security Apps"
            target:self
            set:NULL
            get:NULL
            detail:Nil
            cell:DOButtonCell
            edit:Nil];
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
            cell:DOButtonCell
            edit:Nil];
        [applySpecifier setProperty:@"applyRootHideSettings:" forKey:@"action"];
        [applySpecifier setProperty:@"Apply RootHide settings and reboot userspace?" forKey:@"confirmationTitle"];
        [applySpecifier setProperty:@"This will restart SpringBoard and all apps." forKey:@"confirmationMessage"];
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
    
    // Update jbserver setting
    jbclient_jbsettings_set_bool("roothide.enabled", enabled);
    
    [self reloadSpecifier:specifier];
}

- (NSString *)currentJBRootPath
{
    return [self getActualJBRootPath] ?: @"/var/jb (standard)";
}

- (NSString *)sessionIDString
{
    unsigned long long sessionID = jbrand();
    return [NSString stringWithFormat:@"%016llX", sessionID];
}

- (NSString *)blacklistCountString
{
    return [NSString stringWithFormat:@"%lu apps blacklisted", (unsigned long)_mutableBlacklist.count];
}

#pragma mark - Helper Methods

- (NSString *)getActualJBRootPath
{
    const char *jbroot = rothide_get_jbroot();
    if (jbroot) {
        return [NSString stringWithUTF8String:jbroot];
    }
    return @"/var/jb";
}

- (void)refreshBlacklist
{
    NSArray *saved = [[NSUserDefaults standardUserDefaults] arrayForKey:kRootHideBlacklistKey];
    _mutableBlacklist = saved ? [saved mutableCopy] : [NSMutableArray new];
    
    // Load default blacklist from roothide system
    for (int i = 0; i < rothide_get_blacklist_count(); i++) {
        const char *entry = rothide_get_blacklist_entry(i);
        if (entry && ![_mutableBlacklist containsObject:[NSString stringWithUTF8String:entry]]) {
            [_mutableBlacklist addObject:[NSString stringWithUTF8String:entry]];
        }
    }
}

- (void)saveBlacklist
{
    [[NSUserDefaults standardUserDefaults] setObject:_mutableBlacklist forKey:kRootHideBlacklistKey];
    [[NSUserDefaults standardUserDefaults] synchronize];
    
    // Sync to roothide system
    for (NSString *bundleID in _mutableBlacklist) {
        rothide_add_blacklist(bundleID.UTF8String);
    }
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
        textField.autocorrectionType = UITextCorrectionTypeNo;
    }];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Add" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        NSString *bundleID = alert.textFields.firstObject.text;
        if (bundleID.length > 0 && ![self->_mutableBlacklist containsObject:bundleID]) {
            [self->_mutableBlacklist addObject:bundleID];
            rothide_add_blacklist(bundleID.UTF8String);
            [self saveBlacklist];
            [self reloadSpecifiers];
        }
    }]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)clearBlacklist:(id)sender
{
    [_mutableBlacklist removeAllObjects];
    [self saveBlacklist];
    [self reloadSpecifiers];
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
    
    for (NSString *bundleID in vietnameseBankingApps) {
        if (![_mutableBlacklist containsObject:bundleID]) {
            [_mutableBlacklist addObject:bundleID];
            rothide_add_blacklist(bundleID.UTF8String);
        }
    }
    
    [self saveBlacklist];
    [self reloadSpecifiers];
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
    
    for (NSString *bundleID in detectionApps) {
        if (![_mutableBlacklist containsObject:bundleID]) {
            [_mutableBlacklist addObject:bundleID];
            rothide_add_blacklist(bundleID.UTF8String);
        }
    }
    
    [self saveBlacklist];
    [self reloadSpecifiers];
}

- (void)applyRootHideSettings:(id)sender
{
    // Save current settings
    [self saveBlacklist];
    
    // Initialize RootHide subsystem
    roothide_init();
    
    // Set enabled state via jbserver
    BOOL enabled = self.isRootHideEnabled;
    jbclient_jbsettings_set_bool("roothide.enabled", enabled);
    
    // Trigger userspace reboot to apply
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        // Use jbctl to perform userspace reboot
        system("jbctl userspace-reboot");
    });
}

#pragma mark - Blacklist Sub-controller

@interface DORootHideBlacklistController : PSListController <UITableViewDelegate, UITableViewDataSource>
@property (nonatomic, strong) NSMutableArray *apps;
@end

@implementation DORootHideBlacklistController

- (id)specifiers
{
    if (!_specifiers) {
        _specifiers = [NSMutableArray new];
    }
    return _specifiers;
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    
    // Load blacklist from parent
    DORootHideManager *parent = (DORootHideManager *)self.parentController;
    _apps = parent.mutableBlacklist ?: [NSMutableArray new];
    
    self.tableView.delegate = self;
    self.tableView.dataSource = self;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section
{
    return _apps.count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath
{
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"BlacklistCell"];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:@"BlacklistCell"];
    }
    
    NSString *bundleID = _apps[indexPath.row];
    cell.textLabel.text = bundleID;
    cell.detailTextLabel.text = @"Tap to remove from blacklist";
    cell.accessoryType = UITableViewCellAccessoryDetailButton;
    
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath
{
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    
    NSString *bundleID = _apps[indexPath.row];
    
    UIAlertController *alert = [UIAlertController 
        alertControllerWithTitle:@"Remove from Blacklist" 
        message:[NSString stringWithFormat:@"Remove %@ from blacklist?", bundleID] 
        preferredStyle:UIAlertControllerStyleActionSheet];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Remove" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
        [self->_apps removeObjectAtIndex:indexPath.row];
        rothide_remove_blacklist(bundleID.UTF8String);
        
        // Save to parent
        DORootHideManager *parent = (DORootHideManager *)self.parentController;
        [parent saveBlacklist];
        
        [self.tableView deleteRowsAtIndexPaths:@[indexPath] withRowAnimation:UITableViewRowAnimationAutomatic];
    }]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    
    [self presentViewController:alert animated:YES completion:nil];
}

@end

@end
