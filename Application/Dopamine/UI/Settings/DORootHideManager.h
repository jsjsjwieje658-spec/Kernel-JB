//
//  DORootHideManager.h
//  Dopamine
//
//  RootHide Manager - Jailbreak Hiding Interface
//  Provides UI for managing RootHide mode, blacklist, and path randomization
//

#import <Preferences/PSListController.h>
#import <Preferences/PSSpecifier.h>

@interface DORootHideManager : PSListController

@property (nonatomic, strong) NSArray *blacklistedApps;
@property (nonatomic, copy) NSString *currentJBRootPath;

// Action handlers (receive PSSpecifier from DOButtonCell)
- (void)addToBlacklist:(PSSpecifier *)specifier;
- (void)viewBlacklist:(PSSpecifier *)specifier;
- (void)clearBlacklist:(PSSpecifier *)specifier;
- (void)addBankingApps:(PSSpecifier *)specifier;
- (void)addDetectionApps:(PSSpecifier *)specifier;
- (void)applyRootHideSettings:(PSSpecifier *)specifier;

// Data management
- (void)refreshBlacklist;

// Property accessors
- (BOOL)isRootHideEnabled;
- (void)setRootHideEnabled:(BOOL)enabled specifier:(PSSpecifier *)specifier;

@end
