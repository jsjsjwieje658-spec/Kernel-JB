//
//  DORootHideManager.h
//  Dopamine
//
//  RootHide Manager - Jailbreak Hiding Interface
//  Provides UI for managing RootHide mode, blacklist, and path randomization
//

#import <Preferences/PSListController.h>

@interface DORootHideManager : PSListController

@property (nonatomic, strong) NSArray *blacklistedApps;
@property (nonatomic, copy) NSString *currentJBRootPath;

// Actions (matching implementation signatures)
- (void)addToBlacklist:(id)sender;
- (void)viewBlacklist:(id)sender;
- (void)clearBlacklist:(id)sender;
- (void)addBankingApps:(id)sender;
- (void)addDetectionApps:(id)sender;
- (void)applyRootHideSettings:(id)sender;
- (void)refreshBlacklist;

// Property accessors
- (BOOL)isRootHideEnabled;
- (void)setRootHideEnabled:(BOOL)enabled specifier:(PSSpecifier *)specifier;

@end
