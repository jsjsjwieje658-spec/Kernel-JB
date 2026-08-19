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
@property (nonatomic, assign) BOOL isRootHideEnabled;
@property (nonatomic, copy) NSString *currentJBRootPath;

// Actions
- (void)toggleRootHideMode:(id)sender;
- (void)addToBlacklist:(NSString *)bundleID;
- (void)removeFromBlacklist:(NSString *)bundleID;
- (void)refreshBlacklist;
- (void)applyRootHideSettings;

@end
