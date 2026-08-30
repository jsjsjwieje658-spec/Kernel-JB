#include <Foundation/Foundation.h>

#include <spawn.h>
#include <roothide.h>

#include "common.h"
#include "Hooking.h"

extern char **environ;

typedef void (^LSOpenCompletionHandler)(BOOL success, NSError *error);
#pragma GCC diagnostic ignored "-Wobjc-method-access"
#pragma GCC diagnostic ignored "-Wunused-variable"

/*lsd can only get path for normal app via proc_pidpath, or we can use
  xpc_connection_get_audit_token([connection _xpcConnection], &token) //_LSCopyExecutableURLForXPCConnection
  proc_pidpath_audittoken(tokenarg, buffer, size) //_LSCopyExecutableURLForAuditToken
  */

@interface LSApplicationProxy : NSObject
+ (id)applicationProxyForIdentifier:(id)arg1;
- (NSURL *)bundleURL;
@end

@interface LSApplicationWorkspace : NSObject
+ (LSApplicationWorkspace *)defaultWorkspace;
- (NSArray *)applicationsAvailableForHandlingURLScheme:(NSString *)scheme;
- (NSArray *)applicationsAvailableForOpeningURL:(NSURL *)url legacySPI:(BOOL)legacySPI;
- (NSArray *)applicationsAvailableForOpeningURL:(NSURL *)url;
@end

BOOL isJailbreakURLScheme(NSString *scheme) {
    NSArray *apps = [[NSClassFromString(@"LSApplicationWorkspace") defaultWorkspace]
        applicationsAvailableForHandlingURLScheme:scheme];
    for (id app in apps) //LSApplicationProxy
    {
        NSURL *bundleURL = [app performSelector:@selector(bundleURL)];
        if (!bundleURL)
            continue;

        if (isJailbreakBundlePath(bundleURL.path.fileSystemRepresentation)) {
            return YES;
        }
    }
    return NO;
}

static const void *kBlockSchemeTagKey = &kBlockSchemeTagKey;

CHDeclareClass(_LSURLOverride);

CHMethod1(id, _LSURLOverride, initWithOriginalURL, NSURL *, url) {
    NSNumber *tag = objc_getAssociatedObject(url, kBlockSchemeTagKey);
    if (tag && tag.boolValue) {
        return nil;
    }
    return CHSuper1(_LSURLOverride, initWithOriginalURL, url);
}

CHDeclareClass(_LSCanOpenURLManager);

CHMethod3(void *,
          _LSCanOpenURLManager,
          getIsURL,
          NSURL *,
          url,
          alwaysCheckable,
          BOOL *,
          pCheckable,
          hasHandler,
          BOOL *,
          pHasHandler) {
    BOOL _checkable = NO;
    BOOL _hasHandler = NO;
    void
        *result = CHSuper3(_LSCanOpenURLManager, getIsURL, url, alwaysCheckable, &_checkable, hasHandler, &_hasHandler);
    if (_checkable || _hasHandler) {
        NSNumber *tag = objc_getAssociatedObject(url, kBlockSchemeTagKey);
        if (tag && tag.boolValue) {
            _hasHandler = NO;
            _checkable = NO;
        }
    }

    if (pCheckable)
        *pCheckable = _checkable;
    if (pHasHandler)
        *pHasHandler = _hasHandler;
    return result;
}

CHMethod5(BOOL,
          _LSCanOpenURLManager,
          canOpenURL,
          NSURL *,
          url,
          publicSchemes,
          BOOL,
          ispublic,
          privateSchemes,
          BOOL,
          isprivate,
          XPCConnection,
          NSXPCConnection *,
          connection,
          error,
          NSError *__autoreleasing *,
          perror) {
    BOOL blocked = NO;

    if (connection) //connection=nil if comes from lsd server
    {
        pid_t pid = connection.processIdentifier;

        if (jbclient_blacklist_check_pid(pid) == true) {
            if (isJailbreakURLScheme(url.scheme)) {
                objc_setAssociatedObject(url, kBlockSchemeTagKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

                blocked = YES;
            }
        }
    }

    BOOL ret = CHSuper5(_LSCanOpenURLManager,
                        canOpenURL,
                        url,
                        publicSchemes,
                        ispublic,
                        privateSchemes,
                        isprivate,
                        XPCConnection,
                        connection,
                        error,
                        perror);
    if (blocked) {
        assert(ret == NO);
    }
    return ret;
}

@interface _LSDOpenClient : NSObject
@property(retain, readonly) NSXPCConnection *XPCConnection;
@end

CHDeclareClass(_LSDOpenClient);

CHMethod4(void,
          _LSDOpenClient,
          openApplicationWithIdentifier,
          NSString *,
          identifier,
          options,
          id,
          options,
          useClientProcessHandle,
          BOOL,
          useClientProcessHandle,
          completionHandler,
          LSOpenCompletionHandler,
          completionHandler) {
    BOOL blocked = NO;

    if (self.XPCConnection) {
        pid_t pid = self.XPCConnection.processIdentifier;

        if (jbclient_blacklist_check_pid(pid) == true) {
            LSApplicationProxy *appProxy = [NSClassFromString(@"LSApplicationProxy")
                applicationProxyForIdentifier:identifier];
            if (appProxy && isJailbreakBundlePath(appProxy.bundleURL.path.fileSystemRepresentation)) {
                useClientProcessHandle = YES;

                blocked = YES;
            }
        }
    }

    id newcallback = ^(BOOL success, NSError *error) {
        if (blocked) {
            assert(success == NO);
        }

        return completionHandler(success, error);
    };

    CHSuper4(_LSDOpenClient,
             openApplicationWithIdentifier,
             identifier,
             options,
             options,
             useClientProcessHandle,
             useClientProcessHandle,
             completionHandler,
             newcallback);
}

//16.2(?)+
CHMethod4(void,
          _LSDOpenClient,
          openURL,
          NSURL *,
          url,
          fileHandle,
          id,
          fileHandle,
          options,
          id,
          options,
          completionHandler,
          LSOpenCompletionHandler,
          completionHandler) {
    BOOL blocked = NO;

    if (self.XPCConnection) {
        pid_t pid = self.XPCConnection.processIdentifier;

        if (jbclient_blacklist_check_pid(pid) == true) {
            if (isJailbreakURLScheme(url.scheme)) {
                objc_setAssociatedObject(url, kBlockSchemeTagKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

                blocked = YES;
            }
        }
    }

    id newcallback = ^(BOOL success, NSError *error) {
        if (blocked) {
            assert(success == NO);
        }

        return completionHandler(success, error);
    };

    CHSuper4(_LSDOpenClient, openURL, url, fileHandle, fileHandle, options, options, completionHandler, newcallback);
}

//15.0~16.0(?)
CHMethod3(void,
          _LSDOpenClient,
          openURL,
          NSURL *,
          url,
          options,
          id,
          options,
          completionHandler,
          LSOpenCompletionHandler,
          completionHandler) {
    BOOL blocked = NO;

    if (self.XPCConnection) {
        pid_t pid = self.XPCConnection.processIdentifier;

        if (jbclient_blacklist_check_pid(pid) == true) {
            if (isJailbreakURLScheme(url.scheme)) {
                objc_setAssociatedObject(url, kBlockSchemeTagKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

                blocked = YES;
            }
        }
    }

    id newcallback = ^(BOOL success, NSError *error) {
        if (blocked) {
            assert(success == NO);
        }

        return completionHandler(success, error);
    };

    CHSuper3(_LSDOpenClient, openURL, url, options, options, completionHandler, newcallback);
}

@interface LSPlugInQueryWithUnits : NSObject
- (id)initWithPlugInUnits:(id)units forDatabaseWithUUID:(id)dbUUID;
@end

@interface _LSQueryContext : NSObject
- (NSMutableDictionary *)_resolveQueries:(NSSet *)queries
                           XPCConnection:(NSXPCConnection *)connection
                                   error:(NSError *)error;
@end

CHDeclareClass(_LSQueryContext);

CHMethod3(NSMutableDictionary *,
          _LSQueryContext,
          _resolveQueries,
          NSSet *,
          queries,
          XPCConnection,
          NSXPCConnection *,
          connection,
          error,
          NSError *,
          error) {
    NSMutableDictionary
        *result = CHSuper3(_LSQueryContext, _resolveQueries, queries, XPCConnection, connection, error, error);
    /*
        result: @{
                queries[0]: @[data1, data2, ...],
                queries[1]: @[data1, data2, ...],
        }
        */

    if (!result || !connection) {
        return result;
    }

    pid_t pid = connection.processIdentifier;

    if (jbclient_blacklist_check_pid(pid) == false) {
        return result;
    }

    for (id key in result) {
        if ([key isKindOfClass:NSClassFromString(@"LSPlugInQueryWithUnits")] ||
            [key isKindOfClass:NSClassFromString(@"LSPlugInQueryWithIdentifier")] ||
            [key isKindOfClass:NSClassFromString(@"LSPlugInQueryWithQueryDictionary")]) {
            NSMutableArray *plugins = result[key];

            NSMutableIndexSet *removed = [[NSMutableIndexSet alloc] init];
            for (int i = 0; i < [plugins count]; i++) {
                id plugin = plugins[i]; //LSPlugInKitProxy
                id appbundle = [plugin performSelector:@selector(containingBundle)];
                if (!appbundle)
                    continue;

                NSURL *bundleURL = [appbundle performSelector:@selector(bundleURL)];
                if (isJailbreakBundlePath(bundleURL.path.fileSystemRepresentation)) {
                    [removed addIndex:i];
                }
            }

            [plugins removeObjectsAtIndexes:removed];

            if ([key isKindOfClass:NSClassFromString(@"LSPlugInQueryWithUnits")]) {
                NSMutableArray *units = [[key valueForKey:@"_pluginUnits"] mutableCopy];
                [units removeObjectsAtIndexes:removed];
                [key setValue:[units copy] forKey:@"_pluginUnits"];
            }
        } else if ([key isKindOfClass:NSClassFromString(@"LSPlugInQueryAllUnits")]) {
            NSMutableArray *unitsArray = result[key];
            for (int i = 0; i < [unitsArray count]; i++) {
                id unitsResult = unitsArray[i]; //LSPlugInQueryAllUnitsResult

                NSUUID *_dbUUID = [unitsResult valueForKey:@"_dbUUID"];
                NSArray *_pluginUnits = [unitsResult valueForKey:@"_pluginUnits"];
                id unitQuery = [[NSClassFromString(@"LSPlugInQueryWithUnits") alloc] initWithPlugInUnits:_pluginUnits
                                                                                     forDatabaseWithUUID:_dbUUID];
                NSMutableDictionary *queriesResult = [self _resolveQueries:[NSSet setWithObject:unitQuery]
                                                             XPCConnection:connection
                                                                     error:error];
                if (queriesResult) {
                    for (id queryKey in queriesResult) {
                        NSArray *new_pluginUnits = [queryKey valueForKey:@"_pluginUnits"];
                        [unitsResult setValue:new_pluginUnits forKey:@"_pluginUnits"];
                    }
                }
            }
        }
    }

    return result;
}

// =====================================================================
// RootHide port (Dopamine2-roothide lsd.x UTTypeHooks parity):
//
// WHY THIS EXISTS: apps can enumerate the system UTType (Uniform Type
// Identifier) database through the _LSDReadClient XPC interface. Types
// declared by jailbreak apps (Sileo's source/document types, tweak-provided
// UTIs, ...) stay registered in lsd's database, so a blacklisted app asking
// "which types exist" / "who declared type X" sees jailbreak bundle records
// -> jailbreak detected. Upstream Dopamine2-roothide filters ALL of these
// queries for blacklisted clients; the Relaxin port this fork started from
// never had this subsystem, so it was missing entirely.
//
// HOW IT WORKS (same as upstream):
//   - The _LSDReadClient method hooks below detect requests coming from a
//     blacklisted pid and raise the thread-local g_utrHide flag around the
//     original call.
//   - While the flag is up, the C-level enumeration functions
//     (_UTEnumerateTypesFor*, _UTTypeSearch*) skip every type unit whose
//     declaring bundle lives at a jailbreak path, and the schema cache is
//     bypassed (force recompute / prevent caching) so filtered results are
//     never stored.
//   - g_utrBusy keeps OUR OWN nested database probes out of the filters
//     (utrUnitIsJailbreak itself instantiates type records).
//
// MRC NOTE: this file compiles with -fno-objc-arc. All wrapper blocks are
// used strictly synchronously inside the hooked C functions (never stored),
// so stack blocks are safe. Objects we create use -autorelease.
// =====================================================================

@interface UTTypeRecord : NSObject
+ (id)typeRecordWithIdentifier:(id)identifier;
- (unsigned int)tableID;
@end

@interface _UTDeclaredTypeRecord : NSObject
- (id)_initWithContext:(void *)ctx tableID:(unsigned int)tableID unitID:(unsigned int)unitID;
- (BOOL)isDeclared;
- (BOOL)isCoreType;
- (BOOL)isInPublicDomain;
- (id)identifier;
- (id)declaringBundleRecord;
- (unsigned int)unitID;
- (unsigned int)_rawFlags;
@end

@interface LSBundleRecord : NSObject
- (NSURL *)URL;
@end

@interface _LSDReadClient : NSObject
- (NSXPCConnection *)XPCConnection;
@end

static __thread BOOL g_utrHide = NO; // raised by the _LSDReadClient hooks for blacklisted requests
static __thread int g_utrBusy = 0;   // >0 while we ourselves touch the DB, to keep our access out of the filters

static BOOL utrFilterActive(void) {
    return g_utrHide && !g_utrBusy;
}

static pid_t utrClientPid(_LSDReadClient *client) {
    NSXPCConnection *conn = [client XPCConnection];
    return conn ? conn.processIdentifier : -1;
}

static BOOL utrHideClientBlacklisted(_LSDReadClient *client) {
    pid_t pid = utrClientPid(client);
    if (pid > 0 && jbclient_blacklist_check_pid(pid)) {
        return YES;
    }
    return NO;
}

// type-units table id; constant for the database. Read once, off the hot
// path, via a public accessor.
static unsigned int utrTypeTableID(void) {
    static unsigned int tid = 0;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        // guard this probe's own nested lookup so it is never filtered,
        // independent of the caller. g_utrBusy is a counter, so this nests
        // cleanly inside utrUnitIsJailbreak's busy region.
        g_utrBusy++;
        tid = (unsigned int)[[NSClassFromString(@"UTTypeRecord") typeRecordWithIdentifier:@"public.data"] tableID];
        g_utrBusy--;
    });
    return tid;
}

// YES only when `rec` is a *declared* type whose active declaring bundle is
// a jailbreak bundle, and which is not an Apple core / public-domain type
// (those are never touched).
static BOOL utrRecordIsFromJailbreakApp(_UTDeclaredTypeRecord *rec) {
    if (![rec isDeclared])
        return NO; // dynamic/undeclared -> already the "absent" shape
    if ([rec isCoreType])
        return NO; // Apple core type -> never touched
    if ([rec isInPublicDomain])
        return NO; // public.* -> never touched
    LSBundleRecord *bundleRec = [rec declaringBundleRecord];
    NSURL *url = [bundleRec URL];
    if (![url isKindOfClass:[NSURL class]] || !url.isFileURL)
        return NO;
    if (!isJailbreakBundlePath(url.path.fileSystemRepresentation))
        return NO;

    RHLogDebug(@"[UTType] hide type id=%@ bundle=%@", [rec identifier], url);
    return YES;
}

// build a record for an enumerated unitID and decide if it belongs to a
// jailbreak app.
static BOOL utrUnitIsJailbreak(void *db, intptr_t unitID) {
    BOOL result = NO;
    g_utrBusy++; // keep our own nested DB access out of the filters
    unsigned int tid = utrTypeTableID();
    if (tid) {
        void *ctx = db; // _initWithContext: reads *(void**)ctx (offset 0) == db
        _UTDeclaredTypeRecord *rec = [[[NSClassFromString(@"_UTDeclaredTypeRecord") alloc]
            _initWithContext:(void *)&ctx
                     tableID:tid
                      unitID:(unsigned int)unitID] autorelease];
        result = utrRecordIsFromJailbreakApp(rec);
    }
    g_utrBusy--;
    return result;
}

/////////////////////////////////////////////////////////////////////

typedef intptr_t (^UTREnumBlock)(intptr_t a2, intptr_t unitID, const void *unitBytes, void *a5);

static void (*orig__UTEnumerateTypesForTag)(void *db, void *tagClass, void *tag, id block);
static void new__UTEnumerateTypesForTag(void *db, void *tagClass, void *tag, id block) {
    if (!utrFilterActive() || !block) {
        orig__UTEnumerateTypesForTag(db, tagClass, tag, block);
        return;
    }

    UTREnumBlock orig = (UTREnumBlock)block;
    UTREnumBlock wrapper = ^intptr_t(intptr_t a2, intptr_t unitID, const void *unitBytes, void *a5) {
        if (utrUnitIsJailbreak(db, unitID))
            return 0; // drop -> continue enumeration, nothing recorded
        return orig(a2, unitID, unitBytes, a5); // forward to the original callback
    };
    orig__UTEnumerateTypesForTag(db, tagClass, tag, wrapper);
}

static void (*orig__UTEnumerateTypesForIdentifier)(void *db, long identStrId, id block);
static void new__UTEnumerateTypesForIdentifier(void *db, long identStrId, id block) {
    if (!utrFilterActive() || !block) {
        orig__UTEnumerateTypesForIdentifier(db, identStrId, block);
        return;
    }

    UTREnumBlock orig = (UTREnumBlock)block;
    UTREnumBlock wrapper = ^intptr_t(intptr_t a2, intptr_t unitID, const void *unitBytes, void *a5) {
        if (utrUnitIsJailbreak(db, unitID))
            return 0;
        return orig(a2, unitID, unitBytes, a5);
    };
    orig__UTEnumerateTypesForIdentifier(db, identStrId, wrapper);
}

typedef void (^UTRConformBlock)(intptr_t unitID, const void *unitBytes, intptr_t kind, unsigned char *outStop);

static void (*orig__UTTypeSearchConformingTypesWithBlock)(void *db, long unitID, long flags, long arg4, id block);
static void new__UTTypeSearchConformingTypesWithBlock(void *db, long unitID, long flags, long arg4, id block) {
    if (!utrFilterActive() || !block) {
        orig__UTTypeSearchConformingTypesWithBlock(db, unitID, flags, arg4, block);
        return;
    }

    UTRConformBlock orig = (UTRConformBlock)block;
    UTRConformBlock wrapper = ^void(intptr_t uid, const void *unitBytes, intptr_t kind, unsigned char *outStop) {
        if (utrUnitIsJailbreak(db, uid))
            return; // drop conforming JB type -> outStop stays 0, keep enumerating
        orig(uid, unitBytes, kind, outStop); // forward to the original callback
    };
    orig__UTTypeSearchConformingTypesWithBlock(db, unitID, flags, arg4, wrapper);
}

// parents/forward conformance: filters JB parent types out of related-types
// (degree>0) and out of a record's serialized parentTypeIdentifiers/
// conformsTo list. _UTTypeConformsTo's boolean verdict goes through
// ...Common (not WithBlock), so it is unaffected.
static void (*orig__UTTypeSearchConformsToTypesWithBlock)(void *db, long unitID, long flags, long arg4, id block);
static void new__UTTypeSearchConformsToTypesWithBlock(void *db, long unitID, long flags, long arg4, id block) {
    if (!utrFilterActive() || !block) {
        orig__UTTypeSearchConformsToTypesWithBlock(db, unitID, flags, arg4, block);
        return;
    }

    UTRConformBlock orig = (UTRConformBlock)block;
    UTRConformBlock wrapper = ^void(intptr_t uid, const void *unitBytes, intptr_t kind, unsigned char *outStop) {
        if (utrUnitIsJailbreak(db, uid))
            return; // drop conforming-to (parent) JB type -> keep enumerating
        orig(uid, unitBytes, kind, outStop); // forward to the original callback
    };
    orig__UTTypeSearchConformsToTypesWithBlock(db, unitID, flags, arg4, wrapper);
}

static void (*orig__LSSchemaCacheRead)(void *a1, id block);
static void new__LSSchemaCacheRead(void *a1, id block) {
    if (utrFilterActive())
        return; // force cache miss -> recompute (filtered)
    orig__LSSchemaCacheRead(a1, block);
}

static void (*orig__LSSchemaCacheWrite)(void *a1, id block);
static void new__LSSchemaCacheWrite(void *a1, id block) {
    if (utrFilterActive())
        return; // don't cache the hidden result
    orig__LSSchemaCacheWrite(a1, block);
}

CHDeclareClass(_LSDReadClient);

CHMethod4(void,
          _LSDReadClient,
          getTypeRecordWithTag,
          id,
          tag,
          ofClass,
          id,
          _class,
          conformingToIdentifier,
          id,
          identifier,
          completionHandler,
          id,
          handler) {
    if (!utrHideClientBlacklisted(self)) {
        CHSuper4(_LSDReadClient, getTypeRecordWithTag, tag, ofClass, _class, conformingToIdentifier, identifier, completionHandler, handler);
        return;
    }
    RHLogDebug(@"[UTType] getTypeRecordWithTag:%@ ofClass:%@ conforming:%@ pid=%d", tag, _class, identifier, utrClientPid(self));
    g_utrHide = YES;
    CHSuper4(_LSDReadClient, getTypeRecordWithTag, tag, ofClass, _class, conformingToIdentifier, identifier, completionHandler, handler);
    g_utrHide = NO;
}

CHMethod4(void,
          _LSDReadClient,
          getTypeRecordsWithTag,
          id,
          tag,
          ofClass,
          id,
          _class,
          conformingToIdentifier,
          id,
          identifier,
          completionHandler,
          id,
          handler) {
    if (!utrHideClientBlacklisted(self)) {
        CHSuper4(_LSDReadClient, getTypeRecordsWithTag, tag, ofClass, _class, conformingToIdentifier, identifier, completionHandler, handler);
        return;
    }
    RHLogDebug(@"[UTType] getTypeRecordsWithTag:%@ ofClass:%@ conforming:%@ pid=%d", tag, _class, identifier, utrClientPid(self));
    g_utrHide = YES;
    CHSuper4(_LSDReadClient, getTypeRecordsWithTag, tag, ofClass, _class, conformingToIdentifier, identifier, completionHandler, handler);
    g_utrHide = NO;
}

CHMethod3(void,
          _LSDReadClient,
          getTypeRecordWithIdentifier,
          id,
          identifier,
          allowUndeclared,
          BOOL,
          allowUndeclared,
          completionHandler,
          id,
          handler) {
    if (!utrHideClientBlacklisted(self)) {
        CHSuper3(_LSDReadClient, getTypeRecordWithIdentifier, identifier, allowUndeclared, allowUndeclared, completionHandler, handler);
        return;
    }
    RHLogDebug(@"[UTType] getTypeRecordWithIdentifier:%@ allowUndeclared:%d pid=%d", identifier, allowUndeclared, utrClientPid(self));
    g_utrHide = YES;
    CHSuper3(_LSDReadClient, getTypeRecordWithIdentifier, identifier, allowUndeclared, allowUndeclared, completionHandler, handler);
    g_utrHide = NO;
}

CHMethod2(void,
          _LSDReadClient,
          getTypeRecordsWithIdentifiers,
          id,
          identifiers,
          completionHandler,
          id,
          handler) {
    if (!utrHideClientBlacklisted(self)) {
        CHSuper2(_LSDReadClient, getTypeRecordsWithIdentifiers, identifiers, completionHandler, handler);
        return;
    }
    RHLogDebug(@"[UTType] getTypeRecordsWithIdentifiers:%@ pid=%d", identifiers, utrClientPid(self));
    g_utrHide = YES;
    CHSuper2(_LSDReadClient, getTypeRecordsWithIdentifiers, identifiers, completionHandler, handler);
    g_utrHide = NO;
}

CHMethod3(void,
          _LSDReadClient,
          getTypeRecordForImportedTypeWithIdentifier,
          id,
          identifier,
          conformingToIdentifier,
          id,
          conforming,
          completionHandler,
          id,
          handler) {
    if (!utrHideClientBlacklisted(self)) {
        CHSuper3(_LSDReadClient, getTypeRecordForImportedTypeWithIdentifier, identifier, conformingToIdentifier, conforming, completionHandler, handler);
        return;
    }
    RHLogDebug(@"[UTType] getTypeRecordForImportedTypeWithIdentifier:%@ conforming:%@ pid=%d", identifier, conforming, utrClientPid(self));
    g_utrHide = YES;
    CHSuper3(_LSDReadClient, getTypeRecordForImportedTypeWithIdentifier, identifier, conformingToIdentifier, conforming, completionHandler, handler);
    g_utrHide = NO;
}

CHMethod3(void,
          _LSDReadClient,
          getRelatedTypesOfTypeWithIdentifier,
          id,
          identifier,
          maximumDegreeOfSeparation,
          NSInteger,
          degree,
          completionHandler,
          id,
          handler) {
    if (!utrHideClientBlacklisted(self)) {
        CHSuper3(_LSDReadClient, getRelatedTypesOfTypeWithIdentifier, identifier, maximumDegreeOfSeparation, degree, completionHandler, handler);
        return;
    }
    RHLogDebug(@"[UTType] getRelatedTypesOfTypeWithIdentifier:%@ degree:%ld pid=%d", identifier, (long)degree, utrClientPid(self));
    g_utrHide = YES;
    CHSuper3(_LSDReadClient, getRelatedTypesOfTypeWithIdentifier, identifier, maximumDegreeOfSeparation, degree, completionHandler, handler);
    g_utrHide = NO;
}

CHMethod3(void,
          _LSDReadClient,
          getWhetherTypeIdentifier,
          id,
          identifier,
          conformsToTypeIdentifier,
          id,
          other,
          completionHandler,
          id,
          handler) {
    if (!utrHideClientBlacklisted(self)) {
        CHSuper3(_LSDReadClient, getWhetherTypeIdentifier, identifier, conformsToTypeIdentifier, other, completionHandler, handler);
        return;
    }
    RHLogDebug(@"[UTType] getWhetherTypeIdentifier:%@ conformsToTypeIdentifier:%@ pid=%d", identifier, other, utrClientPid(self));
    g_utrHide = YES;
    CHSuper3(_LSDReadClient, getWhetherTypeIdentifier, identifier, conformsToTypeIdentifier, other, completionHandler, handler);
    g_utrHide = NO;
}

CHMethod4(void,
          _LSDReadClient,
          getResourceValuesForKeys,
          id,
          keys,
          URL,
          id,
          url,
          preferredLocalizations,
          id,
          locs,
          completionHandler,
          id,
          handler) {
    if (!utrHideClientBlacklisted(self)) {
        CHSuper4(_LSDReadClient, getResourceValuesForKeys, keys, URL, url, preferredLocalizations, locs, completionHandler, handler);
        return;
    }
    RHLogDebug(@"[UTType] getResourceValuesForKeys:%@ URL:%@ pid=%d", keys, url, utrClientPid(self));
    g_utrHide = YES;
    CHSuper4(_LSDReadClient, getResourceValuesForKeys, keys, URL, url, preferredLocalizations, locs, completionHandler, handler);
    g_utrHide = NO;
}

CHMethod2(void,
          _LSDReadClient,
          getBoundIconInfoForDocumentProxy,
          id,
          documentProxy,
          completionHandler,
          id,
          handler) {
    if (!utrHideClientBlacklisted(self)) {
        CHSuper2(_LSDReadClient, getBoundIconInfoForDocumentProxy, documentProxy, completionHandler, handler);
        return;
    }
    RHLogDebug(@"[UTType] getBoundIconInfoForDocumentProxy:%@ pid=%d", documentProxy, utrClientPid(self));
    g_utrHide = YES;
    CHSuper2(_LSDReadClient, getBoundIconInfoForDocumentProxy, documentProxy, completionHandler, handler);
    g_utrHide = NO;
}

//or -[Copier initWithSourceURL:uniqueIdentifier:destURL:callbackTarget:selector:options:] in transitd
NSURL *(*orig_LSGetInboxURLForBundleIdentifier)(NSString *bundleIdentifier) = NULL;
NSURL *new_LSGetInboxURLForBundleIdentifier(NSString *bundleIdentifier) {
    NSURL *pathURL = orig_LSGetInboxURLForBundleIdentifier(bundleIdentifier);

    if (![bundleIdentifier hasPrefix:@"com.apple."] &&
        [pathURL.path hasPrefix:@"/var/mobile/Library/Application Support/Containers/"]) {
        pathURL = [NSURL fileURLWithPath:jbroot(pathURL.path)]; //require unsandboxing file-write-read for jbroot:/var/
    }

    return pathURL;
}

int (*orig_LSServer_RebuildApplicationDatabases)() = NULL;
int new_LSServer_RebuildApplicationDatabases() {
    int r = orig_LSServer_RebuildApplicationDatabases();

    if (access(jbroot("/.disable_auto_uicache"), F_OK) == 0)
        return r;

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        // Ensure jailbreak apps are readded to icon cache after the system reloads it
        // A bit hacky, but works
        char *const args[] = {"/usr/bin/uicache", "-a", NULL};
        const char *uicachePath = jbroot(args[0]);
        if (access(uicachePath, F_OK) == 0) {
            pid_t pid = 0;
            int spawnerr = posix_spawn(&pid, uicachePath, NULL, NULL, args, environ);
            if (spawnerr == 0) {
                wait_for_exit(pid);
            }
        }
    });

    return r;
}

void lsdInit(void) {
    MSImageRef coreServicesImage = MSGetImageByName("/System/Library/Frameworks/CoreServices.framework/CoreServices");

    void *_LSGetInboxURLForBundleIdentifier = MSFindSymbol(coreServicesImage, "__LSGetInboxURLForBundleIdentifier");
    if (_LSGetInboxURLForBundleIdentifier) {
        MSHookFunction(_LSGetInboxURLForBundleIdentifier,
                       (void *)&new_LSGetInboxURLForBundleIdentifier,
                       (void **)&orig_LSGetInboxURLForBundleIdentifier);
    }

    void *_LSServer_RebuildApplicationDatabases = MSFindSymbol(coreServicesImage,
                                                               "__LSServer_RebuildApplicationDatabases");
    if (_LSServer_RebuildApplicationDatabases) {
        MSHookFunction(_LSServer_RebuildApplicationDatabases,
                       (void *)&new_LSServer_RebuildApplicationDatabases,
                       (void **)&orig_LSServer_RebuildApplicationDatabases);
    }

    // RootHide port (Dopamine2-roothide lsd.x parity): UTType subsystem
    // hiding for blacklisted clients. Install ONLY when all six CoreServices
    // symbols resolve (same gating as upstream's %init(UTTypeHooks, ...));
    // partial installation could leave the schema-cache bypass active
    // without the enumeration filters (or vice versa) and corrupt lsd's
    // type database view for blacklisted clients.
    {
        void *symSchemaCacheRead = MSFindSymbol(coreServicesImage, "__LSSchemaCacheRead");
        void *symSchemaCacheWrite = MSFindSymbol(coreServicesImage, "__LSSchemaCacheWrite");
        void *symEnumerateTypesForTag = MSFindSymbol(coreServicesImage, "__UTEnumerateTypesForTag");
        void *symEnumerateTypesForIdentifier = MSFindSymbol(coreServicesImage, "__UTEnumerateTypesForIdentifier");
        void *symSearchConformingTypesWithBlock = MSFindSymbol(coreServicesImage, "__UTTypeSearchConformingTypesWithBlock");
        void *symSearchConformsToTypesWithBlock = MSFindSymbol(coreServicesImage, "__UTTypeSearchConformsToTypesWithBlock");
        if (symSchemaCacheRead && symSchemaCacheWrite && symEnumerateTypesForTag && symEnumerateTypesForIdentifier &&
            symSearchConformingTypesWithBlock && symSearchConformsToTypesWithBlock) {
            RHLogDebug(@"UTTypeHooks: installing");
            MSHookFunction(symSchemaCacheRead, (void *)&new__LSSchemaCacheRead, (void **)&orig__LSSchemaCacheRead);
            MSHookFunction(symSchemaCacheWrite, (void *)&new__LSSchemaCacheWrite, (void **)&orig__LSSchemaCacheWrite);
            MSHookFunction(symEnumerateTypesForTag, (void *)&new__UTEnumerateTypesForTag, (void **)&orig__UTEnumerateTypesForTag);
            MSHookFunction(symEnumerateTypesForIdentifier,
                           (void *)&new__UTEnumerateTypesForIdentifier,
                           (void **)&orig__UTEnumerateTypesForIdentifier);
            MSHookFunction(symSearchConformingTypesWithBlock,
                           (void *)&new__UTTypeSearchConformingTypesWithBlock,
                           (void **)&orig__UTTypeSearchConformingTypesWithBlock);
            MSHookFunction(symSearchConformsToTypesWithBlock,
                           (void *)&new__UTTypeSearchConformsToTypesWithBlock,
                           (void **)&orig__UTTypeSearchConformsToTypesWithBlock);

            CHLoadLateClass(_LSDReadClient);
            CHHook4(_LSDReadClient, getTypeRecordWithTag, ofClass, conformingToIdentifier, completionHandler);
            CHHook4(_LSDReadClient, getTypeRecordsWithTag, ofClass, conformingToIdentifier, completionHandler);
            CHHook3(_LSDReadClient, getTypeRecordWithIdentifier, allowUndeclared, completionHandler);
            CHHook2(_LSDReadClient, getTypeRecordsWithIdentifiers, completionHandler);
            CHHook3(_LSDReadClient, getTypeRecordForImportedTypeWithIdentifier, conformingToIdentifier, completionHandler);
            CHHook3(_LSDReadClient, getRelatedTypesOfTypeWithIdentifier, maximumDegreeOfSeparation, completionHandler);
            CHHook3(_LSDReadClient, getWhetherTypeIdentifier, conformsToTypeIdentifier, completionHandler);
            CHHook4(_LSDReadClient, getResourceValuesForKeys, URL, preferredLocalizations, completionHandler);
            CHHook2(_LSDReadClient, getBoundIconInfoForDocumentProxy, completionHandler);
        }
        else {
            RHLogError(@"UTTypeHooks: NOT installed (missing CoreServices symbols)");
        }
    }

    CHLoadLateClass(_LSURLOverride);
    CHLoadLateClass(_LSCanOpenURLManager);
    CHLoadLateClass(_LSDOpenClient);
    CHLoadLateClass(_LSQueryContext);

    CHHook1(_LSURLOverride, initWithOriginalURL);
    CHHook3(_LSCanOpenURLManager, getIsURL, alwaysCheckable, hasHandler);
    CHHook5(_LSCanOpenURLManager, canOpenURL, publicSchemes, privateSchemes, XPCConnection, error);
    CHHook4(_LSDOpenClient, openApplicationWithIdentifier, options, useClientProcessHandle, completionHandler);
    CHHook4(_LSDOpenClient, openURL, fileHandle, options, completionHandler);
    CHHook3(_LSDOpenClient, openURL, options, completionHandler);
    CHHook3(_LSQueryContext, _resolveQueries, XPCConnection, error);

    RHLogDebug(@"lsd hooks initialized");
}
