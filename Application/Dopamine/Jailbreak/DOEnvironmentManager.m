//
//  EnvironmentManager.m
//  Dopamine
//
//  Created by Lars Fröder on 10.01.24.
//

#import "DOEnvironmentManager.h"
#import "UIImage+JPEG2000.h"

#import <sys/sysctl.h>
#import <sys/mount.h>
#import <sys/utsname.h>
#import <sys/stat.h>
#import <unistd.h>
#import <mach-o/dyld.h>
#import <libgrabkernel2/libgrabkernel2.h>
#import <libjailbreak/info.h>
#import <libjailbreak/codesign.h>
#import <libjailbreak/util.h>
#import <libjailbreak/display.h>
#import <libjailbreak/machine_info.h>
#import <libjailbreak/carboncopy.h>

#import <IOKit/IOKitLib.h>
#import "DOUIManager.h"
#import "DOExploitManager.h"
#import "DOPreferenceManager.h"
#import "NSData+Hex.h"
#import <LocalAuthentication/LocalAuthentication.h>

int reboot3(uint64_t flags, ...);
CFPropertyListRef MGCopyAnswer(CFStringRef);
extern char **environ;

@implementation DOEnvironmentManager

+ (instancetype)sharedManager
{
    static DOEnvironmentManager *shared;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shared = [[DOEnvironmentManager alloc] init];
    });
    return shared;
}

- (instancetype)init
{
    self = [super init];
    if (self) {
        _bootstrapNeedsMigration = NO;
        _bootstrapper = [[DOBootstrapper alloc] init];
        if ([self isJailbroken]) {
            gSystemInfo.jailbreakInfo.rootPath = strdup(jbclient_get_jbroot() ?: "");
        }
        else if ([self isInstalledThroughTrollStore]) {
            [self locateJailbreakRoot];
        }
    }
    return self;
}

- (NSString *)nightlyHash
{
#ifdef NIGHTLY
    return [NSString stringWithUTF8String:COMMIT_HASH];
#else
    return nil;
#endif
}

- (NSString *)appVersion
{
    return [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
}

- (NSString *)appVersionDisplayString
{
    NSString *nightlyHash = [self nightlyHash];
    if (nightlyHash) {
        return [NSString stringWithFormat:@"%@~%@", self.appVersion, [nightlyHash substringToIndex:6]];
    }
    else {
        return [self appVersion];
    }
}

- (NSString *)privatePrebootPath
{
    return @"/private/preboot";
}

- (NSString *)activePrebootPath
{
    NSString *bootManifestString = [NSString stringWithUTF8String:boot_manifest_hash()];
    return [[self privatePrebootPath] stringByAppendingPathComponent:bootManifestString];
}

// ROOTHIDE FIX: Generate a JBRAND matching RootHide format.
// RootHide roothideinit.dylib requires jbroot dir name = ".jbroot-XXXXXXXXXXXXXXXX"
// (16 hex uppercase, byte 0 = XOR checksum of bytes 1..7).
static NSString *generateRootHideJBRAND(void)
{
    uint64_t value = ((uint64_t)arc4random()) | ((uint64_t)arc4random() << 32);
    uint8_t check = (value >> 8) ^ (value >> 16) ^ (value >> 24) ^
                    (value >> 32) ^ (value >> 40) ^ (value >> 48) ^ (value >> 56);
    uint64_t jbrand = (value & ~0xFFULL) | check;
    return [NSString stringWithFormat:@"%016llX", jbrand];
}

static BOOL checkRootHideJBRAND(NSString *str)
{
    if (str.length != 16) return NO;
    const char *cstr = str.UTF8String;
    char *endp = NULL;
    unsigned long long value = strtoull(cstr, &endp, 16);
    if (!endp || *endp != '\0') return NO;
    uint8_t check = (value >> 8) ^ (value >> 16) ^ (value >> 24) ^
                    (value >> 32) ^ (value >> 40) ^ (value >> 48) ^ (value >> 56);
    return check == (uint8_t)value;
}

- (void)locateJailbreakRoot
{
    if (!gSystemInfo.jailbreakInfo.rootPath) {
        // ROOTHIDE: jbroot is at /var/containers/Bundle/Application/.jbroot-XXXXXXXXXXXXXXXX
        // This path format is REQUIRED by roothideinit.dylib is_jbroot_name().
        NSString *jbrootSearchPath = @"/var/containers/Bundle/Application";
        NSString *randomizedJailbreakPath;

        // AMFI blocks NSFileManager from listing /var/containers/Bundle/Application/
        // even when running as root. We MUST use exec_cmd_root to spawn /bin/ls
        // with persona override — the child process gets a fresh AMFI context.
        NSLog(@"[RootHide] locateJailbreakRoot: listing %@ via exec_cmd_root", jbrootSearchPath);

        // Create a pipe to capture /bin/ls output
        int pipefd[2];
        if (pipe(pipefd) != 0) {
            NSLog(@"[RootHide] locateJailbreakRoot: pipe() failed");
            return;
        }

        pid_t pid = 0;
        posix_spawn_file_actions_t action;
        posix_spawn_file_actions_init(&action);
        posix_spawn_file_actions_adddup2(&action, pipefd[1], STDOUT_FILENO);
        posix_spawn_file_actions_addclose(&action, pipefd[0]);
        posix_spawn_file_actions_addclose(&action, pipefd[1]);

        posix_spawnattr_t attr;
        posix_spawnattr_init(&attr);
        posix_spawnattr_set_persona_np(&attr, 99, POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);
        posix_spawnattr_set_persona_uid_np(&attr, 0);
        posix_spawnattr_set_persona_gid_np(&attr, 0);

        char *argv[] = {"/bin/ls", "-1a", (char *)jbrootSearchPath.UTF8String, NULL};
        int spawnErr = posix_spawn(&pid, "/bin/ls", &action, &attr, argv, NULL);
        posix_spawnattr_destroy(&attr);
        posix_spawn_file_actions_destroy(&action);
        close(pipefd[1]);

        if (spawnErr != 0) {
            close(pipefd[0]);
            NSLog(@"[RootHide] locateJailbreakRoot: /bin/ls spawn failed: %d", spawnErr);
            // Fallback: try NSFileManager (might work after unsandbox)
            NSError *listError = nil;
            NSArray *fmItems = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:jbrootSearchPath error:&listError];
            if (listError) {
                NSLog(@"[RootHide] locateJailbreakRoot: NSFileManager also failed: %@", listError);
            } else if (fmItems) {
                // FIX: length must be 24 (8 prefix `.jbroot-` + 16 hex jbrand),
                // not 23. With length==23, substringFromIndex:8 returns 15 chars
                // and checkRootHideJBRAND() always returns NO (it requires 16),
                // causing every jailbreak to create a NEW .jbroot-XXX instead
                // of reusing the existing one.
                for (NSString *subItem in fmItems) {
                    if (subItem.length == 24 && [subItem hasPrefix:@".jbroot-"]) {
                        NSString *jbrandStr = [subItem substringFromIndex:8];
                        if (checkRootHideJBRAND(jbrandStr)) {
                            randomizedJailbreakPath = [jbrootSearchPath stringByAppendingPathComponent:subItem];
                            NSLog(@"[RootHide] locateJailbreakRoot: FOUND via NSFileManager: %@", randomizedJailbreakPath);
                            break;
                        }
                    }
                }
            }
        } else {
            // Read /bin/ls output.
            // FIX: 16 KB is too small for /var/containers/Bundle/Application,
            // which can hold 500+ app UUIDs once tweaks are installed
            // (each UUID = 36 chars + newline = 37 bytes; 16 KB / 37 ≈ 440).
            // Use a growable NSMutableData and read until EOF so the .jbroot-
            // entry is never truncated off the end of the buffer.
            NSMutableData *outData = [NSMutableData dataWithCapacity:262144];
            char chunk[8192];
            ssize_t n;
            while ((n = read(pipefd[0], chunk, sizeof(chunk))) > 0) {
                [outData appendBytes:chunk length:(NSUInteger)n];
                if (outData.length >= 4 * 1024 * 1024) break; // 4 MB hard cap
            }
            close(pipefd[0]);
            int status = 0;
            if (pid > 0) waitpid(pid, &status, 0);

            if (outData.length > 0) {
                NSString *output = [[NSString alloc] initWithData:outData encoding:NSUTF8StringEncoding];
                if (!output) {
                    NSLog(@"[RootHide] locateJailbreakRoot: failed to decode /bin/ls output (length=%lu)", (unsigned long)outData.length);
                    output = @"";
                }
                NSArray *subItems = [output componentsSeparatedByString:@"\n"];
                NSLog(@"[RootHide] locateJailbreakRoot: /bin/ls -1a found %lu items", (unsigned long)subItems.count);

                for (NSString *subItem in subItems) {
                    NSString *trimmed = [subItem stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
                    if (trimmed.length == 0) continue;
                    if ([trimmed hasPrefix:@"."]) {
                        NSLog(@"[RootHide] locateJailbreakRoot: found hidden: %@", trimmed);
                    }
                    // FIX: length == 24 (not 23) — see comment above.
                    if (trimmed.length == 24 && [trimmed hasPrefix:@".jbroot-"]) {
                        NSString *jbrandStr = [trimmed substringFromIndex:8];
                        BOOL valid = checkRootHideJBRAND(jbrandStr);
                        NSLog(@"[RootHide] locateJailbreakRoot: .jbroot- found, jbrand=%@ valid=%d", jbrandStr, valid);
                        if (valid) {
                            randomizedJailbreakPath = [jbrootSearchPath stringByAppendingPathComponent:trimmed];
                            NSLog(@"[RootHide] locateJailbreakRoot: FOUND existing jbroot at %@", randomizedJailbreakPath);
                            break;
                        }
                    }
                }
            } else {
                NSLog(@"[RootHide] locateJailbreakRoot: /bin/ls produced no output");
            }
        }

        // Legacy migration
        if (!randomizedJailbreakPath) {
            NSLog(@"[RootHide] locateJailbreakRoot: no .jbroot-XXX found, checking legacy /private/preboot");
            NSString *activePrebootPath = [self activePrebootPath];
            for (NSString *subItem in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:activePrebootPath error:nil]) {
                if (subItem.length == 15 && [subItem hasPrefix:@"dopamine-"]) {
                    NSString *legacyPath = [activePrebootPath stringByAppendingPathComponent:subItem];
                    NSString *legacyProcursus = [legacyPath stringByAppendingPathComponent:@"procursus"];
                    if ([[NSFileManager defaultManager] fileExistsAtPath:[legacyProcursus stringByAppendingPathComponent:@".installed_dopamine"]]) {
                        randomizedJailbreakPath = legacyPath;
                        _bootstrapNeedsMigration = YES;
                        NSLog(@"[RootHide] locateJailbreakRoot: found legacy dopamine path: %@", legacyPath);
                        break;
                    }
                }
            }
        }

        if (randomizedJailbreakPath) {
            if ([[NSFileManager defaultManager] fileExistsAtPath:randomizedJailbreakPath]) {
                gSystemInfo.jailbreakInfo.rootPath = strdup(randomizedJailbreakPath.fileSystemRepresentation);
                NSLog(@"[RootHide] locateJailbreakRoot: set rootPath to %s", gSystemInfo.jailbreakInfo.rootPath);
            }
        } else {
            NSLog(@"[RootHide] locateJailbreakRoot: NO existing jbroot found — will create new");
        }
    }
}

- (NSError *)ensureJailbreakRootExists
{
    NSError *error = nil;

    // ROOTHIDE FIX: Clear rootPath and re-scan.
    // locateJailbreakRoot was called in init() BEFORE elevatePrivileges,
    // so it found the legacy /private/preboot path (not .jbroot-XXX).
    // Now that we ARE root, clear rootPath and re-scan so we can find
    // existing .jbroot-XXX via /bin/ls (which needs root for AMFI).
    if (gSystemInfo.jailbreakInfo.rootPath) {
        NSString *oldPath = [NSString stringWithUTF8String:gSystemInfo.jailbreakInfo.rootPath];
        // Only clear if it's the legacy path (contains /private/preboot)
        if ([oldPath containsString:@"/private/preboot/"]) {
            NSLog(@"[RootHide] ensureJailbreakRootExists: clearing legacy rootPath %@ to re-scan", oldPath);
            free(gSystemInfo.jailbreakInfo.rootPath);
            gSystemInfo.jailbreakInfo.rootPath = NULL;
        }
    }

    [self locateJailbreakRoot];

    // DOPACLEAN logic to move a corrupted dopamine directory to a different path to at least make jailbreaking work again
    // if (gSystemInfo.jailbreakInfo.rootPath) {
    //     NSString *randomizedJailbreakPath = [NSString stringWithUTF8String:gSystemInfo.jailbreakInfo.rootPath].stringByDeletingLastPathComponent;
    //     NSString *characterSet = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    //     NSUInteger stringLen = 6;
    //     NSMutableString *randomString = [NSMutableString stringWithCapacity:stringLen];
    //     for (NSUInteger i = 0; i < stringLen; i++) {
    //         NSUInteger randomIndex = arc4random_uniform((uint32_t)[characterSet length]);
    //         unichar randomCharacter = [characterSet characterAtIndex:randomIndex];
    //         [randomString appendFormat:@"%C", randomCharacter];
    //     }
    //
    //     NSString *activePrebootPath = [self activePrebootPath];
    //     NSString *orphanedName = [NSString stringWithFormat:@"orphaned-%@", randomString];
    //     NSString *orphanedPath = [activePrebootPath stringByAppendingPathComponent:orphanedName];
    //     [[NSFileManager defaultManager] moveItemAtPath:randomizedJailbreakPath toPath:orphanedPath error:nil];
    // }

    // return [NSError errorWithDomain:@"Cleaned" code:1 userInfo:nil];

    if (!gSystemInfo.jailbreakInfo.rootPath || _bootstrapNeedsMigration) {
        // ROOTHIDE: Create jbroot at /var/containers/Bundle/Application/.jbroot-XXXXXXXXXXXXXXXX
        // This path format is REQUIRED by roothideinit.dylib is_jbroot_name().
        NSString *jbrandStr = generateRootHideJBRAND();
        NSString *randomJailbreakFolderName = [NSString stringWithFormat:@".jbroot-%@", jbrandStr];
        NSString *randomizedJailbreakPath = [@"/var/containers/Bundle/Application" stringByAppendingPathComponent:randomJailbreakFolderName];

        // If migrating from old Dopamine path, delete the old directory.
        if (_bootstrapNeedsMigration) {
            NSString *oldPath = [NSString stringWithUTF8String:gSystemInfo.jailbreakInfo.rootPath];
            NSString *oldDopamineDir = [oldPath stringByDeletingLastPathComponent];
            NSLog(@"[RootHide] Removing old Dopamine bootstrap at %@", oldDopamineDir);
            // Use exec_cmd_root (persona override) for rm -rf
            exec_cmd_root("/bin/rm", "-rf", oldDopamineDir.fileSystemRepresentation, NULL);
            free(gSystemInfo.jailbreakInfo.rootPath);
            gSystemInfo.jailbreakInfo.rootPath = NULL;
            _bootstrapNeedsMigration = NO;
        }

        // Create the new .jbroot-XXX directory.
        //
        // WHY exec_cmd_root instead of mkdir(2):
        //   Even though we setuid(0) and unsandbox (mac_label_set), the AMFI
        //   MAC policy still blocks direct mkdir on /var/containers/Bundle/Application/
        //   from within the Dopamine app process.  The RootHide Bootstrap app
        //   avoids this by spawning a CHILD process via posix_spawn with
        //   persona override (POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE + uid 0).
        //   The child process runs with a FRESH AMFI context that allows
        //   the mkdir to succeed.
        //
        //   We use the same approach: spawn /bin/mkdir via exec_cmd_root,
        //   which calls posix_spawnattr_set_persona_np(99, OVERRIDE) +
        //   posix_spawnattr_set_persona_uid_np(0) + gid 0.
        NSLog(@"[RootHide] Creating jbroot at %@ via root spawn", randomizedJailbreakPath);
        int mkdirRet = exec_cmd_root("/bin/mkdir", "-m", "0755",
                                      randomizedJailbreakPath.fileSystemRepresentation, NULL);
        if (mkdirRet != 0) {
            // Fallback: try mkdir(2) directly
            NSLog(@"[RootHide] exec_cmd_root mkdir returned %d, trying direct mkdir(2)", mkdirRet);
            const char *path = randomizedJailbreakPath.fileSystemRepresentation;
            if (mkdir(path, 0755) != 0 && errno != EEXIST) {
                error = [NSError errorWithDomain:NSPOSIXErrorDomain code:errno
                                       userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"Failed to create jbroot directory %s: %s", path, strerror(errno)]}];
                NSLog(@"[RootHide] mkdir(2) also failed: %s", strerror(errno));
            }
            else {
                chown(path, 0, 0);
                NSLog(@"[RootHide] mkdir(2) succeeded for %@", randomizedJailbreakPath);
                gSystemInfo.jailbreakInfo.rootPath = strdup(randomizedJailbreakPath.UTF8String);
            }
        }
        else {
            // chown to root:wheel via root spawn too
            exec_cmd_root("/usr/sbin/chown", "root:wheel",
                          randomizedJailbreakPath.fileSystemRepresentation, NULL);
            NSLog(@"[RootHide] Created jbroot at %@", randomizedJailbreakPath);
            gSystemInfo.jailbreakInfo.rootPath = strdup(randomizedJailbreakPath.UTF8String);

            // ROOTHIDE FIX LỖI 2 (CRITICAL): Tạo .jbroot và rootfs symlinks tại jbroot root
            //
            // Phân tích RootHide Bootstrap gốc (bootstrap-1800.tar):
            //   ./.jbroot  ->  .         (symlink đến chính jbroot)
            //   ./rootfs   ->  /         (symlink đến rootfs thật)
            //   ./dev      ->  /dev       (symlink đến /dev)
            //
            // Mục đích của các symlinks này:
            //   1. `.jbroot -> .` cho phép relative paths hoạt động trong mọi subdir.
            //      Ví dụ: /usr/bin/.jbroot -> ../../.jbroot (relative) → trỏ về jbroot root.
            //      Khi một binary ở /usr/bin/ gọi dlopen("@loader_path/.jbroot/usr/lib/..."),
            //      @loader_path = /usr/bin/, .jbroot = ../../.jbroot = jbroot root, OK.
            //
            //   2. `rootfs -> /` cho phép tweaks truy cập system rootfs thật.
            //      Ví dụ: tweak cần đọc /System/Library/... → jbroot/rootfs/System/Library/...
            //
            //   3. `dev -> /dev` cho phép tạo device nodes.
            //
            // QUAN TRỌNG: RootHide Bootstrap GỐC KHÔNG bind mount /System, /usr!
            // Họ dùng libvroot (virtual rootfs) để intercept system calls thay vì bind mount.
            // Dopamine rootless port sang roothide lại vẫn bind mount /System, /usr, /usr/lib
            // → bị lộ qua getmntinfo() → RootHide app cảnh báo "Unknown Bindfs Mount(s)".
            //
            // FIX tạm thời (không thể remove bind mount vì Dopamine cần chúng):
            //   - Hook getmntinfo/statfs để filter out bind mount entries
            //   - Tạo .jbroot + rootfs symlinks để đảm bảo tương thích RootHide app
            NSFileManager *fm = [NSFileManager defaultManager];
            NSString *jbrootDotLink = [randomizedJailbreakPath stringByAppendingPathComponent:@".jbroot"];
            NSString *rootfsLink = [randomizedJailbreakPath stringByAppendingPathComponent:@"rootfs"];
            NSString *devLink = [randomizedJailbreakPath stringByAppendingPathComponent:@"dev"];

            // Remove existing symlinks if any (idempotent)
            [fm removeItemAtPath:jbrootDotLink error:nil];
            [fm removeItemAtPath:rootfsLink error:nil];
            [fm removeItemAtPath:devLink error:nil];

            // Create .jbroot -> . (self-reference, relative)
            // Phải dùng relative path "." chứ không phải absolute path, vì:
            //   - libvroot có thể remove absolute symlinks
            //   - relative path vẫn đúng khi jbroot được rename (re-randomize)
            NSError *linkErr = nil;
            if ([fm createSymbolicLinkAtPath:jbrootDotLink withDestinationPath:@"." error:&linkErr]) {
                NSLog(@"[RootHide] Created .jbroot -> . (self) at %@", jbrootDotLink);
            } else {
                NSLog(@"[RootHide] FAILED to create .jbroot symlink: %@", linkErr);
            }

            // Create rootfs -> / (system rootfs)
            linkErr = nil;
            if ([fm createSymbolicLinkAtPath:rootfsLink withDestinationPath:@"/" error:&linkErr]) {
                NSLog(@"[RootHide] Created rootfs -> / at %@", rootfsLink);
            } else {
                NSLog(@"[RootHide] FAILED to create rootfs symlink: %@", linkErr);
            }

            // Create dev -> /dev
            linkErr = nil;
            if ([fm createSymbolicLinkAtPath:devLink withDestinationPath:@"/dev" error:&linkErr]) {
                NSLog(@"[RootHide] Created dev -> /dev at %@", devLink);
            } else {
                NSLog(@"[RootHide] FAILED to create dev symlink: %@", linkErr);
            }
        }
    }

    return error;
}

- (BOOL)isArm64e
{
    cpu_subtype_t cpusubtype = 0;
    size_t len = sizeof(cpusubtype);
    if (sysctlbyname("hw.cpusubtype", &cpusubtype, &len, NULL, 0) == -1) return NO;
    return (cpusubtype & ~CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E;
}

- (BOOL)isSPTM
{
    if (@available(iOS 17.0, *)) {
        io_registry_entry_t memory_map = IORegistryEntryFromPath(kIOMainPortDefault, "IODeviceTree:/chosen/memory-map");
        if (memory_map == IO_OBJECT_NULL)   return NO;

        CFArrayRef keys = (CFArrayRef)IORegistryEntryCreateCFProperty(memory_map, CFSTR(kIORegistryEntryPropertyKeysKey), kCFAllocatorDefault, 0);
        IOObjectRelease(memory_map);
        if (!keys)  return NO;

        CFRange range = CFRangeMake(0, CFArrayGetCount(keys));

        bool isSPTM = CFArrayContainsValue(keys, range, CFSTR("SPTM")) && CFArrayContainsValue(keys, range, CFSTR("TXM"));
        CFRelease(keys);

        return isSPTM;
    }
    return false;
}

- (NSString *)versionSupportString
{
    cpu_subtype_t cpuFamily = 0;
    size_t cpuFamilySize = sizeof(cpuFamily);
    sysctlbyname("hw.cpufamily", &cpuFamily, &cpuFamilySize, NULL, 0);
    
    if ([self isArm64e]) {
        if (cpuFamily == CPUFAMILY_ARM_VORTEX_TEMPEST || cpuFamily == CPUFAMILY_ARM_LIGHTNING_THUNDER) {
            return @"iOS 15.0 - 18.7.1, 26.0 - 26.0.1 (A12/A13, PPL)";
        }
        else if (![self isSPTM]) {
            return @"iOS 15.0 - 17.3.1 (PPL)";
        }
        else {
            return @"iOS 17.0 - 17.3.1 (SPTM)";
        }
    }
    else {
        return @"iOS 15.0 - 18.7.1 (arm64e)";
    }
}

- (BOOL)isInstalledThroughTrollStore
{
    static BOOL trollstoreInstallation = NO;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSString* trollStoreMarkerPath = [[[NSBundle mainBundle].bundlePath stringByDeletingLastPathComponent] stringByAppendingPathComponent:@"_TrollStore"];
        trollstoreInstallation = [[NSFileManager defaultManager] fileExistsAtPath:trollStoreMarkerPath];
    });
    return trollstoreInstallation;
}

- (void)updateJailbreakState
{
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        char *jbVersionC = NULL;
        _isJailbroken = jbclient_dopamine_is_jailbroken(&jbVersionC);
        if (jbVersionC) {
            _jailbrokenVersion = [NSString stringWithUTF8String:jbVersionC];
            free(jbVersionC);
        }
    });
}

- (BOOL)isJailbroken
{
    [self updateJailbreakState];
    return _isJailbroken;
}

- (void)setJailbroken:(BOOL)jailbroken withVersion:(NSString *)version
{
    _isJailbroken = jailbroken;
    if (_isJailbroken) _jailbrokenVersion = version;
}

- (BOOL)isJailbrokenWithOtherJailbreak
{
    if (![self isJailbroken]) {
        uint32_t csFlags = 0;
        csops(getpid(), CS_OPS_STATUS, &csFlags, sizeof(csFlags));
        
        // Palera1n
        if (csFlags & CS_PLATFORM_BINARY) return YES;
        
        // Older Dopamine build
        if (!access("/usr/lib/systemhook.dylib", F_OK)) return YES;
    }
    return NO;
}

- (NSString *)jailbrokenVersion
{
    [self updateJailbreakState];
    if (!_isJailbroken) return nil;
    return _jailbrokenVersion;
}

- (NSString *)systemVersion
{
    return (__bridge NSString *)MGCopyAnswer((__bridge CFStringRef)@"ProductVersion");
}

- (BOOL)isBootstrapped
{
    return (BOOL)jbinfo(rootPath);
}

- (void)runUnsandboxed:(void (^)(void))unsandboxBlock
{
    if ([self isInstalledThroughTrollStore]) {
        unsandboxBlock();
    }
    else if ([self isJailbroken]) {
        uint64_t labelBackup = 0;
        jbclient_root_set_mac_label(1, -1, &labelBackup);
        unsandboxBlock();
        jbclient_root_set_mac_label(1, labelBackup, NULL);
    }
    else {
        // Hope that we are already unsandboxed
        unsandboxBlock();
    }
}

- (void)runAsRoot:(void (^)(void))rootBlock
{
    uint32_t orgUser = geteuid();
    uint32_t orgGroup = getegid();
    
    if (orgUser == 0 && orgGroup == 0) {
        rootBlock();
        return;
    }

    if (self.isJailbroken) {
        if (jbclient_dopamine_get_root() == 0) {
            rootBlock();
            jbclient_dopamine_drop_root();
        }
    }
}

- (int)spawnJbctlAsRootWithArgs:(NSArray *)args
{
    bool needsLegacySolution = false;
    if (self.jailbrokenVersion) {
        needsLegacySolution = (strcmp(self.jailbrokenVersion.UTF8String, "3.0.5") < 0);
    }

    char **argBuf = malloc((args.count + 4) * sizeof(char *));
    argBuf[0] = strdup(JBROOT_PATH("/basebin/jbctl"));
    int i = 1;
    for (NSString *arg in args) {
        argBuf[i++] = strdup(arg.UTF8String);
    }

    if (!needsLegacySolution) {
        argBuf[i++] = strdup("--waitfor");
        argBuf[i++] = strdup("3");
    }
    argBuf[i++] = NULL;
    
    posix_spawn_file_actions_t act = NULL;
        posix_spawn_file_actions_init(&act);
    posix_spawnattr_t attr = NULL;
    posix_spawnattr_init(&attr);
     
    int waitPipe[2];
    
    if (!needsLegacySolution) {
        pipe(waitPipe);
        posix_spawn_file_actions_adddup2(&act, waitPipe[0], 3);
    }
    else {
        posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);
    }

    __block int pid = 0;
    __block int r = -1;

    // Capture the jbctl path string BEFORE we free argBuf[] below so that
    // if posix_spawn fails we can log which path we tried (the user-reported
    // "app crashes at final step" is almost always posix_spawn returning
    // ENOENT because <jbroot>/basebin/jbctl doesn't exist or is the wrong
    // path; without this log it was impossible to diagnose).
    NSString *jbctlPathForLog = [NSString stringWithUTF8String:argBuf[0]];

    [self runAsRoot:^{
        [self runUnsandboxed:^{
            r = posix_spawn(&pid, argBuf[0], &act, &attr, (char *const *)argBuf, (char *const *)environ);
            if (needsLegacySolution) {
                // Legacy solution is a gamble, which is why it was removed and superseeded by --waitfor
                // But if jailbroken with <3.0.5, jbctl doesn't support --waitfor yet
                kill(pid, SIGCONT);
            }
        }];
        // We *NEED* to leave this block on iOS 17+ to avoid a panic, --waitfor ensures this always happens
    }];

    posix_spawnattr_destroy(&attr);
    posix_spawn_file_actions_destroy(&act);
    for (int y = 0; y < i; y++) {
        free(argBuf[y]);
    }
    free(argBuf);

    if (!needsLegacySolution) {
        if (r == 0) {
            // We left the root/unsandbox block, now resume jbctl by writing to pipe
            char w = 'w';
            write(waitPipe[1], &w, sizeof(w));
        }
        else {
            // FIX: posix_spawn FAILED. The previous code silently fell through
            // to `return cmd_wait_for_exit(pid)` with pid == 0 (still its
            // initial value because posix_spawn never overwrote it).
            // `cmd_wait_for_exit(0)` calls `waitpid(0, ...)` which on POSIX
            // means "wait for ANY child in the calling process group" —
            // this blocks forever, and the iOS watchdog eventually kills
            // the app. The user perceives this as "app crashes at the
            // final jailbreak step, no userspace reboot".
            //
            // Common causes of posix_spawn failure here:
            //   ENOENT — <jbroot>/basebin/jbctl doesn't exist (ensureJailbreakRootExists
            //             picked the wrong jbroot path, or bootstrap extraction failed)
            //   EACCES — AMFI rejected the binary (cdhash not in trustcache)
            //   E2BIG  — argv too long (shouldn't happen here)
            NSLog(@"[RootHide] spawnJbctlAsRootWithArgs: posix_spawn FAILED for '%@' (errno=%d: %s)",
                  jbctlPathForLog, r, strerror(r));
            close(waitPipe[0]);
            close(waitPipe[1]);
            return r;
        }

        close(waitPipe[0]);
        close(waitPipe[1]);
    }

    return cmd_wait_for_exit(pid);
}

- (int)runTrollStoreAction:(NSString *)action
{
    if (![self isInstalledThroughTrollStore]) return -1;
    
    uint32_t selfPathSize = PATH_MAX;
    char selfPath[selfPathSize];
    _NSGetExecutablePath(selfPath, &selfPathSize);
    return exec_cmd_root(selfPath, "trollstore", action.UTF8String, NULL);
}

- (void)respring
{
    [self spawnJbctlAsRootWithArgs:@[@"respring"]];
}

- (void)rebootUserspace
{
    // ROOTHIDE FIX LỖI 1 (CRITICAL):
    // Trước đây hàm này chỉ gọi spawnJbctlAsRootWithArgs 1 lần, ignore return value.
    // Nếu posix_spawn fail (ENOENT/EACCES) hoặc jbctl reboot3 syscall fail,
    // app sẽ sit ở fadeToBlack forever → watchdog kill → user thấy "JB crash cuối".
    //
    // PHIÊN BẢN NÀY: CHỈ REBOOT USERSPACE, KHÔNG HARD REBOOT THIẾT BỊ.
    //
    // User yêu cầu rõ ràng: "tôi chỉ muốn reboot vô userspace thôi chx ko muốn reboot máy"
    // → Loại bỏ hoàn toàn /sbin/reboot (hard reboot) khỏi fallback chain.
    // Lý do: hard reboot sẽ làm device mất JB state, user phải re-jailbreak từ đầu.
    //
    // FIX:
    //   1) Pre-check jbctl binary tồn tại
    //   2) Trust-cache jbctl một lần cuối (defensive — cdhash có thể bị clear)
    //   3) Retry spawnJbctlAsRootWithArgs 3 lần với sleep 200ms giữa các lần
    //      (lý do: posix_spawn có thể transient fail do AMFI/port pressure)
    //   4) Nếu retry hết fail → fallback respring (kill backboardd via sbreload)
    //   5) Nếu respring cũng fail → thử respring via killall backboardd SIGTERM
    //   6) Nếu vẫn fail → exit(0) để app tự close, user có thể vào home screen
    //      và re-jailbreak khi cần (KHÔNG hard reboot để giữ JB state)

    NSString *jbctlPath = [NSString stringWithUTF8String:JBROOT_PATH("/basebin/jbctl")];
    if (![[NSFileManager defaultManager] fileExistsAtPath:jbctlPath]) {
        NSLog(@"[RootHide] rebootUserspace: jbctl NOT FOUND at %@", jbctlPath);
        NSString *errMsg = [NSString stringWithFormat:
            @"Cannot reboot userspace: jbctl binary not found at %@.\n"
            @"This means basebin.tar was not extracted correctly into the jbroot.\n"
            @"Falling back to respring (kill backboardd).", jbctlPath];
        [[DOUIManager sharedInstance] sendLog:errMsg debug:NO];
        NSLog(@"[RootHide] rebootUserspace: falling back to respring (no jbctl)");
        [self respring];
        return;
    }

    // Pre-flight: trust-cache jbctl defensive (cdhash có thể bị clear nếu
    // kernel primitive đã cleanup hoặc memory pressure cao). Idempotent.
    int tcR = jbclient_trust_file_by_path(jbctlPath.fileSystemRepresentation);
    NSLog(@"[RootHide] rebootUserspace: pre-flight trust-cache jbctl (r=%d)", tcR);

    // Retry loop: 3 lần với sleep 200ms
    int r = -1;
    for (int attempt = 1; attempt <= 3; attempt++) {
        NSLog(@"[RootHide] rebootUserspace: attempt %d/3 spawning jbctl reboot_userspace", attempt);
        r = [self spawnJbctlAsRootWithArgs:@[@"reboot_userspace"]];
        NSLog(@"[RootHide] rebootUserspace: attempt %d returned %d", attempt, r);

        if (r == 0) {
            // jbctl exited cleanly → reboot3 likely succeeded.
            // Process sẽ bị kill bởi reboot3 syscall trong ~1-2s.
            NSLog(@"[RootHide] rebootUserspace: SUCCESS — jbctl exited cleanly, reboot3 likely triggered. App should be killed by the reboot.");
            return;
        }

        // Log error chi tiết
        NSString *errMsg;
        if (r > 0) {
            errMsg = [NSString stringWithFormat:
                @"Userspace reboot attempt %d failed (jbctl exit code %d).\n"
                @"Common causes:\n"
                @"  • jbctl cdhash not in trustcache (pre-flight should have fixed this)\n"
                @"  • jbctl entitlements not honored (re-sign with ldid)\n"
                @"  • iOS version mismatch (reboot3 RB2_USERREBOOT not supported on this iOS)\n",
                attempt, r];
        } else {
            int errnoVal = -r;
            errMsg = [NSString stringWithFormat:
                @"Userspace reboot attempt %d failed to spawn jbctl (errno %d: %s).\n",
                attempt, errnoVal, strerror(errnoVal)];
        }
        [[DOUIManager sharedInstance] sendLog:errMsg debug:NO];
        fprintf(stderr, "[RootHide] rebootUserspace attempt %d FAILED: %s\n", attempt, errMsg.UTF8String);

        // Sleep 200ms trước retry (tránh spawn quá nhanh)
        if (attempt < 3) {
            usleep(200000);
        }
    }

    // Tất cả 3 retry đều fail → fallback respring
    NSLog(@"[RootHide] rebootUserspace: ALL 3 attempts failed, falling back to respring (kill backboardd)");
    [[DOUIManager sharedInstance] sendLog:@"Userspace reboot failed 3 times. Falling back to respring (SpringBoard reload, NO hard reboot)..." debug:NO];
    [self respring];

    // Đợi 2s để respring có hiệu lực (kill backboardd + sbreload)
    usleep(2000000);

    // ROOTHIDE FIX: Nếu respring cũng fail, thử fallback #2 — kill backboardd trực tiếp.
    // KHÔNG gọi /sbin/reboot (hard reboot) — user yêu cầu rõ ràng KHÔNG hard reboot.
    NSLog(@"[RootHide] rebootUserspace: respring via jbctl likely failed, trying direct killall backboardd");
    [[DOUIManager sharedInstance] sendLog:@"Respring likely failed. Trying direct killall backboardd (NO hard reboot to preserve JB state)..." debug:NO];
    exec_cmd_trusted(JBROOT_PATH("/usr/bin/killall"), "-9", "backboardd", NULL);

    // Đợi 3s
    usleep(3000000);

    // Fallback #3: exit app gracefully — user có thể vào home screen và re-jailbreak
    // KHÔNG hard reboot để giữ JB state (đã inject vào launchd/SpringBoard)
    NSLog(@"[RootHide] rebootUserspace: all soft reboots failed, exiting app gracefully (NO hard reboot — JB state preserved)");
    [[DOUIManager sharedInstance] sendLog:@"All soft reboots failed. Exiting app. Your jailbreak state is preserved — re-open Dopamine to re-trigger userspace reboot." debug:NO];
    // Để app exit về home screen thay vì hard reboot
    // User có thể re-open Dopamine app → app sẽ detect "isJailbroken" và trigger reboot lại
}


- (void)refreshJailbreakApps
{
    [self runAsRoot:^{
        [self runUnsandboxed:^{
            exec_cmd(JBROOT_PATH("/usr/bin/uicache"), "-a", NULL);
        }];
    }];
}

- (void)unregisterJailbreakApps
{
    [self runAsRoot:^{
        [self runUnsandboxed:^{
            NSArray *jailbreakApps = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:JBROOT_PATH(@"/Applications") error:nil];
            if (jailbreakApps.count) {
                for (NSString *jailbreakApp in jailbreakApps) {
                    NSString *jailbreakAppPath = [JBROOT_PATH(@"/Applications") stringByAppendingPathComponent:jailbreakApp];
                    exec_cmd(JBROOT_PATH("/usr/bin/uicache"), "-u", jailbreakAppPath.fileSystemRepresentation, NULL);
                }
            }
        }];
    }];
}

- (void)reboot
{
    [self runAsRoot:^{
        [self runUnsandboxed:^{
            reboot3(0x8000000000000000, 0);
        }];
    }];
}


- (void)changeMobilePassword:(NSString *)newPassword
{
    [self runAsRoot:^{
        [self runUnsandboxed:^{
            // FIX: previously `pw usermod 501 -h 0` was used, but `pw usermod`
            // treats the first positional arg as a USERNAME, not a UID.
            // Looking up user "501" fails with "user '501' disappeared during update".
            // The correct syntax is `pw usermod -u 501 -h 0` (use -u flag for UID).
            //
            // Also escape single quotes in the password to prevent shell injection
            // (the password is passed via printf, so we only need to escape ' for the
            // outer single-quoted dash -c argument).
            NSString *escapedPassword = [newPassword stringByReplacingOccurrencesOfString:@"'" withString:@"'\\''"];
            NSString *dashCommand = [NSString stringWithFormat:@"printf \"%%s\\n\" '%@' | %@ usermod -u 501 -h 0", escapedPassword, JBROOT_PATH(@"/usr/sbin/pw")];
            NSLog(@"[RootHide] changeMobilePassword: running pw usermod -u 501 -h 0");
            int r = exec_cmd(JBROOT_PATH("/usr/bin/dash"), "-c", dashCommand.UTF8String, NULL);
            if (r != 0) {
                NSLog(@"[RootHide] changeMobilePassword: pw returned %d, trying chpasswd fallback", r);
                // FIX: bỏ `su -q passwd root` (su không có option -q trong Procursus,
                // và `echo '...' | su` truyền password vào stdin của su chứ không phải
                // passwd → không work). `|| true` cuối cũng nuốt hết error → user
                // tưởng đổi pass OK nhưng thực ra không.
                // Fallback chỉ dùng `chpasswd` (đúng syntax cho Procursus).
                // Lưu ý: chpasswd nhận input dạng "user:password" trên stdin.
                NSString *fallbackCmd = [NSString stringWithFormat:@"printf 'mobile:%@\\n' | %@ chpasswd 2>&1",
                    escapedPassword,
                    JBROOT_PATH(@"/usr/sbin/chpasswd")];
                int r2 = exec_cmd(JBROOT_PATH("/usr/bin/dash"), "-c", fallbackCmd.UTF8String, NULL);
                if (r2 != 0) {
                    NSLog(@"[RootHide] changeMobilePassword: chpasswd also failed (%d), password NOT changed", r2);
                } else {
                    NSLog(@"[RootHide] changeMobilePassword: chpasswd fallback OK");
                }
            }
        }];
    }];
}

- (NSError*)updateEnvironment
{
    NSString *newBasebinTarPath = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"basebin.tar"];
    int result = jbclient_platform_stage_jailbreak_update(newBasebinTarPath.fileSystemRepresentation);
    if (result == 0) {
        [self rebootUserspace];
        return nil;
    }
    return [NSError errorWithDomain:@"Dopamine" code:result userInfo:nil];
}

- (void)updateJailbreakFromTIPA:(NSString *)tipaPath
{
    [self spawnJbctlAsRootWithArgs:@[@"update", @"tipa", tipaPath]];
}

- (BOOL)isTweakInjectionEnabled
{
    return ![[NSFileManager defaultManager] fileExistsAtPath:JBROOT_PATH(@"/basebin/.safe_mode")];
}

- (void)setTweakInjectionEnabled:(BOOL)enabled
{
    NSString *safeModePath = JBROOT_PATH(@"/basebin/.safe_mode");
    if ([self isJailbroken]) {
        [self runAsRoot:^{
            [self runUnsandboxed:^{
                if (enabled) {
                    [[NSFileManager defaultManager] removeItemAtPath:safeModePath error:nil];
                }
                else {
                    [[NSData data] writeToFile:safeModePath atomically:YES];
                }
            }];
        }];
    }
}

- (BOOL)isIDownloadEnabled
{
    __block BOOL isEnabled = NO;
    [self runAsRoot:^{
        [self runUnsandboxed:^{
            NSDictionary *disabledDict = [NSDictionary dictionaryWithContentsOfFile:@"/var/db/com.apple.xpc.launchd/disabled.plist"];
            NSNumber *idownloaddDisabledNum = disabledDict[@"com.opa334.Dopamine.idownloadd"];
            if (idownloaddDisabledNum) {
                isEnabled = ![idownloaddDisabledNum boolValue];
            }
            else {
                isEnabled = NO;
            }
        }];
    }];
    return isEnabled;
}

- (void)setIDownloadEnabled:(BOOL)enabled needsUnsandbox:(BOOL)needsUnsandbox
{
    void (^updateBlock)(void) = ^{
        if (enabled) {
            exec_cmd_trusted(JBROOT_PATH("/usr/bin/launchctl"), "enable", "system/com.opa334.Dopamine.idownloadd", NULL);
        }
        else {
            exec_cmd_trusted(JBROOT_PATH("/usr/bin/launchctl"), "disable", "system/com.opa334.Dopamine.idownloadd", NULL);
        }
    };

    if (needsUnsandbox) {
        [self runAsRoot:^{
            [self runUnsandboxed:updateBlock];
        }];
    }
    else {
        updateBlock();
    }
}

- (void)setIDownloadLoaded:(BOOL)loaded needsUnsandbox:(BOOL)needsUnsandbox
{
    if (loaded) {
        [self setIDownloadEnabled:loaded needsUnsandbox:needsUnsandbox];
    }
    
    void (^updateBlock)(void) = ^{
        if (loaded) {
            exec_cmd(JBROOT_PATH("/usr/bin/launchctl"), "load", JBROOT_PATH("/basebin/LaunchDaemons/com.opa334.Dopamine.idownloadd.plist"), NULL);
        }
        else {
            exec_cmd(JBROOT_PATH("/usr/bin/launchctl"), "unload", JBROOT_PATH("/basebin/LaunchDaemons/com.opa334.Dopamine.idownloadd.plist"), NULL);
        }
    };
    
    if (needsUnsandbox) {
        [self runAsRoot:^{
            [self runUnsandboxed:updateBlock];
        }];
    }
    else {
        updateBlock();
    }
    
    if (!loaded) {
        [self setIDownloadEnabled:loaded needsUnsandbox:needsUnsandbox];
    }
}

- (BOOL)isFakelibMounted
{
    struct statfs fsb;
    if (statfs("/usr/lib", &fsb) != 0) return NO;
    return strcmp(fsb.f_mntonname, "/usr/lib") == 0;
}

- (int)setFakelibMounted:(BOOL)mounted
{
    int r = 0;
    if (mounted != [self isFakelibMounted]) {
        NSString *arg = mounted ? @"mount" : @"unmount";
        r = [self spawnJbctlAsRootWithArgs:@[@"internal", @"fakelib", arg]];
    }
    return r;
}

- (int)setPrivatePrebootProtected:(BOOL)protected
{
    NSString *arg = protected ? @"activate" : @"deactivate";
    return [self spawnJbctlAsRootWithArgs:@[@"internal", @"protection", arg]];
}

- (BOOL)isJailbreakHidden
{
    // RootHide does not use /var/jb
    // Check if jbroot is accessible instead
    NSString *jbrootPath = JBROOT_PATH(@"/");
    return ![[NSFileManager defaultManager] fileExistsAtPath:jbrootPath];
}

- (void)setJailbreakHidden:(BOOL)hidden
{
    if (hidden && ![self isJailbroken] && geteuid() != 0) {
        [self runTrollStoreAction:@"hide-jailbreak"];
        return;
    }
    
    void (^actionBlock)(void) = ^{
        BOOL alreadyHidden = [self isJailbreakHidden];
        if (hidden != alreadyHidden) {
            if (hidden) {
                if ([self isJailbroken]) {
                    [self unregisterJailbreakApps];
                    [self setPrivatePrebootProtected:NO];
                    [self setFakelibMounted:NO];
                    jbclient_platform_set_systemwide_domain_enabled(false);
                }
                // RootHide: Remove /var/jb if it exists (leftover from other JBs)
                [[NSFileManager defaultManager] removeItemAtPath:@"/var/jb" error:nil];
            }
            else {
                // RootHide: Do NOT create /var/jb symlink - uses randomized jbroot only
                if ([self isJailbroken]) {
                    jbclient_platform_set_systemwide_domain_enabled(true);
                    [self setFakelibMounted:YES];
                    [self setPrivatePrebootProtected:YES];
                    [self refreshJailbreakApps];
                }
            }
        }
    };
    
    if ([self isJailbroken]) {
        [self runAsRoot:^{
            [self runUnsandboxed:actionBlock];
        }];
    }
    else {
        actionBlock();
    }
}

- (NSString *)accessibleKernelPath
{
    if ([self isInstalledThroughTrollStore] || getuid() == 0) {
        NSString *kernelcachePath = [[self activePrebootPath] stringByAppendingPathComponent:@"System/Library/Caches/com.apple.kernelcaches/kernelcache"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:kernelcachePath]) {
            return kernelcachePath;
        }
        return @"/System/Library/Caches/com.apple.kernelcaches/kernelcache";
    }
    else {
        NSString *kernelInApp = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@"kernelcache"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:kernelInApp]) {
            return kernelInApp;
        }
        
        [[DOUIManager sharedInstance] sendLog:@"Downloading Kernel" debug:NO];
        NSString *kernelcachePath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/kernelcache"];
        if (![[NSFileManager defaultManager] fileExistsAtPath:kernelcachePath]) {
            if (grab_images([NSHomeDirectory() stringByAppendingPathComponent:@"Documents"]) == false) return nil;
        }
        return kernelcachePath;
    }
}

- (NSString *)accessibleSPTMPath
{
    NSString *sptmInAppPath = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@"sptm.img4"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:sptmInAppPath]) {
        return sptmInAppPath;
    }
    
    NSString *sptmInDocsPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/sptm.img4"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:sptmInDocsPath]) {
        return sptmInDocsPath;
    }
    
    sptmInDocsPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/sptm.im4p"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:sptmInDocsPath]) {
        return sptmInDocsPath;
    }

    if ([self isInstalledThroughTrollStore] || getuid() == 0) {
        NSString *sptmPath = [[self activePrebootPath] stringByAppendingPathComponent:@"/usr/standalone/firmware/FUD/Ap,SecurePageTableMonitor.img4"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:sptmPath]) {
            return sptmPath;
        }
    }

    return nil;
}

- (NSString *)accessibleTXMPath
{
    NSString *txmInAppPath = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@"txm.img4"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:txmInAppPath]) {
        return txmInAppPath;
    }
    
    NSString *txmInDocsPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/txm.img4"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:txmInDocsPath]) {
        return txmInDocsPath;
    }
    
    txmInDocsPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/txm.im4p"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:txmInDocsPath]) {
        return txmInDocsPath;
    }

    if ([self isInstalledThroughTrollStore] || getuid() == 0) {
        NSString *txmPath = [[self activePrebootPath] stringByAppendingPathComponent:@"/usr/standalone/firmware/FUD/Ap,TrustedExecutionMonitor.img4"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:txmPath]) {
            return txmPath;
        }
    }

    return nil;
}


- (BOOL)isPACBypassRequired
{
    if (![self isArm64e]) return NO;
    
    if (@available(iOS 15.2, *)) {
        return NO;
    }
    return YES;
}

- (BOOL)isPPLBypassRequired
{
    return [self isArm64e];
}

- (BOOL)isSupported
{
    //cpu_subtype_t cpuFamily = 0;
    //size_t cpuFamilySize = sizeof(cpuFamily);
    //sysctlbyname("hw.cpufamily", &cpuFamily, &cpuFamilySize, NULL, 0);
    //if (cpuFamily == CPUFAMILY_ARM_TYPHOON) return false; // A8X is unsupported for now (due to 4k page size)
    
    DOExploitManager *exploitManager = [DOExploitManager sharedManager];
    if ([exploitManager availableExploitsForType:EXPLOIT_TYPE_KERNEL].count) {
        if (![self isPACBypassRequired] || [exploitManager availableExploitsForType:EXPLOIT_TYPE_PAC].count) {
            if (![self isPPLBypassRequired] || [exploitManager availableExploitsForType:EXPLOIT_TYPE_PPL].count) {
                return true;
            }
        }
    }
    
    return false;
}

- (BOOL)deviceSupportsFaceID
{
    if (![LAContext class]) return NO;

    LAContext *myContext = [[LAContext alloc] init];
    NSError *authError = nil;
    if (![myContext canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&authError]) {
        NSLog(@"%@", [authError localizedDescription]);
        return NO;
    }

    return myContext.biometryType == LABiometryTypeFaceID;
}

- (BOOL)deviceSupportsLandscapeBootLogo
{
    struct utsname u;
    uname(&u);
    const char *ipadString = "iPad";

    bool isPad = strncmp(u.machine, ipadString, strlen(ipadString)) == 0;
    return isPad && [self deviceSupportsFaceID];
}

- (NSError *)prepareBootstrap
{
    __block NSError *errOut;
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    [_bootstrapper prepareBootstrapWithCompletion:^(NSError *error) {
        errOut = error;
        dispatch_semaphore_signal(sema);
    }];
    dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
    return errOut;
}

- (NSError *)finalizeBootstrap
{
    return [_bootstrapper finalizeBootstrap];
}

- (NSError *)deleteBootstrap
{
    if (![self isJailbroken] && getuid() != 0) {
        int r = [self runTrollStoreAction:@"delete-bootstrap"];
        if (r != 0) {
            // TODO: maybe handle error
        }
        return nil;
    }
    else if ([self isJailbroken]) {
        __block NSError *error;
        [self runAsRoot:^{
            [self runUnsandboxed:^{
                error = [self->_bootstrapper deleteBootstrap];
            }];
        }];
        return error;
    }
    else {
        // Let's hope for the best
        return [_bootstrapper deleteBootstrap];
    }
}

- (NSError *)reinstallPackageManagers
{
    __block NSError *error;
    [self runAsRoot:^{
        [self runUnsandboxed:^{
            error = [self->_bootstrapper installPackageManagers];
        }];
    }];
    return error;
}

- (NSError *)updateBootLogo
{
    const char *bootLogoPath = JBROOT_PATH("/basebin/bootlogo.jp2");
    if ([[DOPreferenceManager sharedManager] boolPreferenceValueForKey:@"bootlogoEnabled" fallback:YES]) {
        UIImage *bootLogoImage;

        if ([[DOPreferenceManager sharedManager] boolPreferenceValueForKey:@"customBootlogoEnabled" fallback:NO]) {
            bootLogoImage = [NSClassFromString(@"UIImage") imageWithContentsOfFile:[DOUIManager sharedInstance].bootlogoPath];
        }

        if (!bootLogoImage) {
            bootLogoImage = [[DOUIManager sharedInstance] renderBootLogo];
        }

        [self runAsRoot:^{
            [self runUnsandboxed:^{
                unlink(bootLogoPath);
                [[bootLogoImage jp2DataWithCompressionQuality:0.9] writeToFile:[NSString stringWithUTF8String:bootLogoPath] atomically:NO];
            }];
        }];

        return nil;
    }
    else {
        [self runAsRoot:^{
            [self runUnsandboxed:^{
                unlink(bootLogoPath);
            }];
        }];
        return nil;
    }
}

@end
