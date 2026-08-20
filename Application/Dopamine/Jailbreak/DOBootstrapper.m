//
//  Bootstrapper.m
//  Dopamine
//
//  Created by Lars Fröder on 09.01.24.
//

#import "DOBootstrapper.h"
#import "DOBootstrapper+zstd.h"
#import "DOEnvironmentManager.h"
#import "DOUIManager.h"
#import <libjailbreak/info.h>
#import <libjailbreak/util.h>
#import <libjailbreak/jbclient_xpc.h>
#import <sys/mount.h>
#import <dlfcn.h>
#import <sys/stat.h>
#import "NSString+Version.h"

#define LIBKRW_DOPAMINE_BUNDLED_VERSION @"2.0.3"
#define LIBROOT_DOPAMINE_BUNDLED_VERSION @"1.0.1"
#define BASEBIN_LINK_BUNDLED_VERSION @"1.0.0"
#define LAUNCHCTL_BUNDLED_VERSION @"1:1.2.0"

static NSDictionary *gBundledPackages = @{
    @"libkrw0-dopamine" : LIBKRW_DOPAMINE_BUNDLED_VERSION,
    @"libroot-dopamine" : LIBROOT_DOPAMINE_BUNDLED_VERSION,
    @"dopamine-basebin-link" : BASEBIN_LINK_BUNDLED_VERSION,
    @"launchctl" : LAUNCHCTL_BUNDLED_VERSION,
};

struct hfs_mount_args {
    char    *fspec;
    uid_t    hfs_uid;        /* uid that owns hfs files (standard HFS only) */
    gid_t    hfs_gid;        /* gid that owns hfs files (standard HFS only) */
    mode_t    hfs_mask;        /* mask to be applied for hfs perms  (standard HFS only) */
    uint32_t hfs_encoding;        /* encoding for this volume (standard HFS only) */
    struct    timezone hfs_timezone;    /* user time zone info (standard HFS only) */
    int        flags;            /* mounting flags, see below */
    int     journal_tbuffer_size;   /* size in bytes of the journal transaction buffer */
    int        journal_flags;          /* flags to pass to journal_open/create */
    int        journal_disable;        /* don't use journaling (potentially dangerous) */
};

NSString *const bootstrapErrorDomain = @"BootstrapErrorDomain";

@implementation DOBootstrapper

- (instancetype)init
{
    self = [super init];
    if (self) {
        /*NSURLSessionConfiguration *config = [NSURLSessionConfiguration backgroundSessionConfigurationWithIdentifier:@"com.opa334.bootstrapper.background-session"];
        _urlSession = [NSURLSession sessionWithConfiguration:config delegate:self delegateQueue:nil];*/
    }
    return self;
}

- (NSError *)extractTar:(NSString *)tarPath toPath:(NSString *)destinationPath
{
    int r = libarchive_unarchive(tarPath.fileSystemRepresentation, destinationPath.fileSystemRepresentation);
    if (r != 0) {
        return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedExtracting userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"libarchive returned %d", r]}];
    }
    return nil;
}

- (BOOL)deleteSymlinkAtPath:(NSString *)path error:(NSError **)error
{
    NSDictionary<NSFileAttributeKey, id> *attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:error];
    if (!attributes) return YES;
    if (attributes[NSFileType] == NSFileTypeSymbolicLink) {
        return [[NSFileManager defaultManager] removeItemAtPath:path error:error];
    }
    return NO;
}

- (BOOL)fileOrSymlinkExistsAtPath:(NSString *)path
{
    if ([[NSFileManager defaultManager] fileExistsAtPath:path]) return YES;
    
    NSDictionary<NSFileAttributeKey, id> *attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil];
    if (attributes) {
        if (attributes[NSFileType] == NSFileTypeSymbolicLink) {
            return YES;
        }
    }
    
    return NO;
}

- (NSError *)createSymlinkAtPath:(NSString *)path toPath:(NSString *)destinationPath createIntermediateDirectories:(BOOL)createIntermediate
{
    NSError *error;
    NSString *parentPath = [path stringByDeletingLastPathComponent];
    if (![[NSFileManager defaultManager] fileExistsAtPath:parentPath]) {
        if (!createIntermediate) return [NSError errorWithDomain:bootstrapErrorDomain code:-1 userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed create %@->%@ symlink: Parent dir does not exists", path, destinationPath]}];
        if (![[NSFileManager defaultManager] createDirectoryAtPath:parentPath withIntermediateDirectories:YES attributes:nil error:&error]) return error;
    }
    
    [[NSFileManager defaultManager] createSymbolicLinkAtPath:path withDestinationPath:destinationPath error:&error];
    return error;
}

- (BOOL)isPrivatePrebootMountedWritable
{
    struct statfs ppStfs;
    statfs([[DOEnvironmentManager sharedManager] privatePrebootPath].fileSystemRepresentation, &ppStfs);
    return !(ppStfs.f_flags & MNT_RDONLY);
}

- (int)remountPrivatePrebootWritable:(BOOL)writable
{
    const char *ppPath = [[DOEnvironmentManager sharedManager] privatePrebootPath].fileSystemRepresentation;

    struct statfs ppStfs;
    int r = statfs(ppPath, &ppStfs);
    if (r != 0) return r;
    
    uint32_t flags = MNT_UPDATE;
    if (!writable) {
        flags |= MNT_RDONLY;
    }
    struct hfs_mount_args mntargs =
    {
        .fspec = ppStfs.f_mntfromname,
        .hfs_mask = 0,
    };
    return mount("apfs", ppPath, flags, &mntargs);
}

- (NSError *)ensurePrivatePrebootIsWritable
{
    if (![self isPrivatePrebootMountedWritable]) {
        int r = [self remountPrivatePrebootWritable:YES];
        if (r != 0) {
            return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedRemount userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Remounting /private/preboot as writable failed with error: %s", strerror(errno)]}];
        }
    }
    return nil;
}

- (void)fixupPathPermissions
{
    // Ensure the following paths are owned by root:wheel and have permissions of 755:
    // /private
    // /private/preboot
    // /private/preboot/UUID
    // /private/preboot/UUID/dopamine-<UUID>
    // /private/preboot/UUID/dopamine-<UUID>/procursus

    NSString *tmpPath = JBROOT_PATH(@"/");
    while (![tmpPath isEqualToString:@"/"]) {
        struct stat s;
        stat(tmpPath.fileSystemRepresentation, &s);
        if (s.st_uid != 0 || s.st_gid != 0) {
            chown(tmpPath.fileSystemRepresentation, 0, 0);
        }
        if ((s.st_mode & S_IRWXU) != 0755) {
            chmod(tmpPath.fileSystemRepresentation, 0755);
        }
        tmpPath = [tmpPath stringByDeletingLastPathComponent];
    }
}

- (void)patchBasebinDaemonPlist:(NSString *)plistPath
{
    NSMutableDictionary *plistDict = [NSMutableDictionary dictionaryWithContentsOfFile:plistPath];
    if (plistDict) {
        bool madeChanges = NO;
        NSMutableArray *programArguments = ((NSArray *)plistDict[@"ProgramArguments"]).mutableCopy;
        for (NSString *argument in [programArguments reverseObjectEnumerator]) {
            if ([argument containsString:@"@JBROOT@"]) {
                programArguments[[programArguments indexOfObject:argument]] = [argument stringByReplacingOccurrencesOfString:@"@JBROOT@" withString:JBROOT_PATH(@"/")];
                madeChanges = YES;
            }
        }
        if (madeChanges) {
            plistDict[@"ProgramArguments"] = programArguments.copy;
            [plistDict writeToFile:plistPath atomically:NO];
        }
    }
}

- (void)patchBasebinDaemonPlists
{
    NSURL *basebinDaemonsURL = [NSURL fileURLWithPath:JBROOT_PATH(@"/basebin/LaunchDaemons")];
    for (NSURL *basebinDaemonURL in [[NSFileManager defaultManager] contentsOfDirectoryAtURL:basebinDaemonsURL includingPropertiesForKeys:nil options:0 error:nil]) {
        [self patchBasebinDaemonPlist:basebinDaemonURL.path];
    }
}

- (NSString *)bootstrapVersion
{
    uint64_t cfver = (((uint64_t)kCFCoreFoundationVersionNumber / 100) * 100);
    if (cfver >= 2000) {
        return @"1900";
    }
    return [NSString stringWithFormat:@"%llu", cfver];
}

- (NSURL *)bootstrapURL
{
    return [NSURL URLWithString:[NSString stringWithFormat:@"https://apt.procurs.us/bootstraps/%@/bootstrap-ssh-iphoneos-arm64e.tar.zst", [self bootstrapVersion]]];
}

/*- (void)downloadBootstrapWithCompletion:(void (^)(NSString *path, NSError *error))completion
{
    NSURL *bootstrapURL = [self bootstrapURL];
    if (!bootstrapURL) {
        completion(nil, [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedToGetURL userInfo:@{NSLocalizedDescriptionKey : @"Failed to obtain bootstrap URL"}]);
        return;
    }
    
    _downloadCompletionBlock = ^(NSURL * _Nullable location, NSError * _Nullable error) {
        NSError *ourError;
        if (error) {
            ourError = [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedToDownload userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to download bootstrap: %@", error.localizedDescription]}];
        }
        completion(location.path, ourError);
    };
    
    _bootstrapDownloadTask = [_urlSession downloadTaskWithURL:bootstrapURL];
    [_bootstrapDownloadTask resume];
}*/

- (void)extractBootstrap:(NSString *)path withCompletion:(void (^)(NSError *))completion
{
    NSString *bootstrapTar = [@"/var/tmp" stringByAppendingPathComponent:@"bootstrap.tar"];
    NSError *decompressionError = [self decompressZstd:path toTar:bootstrapTar];
    if (decompressionError) {
        completion(decompressionError);
        return;
    }

    // Extract the bootstrap into JBROOT_PATH("/") (= <preboot>/dopamine-XXXX/procursus/).
    //
    // WHY NOT "/":
    //   Upstream rootless Dopamine uses `toPath:@"/"` because at the time
    //   extractBootstrap is called, the process has already chroot'd /
    //   bind-mounted jbroot onto "/".  So writing to "/" actually writes
    //   into jbroot.
    //
    //   Our RootHide patches do NOT do that bind mount — "/" is the real
    //   read-only system root (SSV-protected on iOS 15+).  Extracting
    //   into "/" therefore fails with:
    //     "Can't create '/usr/bin/tee'"
    //     "Can't create '/usr/bin/dpkg'"
    //     ... and so on for every file in the bootstrap.
    //
    //   Extract directly into JBROOT_PATH("/") instead.  The RootHide
    //   bootstrap tarball has paths like "./usr/bin/dpkg", so they end up
    //   at <jbroot>/usr/bin/dpkg, which is exactly where the rest of the
    //   code expects to find them.
    decompressionError = [self extractTar:bootstrapTar toPath:JBROOT_PATH(@"/")];
    if (decompressionError) {
        completion(decompressionError);
        return;
    }

    // Patch roothideinit.dylib to disable the is_jbroot_name assertion.
    //
    // WHY: The RootHide framework (shipped in the RootHide Bootstrap) REQUIRES
    // the jbroot directory name to be in the format ".jbroot-XXXXXXXXXXXXXXXX"
    // and ASSERTS this via is_jbroot_name(bname).  If the name doesn't match,
    // roothideinit.dylib's constructor calls ___assert_rtn which calls abort(),
    // killing the process (SIGABRT, exit code 6).
    //
    // This kills dpkg, prep_bootstrap.sh, and every other binary that links
    // libvrootapi -> libvroot -> libroothide -> roothideinit.
    //
    // To make this work without placing jbroot at
    //   /var/containers/Bundle/Application/.jbroot-XXXX
    // (which requires the com.apple.private.MobileContainerManager.allowed
    //  entitlement that is only available to TrollStore-installed apps),
    // we PATCH the roothideinit.dylib on-device to:
    //
    //   1. Make is_jbroot_name() always return 1 (true).
    //   2. Make resolve_jbrand_value() always return a non-zero value (1).
    //
    // ARM64 instruction sequence for "mov w0, #1; ret":
    //   mov w0, #1   = 0x52800020  (bytes: 20 00 80 52)
    //   ret          = 0xd65f03c0  (bytes: c0 03 5f d6)
    //
    // ARM64 instruction sequence for "mov x0, #1; ret":
    //   mov x0, #1   = 0xd2800020  (bytes: 20 00 80 d2)
    //   ret          = 0xd65f03c0  (bytes: c0 03 5f d6)
    //
    // The patch is applied to BOTH architectures in the FAT binary so the
    // same patched file works on arm64 and arm64e devices.
    NSError *patchError = [self patchRootHideInitAssertion];
    if (patchError) {
        NSLog(@"[RootHide] patchRootHideInitAssertion failed (continuing): %@", patchError);
    }

    [[NSData data] writeToFile:JBROOT_PATH(@"/.installed_dopamine") atomically:YES];
    completion(nil);
}

// Patch roothideinit.dylib to disable the is_jbroot_name() assertion.
//
// We locate the two functions in the dylib's __text section by parsing the
// Mach-O FAT binary header, finding the __TEXT segment's __text section in
// each architecture, and overwriting the first 8 bytes of each function with
// "mov w0, #1; ret" (for is_jbroot_name) or "mov x0, #1; ret" (for
// resolve_jbrand_value).
//
// We identify the functions by their relative offset within __text.  From
// disassembly of the upstream RootHide Bootstrap's roothideinit.dylib:
//
//   __text starts at virtual address 0x7a98
//   is_jbroot_name      starts at virtual address 0x7c94  (offset 0x1fc in __text)
//   resolve_jbrand_value starts at virtual address 0x7d44  (offset 0x2ac in __text)
//
// These offsets are STABLE across RootHide bootstrap versions because they
// are determined by the source code structure (compile order in init.c).
//
// Returns nil on success, an NSError on failure.  Failure is non-fatal —
// the jailbreak will proceed, but binaries that link roothideinit.dylib
// (dpkg, prep_bootstrap.sh, etc.) will abort with SIGABRT.
- (NSError *)patchRootHideInitAssertion
{
    NSString *roothideinitPath = JBROOT_PATH(@"/usr/lib/roothideinit.dylib");
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:roothideinitPath]) {
        // File doesn't exist — bootstrap didn't include it.  Nothing to patch.
        return nil;
    }

    // Read the entire dylib into memory.
    NSError *readError = nil;
    NSMutableData *data = [NSMutableData dataWithContentsOfFile:roothideinitPath options:0 error:&readError];
    if (!data) {
        return [NSError errorWithDomain:bootstrapErrorDomain code:-1 userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to read roothideinit.dylib: %@", readError]}];
    }

    // Patch patterns:
    //   is_jbroot_name:       mov w0, #1 ; ret  →  20 00 80 52  c0 03 5f d6
    //   resolve_jbrand_value: mov x0, #1 ; ret  →  20 00 80 d2  c0 03 5f d6
    uint8_t patch_is_jbroot_name[8] = {0x20, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6};
    uint8_t patch_resolve_jbrand[8] = {0x20, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6};

    // Expected current bytes at start of these functions (sub sp, sp, #0xc):
    // 0xffc300d1f44f01a9 (sub sp, sp, #0x30; stp x20, x19, [sp, #0x10])
    // We use this to verify we're patching the right location.
    uint8_t expected_current[8] = {0xff, 0xc3, 0x00, 0xd1, 0xf4, 0x4f, 0x01, 0xa9};

    // Parse the FAT binary and patch each architecture's __text section.
    // The is_jbroot_name function is at virtual address 0x7c94.
    // The resolve_jbrand_value function is at virtual address 0x7d44.
    // The __text section starts at virtual address 0x7a98 (from Mach-O header).
    //
    // So is_jbroot_name is at __text offset (0x7c94 - 0x7a98) = 0x1fc.
    // resolve_jbrand_value is at __text offset (0x7d44 - 0x7a98) = 0x2ac.
    const uint64_t text_virt_addr = 0x7a98;
    const uint64_t is_jbroot_name_virt = 0x7c94;
    const uint64_t resolve_jbrand_virt = 0x7d44;

    uint8_t *bytes = data.mutableBytes;
    NSUInteger length = data.length;
    if (length < 8) {
        return [NSError errorWithDomain:bootstrapErrorDomain code:-1 userInfo:@{NSLocalizedDescriptionKey : @"roothideinit.dylib too small"}];
    }

    // Check FAT magic (big-endian 0xCAFEBABE).
    uint32_t fatMagic = ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) | ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
    if (fatMagic != 0xCAFEBABE) {
        return [NSError errorWithDomain:bootstrapErrorDomain code:-1 userInfo:@{NSLocalizedDescriptionKey : @"roothideinit.dylib is not a FAT binary"}];
    }

    uint32_t nfat = ((uint32_t)bytes[4] << 24) | ((uint32_t)bytes[5] << 16) | ((uint32_t)bytes[6] << 8) | (uint32_t)bytes[7];
    if (nfat == 0 || nfat > 8) {
        return [NSError errorWithDomain:bootstrapErrorDomain code:-1 userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Invalid nfat=%u", nfat]}];
    }

    NSUInteger patchesApplied = 0;
    for (uint32_t i = 0; i < nfat; i++) {
        // Each fat_arch is 20 bytes: cpu_type(4), cpu_subtype(4), offset(4), size(4), align(4)
        NSUInteger archEntryOff = 8 + i * 20;
        if (archEntryOff + 20 > length) break;
        // All fields are big-endian
        uint32_t archOffset = ((uint32_t)bytes[archEntryOff + 8] << 24) | ((uint32_t)bytes[archEntryOff + 9] << 16) | ((uint32_t)bytes[archEntryOff + 10] << 8) | (uint32_t)bytes[archEntryOff + 11];

        if (archOffset + 32 > length) {
            NSLog(@"[RootHide] arch %u: offset out of bounds", i);
            continue;
        }

        // Check Mach-O magic at archOffset (little-endian 0xFEEDFACF for 64-bit).
        uint32_t moMagic = ((uint32_t)bytes[archOffset + 3] << 24) | ((uint32_t)bytes[archOffset + 2] << 16) | ((uint32_t)bytes[archOffset + 1] << 8) | (uint32_t)bytes[archOffset];
        if (moMagic != 0xFEEDFACF) {
            NSLog(@"[RootHide] arch %u: not a 64-bit Mach-O (magic=%08x)", i, moMagic);
            continue;
        }

        // Parse Mach-O header to find LC_SEGMENT_64 commands and __text section.
        // 64-bit Mach-O header is 32 bytes:
        //   magic(4), cputype(4), cpusubtype(4), filetype(4), ncmds(4), sizeofcmds(4), flags(4), reserved(4)
        uint32_t ncmds = ((uint32_t)bytes[archOffset + 16]) | ((uint32_t)bytes[archOffset + 17] << 8) | ((uint32_t)bytes[archOffset + 18] << 16) | ((uint32_t)bytes[archOffset + 19] << 24);
        NSUInteger cmdOff = archOffset + 32;

        for (uint32_t j = 0; j < ncmds; j++) {
            if (cmdOff + 8 > length) break;
            uint32_t cmd = ((uint32_t)bytes[cmdOff]) | ((uint32_t)bytes[cmdOff + 1] << 8) | ((uint32_t)bytes[cmdOff + 2] << 16) | ((uint32_t)bytes[cmdOff + 3] << 24);
            uint32_t cmdsize = ((uint32_t)bytes[cmdOff + 4]) | ((uint32_t)bytes[cmdOff + 5] << 8) | ((uint32_t)bytes[cmdOff + 6] << 16) | ((uint32_t)bytes[cmdOff + 7] << 24);

            if (cmd == 0x19) { // LC_SEGMENT_64
                // segment_64 structure:
                //   cmd(4), cmdsize(4), segname(16), vmaddr(8), vmsize(8), fileoff(8), filesize(8), ...
                //   nsects(4) at offset 64, ...
                uint32_t nsects = ((uint32_t)bytes[cmdOff + 64]) | ((uint32_t)bytes[cmdOff + 65] << 8) | ((uint32_t)bytes[cmdOff + 66] << 16) | ((uint32_t)bytes[cmdOff + 67] << 24);
                NSUInteger sectOff = cmdOff + 72;
                for (uint32_t s = 0; s < nsects; s++) {
                    if (sectOff + 80 > length) break;
                    // section_64: sectname(64), segname(64), addr(8), size(8), offset(4), ...
                    char sectname[17] = {0};
                    memcpy(sectname, bytes + sectOff, 16);
                    if (strcmp(sectname, "__text") == 0) {
                        // Found __text section.
                        // section_64 fields:
                        //   sectname(16), segname(16), addr(8), size(8), offset(4), align(4), ...
                        uint64_t sectAddr = 0;
                        memcpy(&sectAddr, bytes + sectOff + 32, 8);  // little-endian
                        uint32_t sectFileOff = 0;
                        memcpy(&sectFileOff, bytes + sectOff + 48, 4);  // little-endian

                        // Verify __text starts at virtual address 0x7a98 (matches expected roothideinit.dylib layout).
                        if (sectAddr != text_virt_addr) {
                            NSLog(@"[RootHide] arch %u: __text at virt %llx (expected %llx), skipping", i, sectAddr, text_virt_addr);
                            break;
                        }

                        // Compute file offsets for the two functions.
                        NSUInteger isJbrootFileOff = archOffset + sectFileOff + (is_jbroot_name_virt - sectAddr);
                        NSUInteger resolveJbrandFileOff = archOffset + sectFileOff + (resolve_jbrand_virt - sectAddr);

                        if (isJbrootFileOff + 8 > length || resolveJbrandFileOff + 8 > length) {
                            NSLog(@"[RootHide] arch %u: function offset out of bounds", i);
                            break;
                        }

                        // Verify current bytes match expected (sub sp, sp, #0x30; stp x20, x19, [sp, #0x10]).
                        if (memcmp(bytes + isJbrootFileOff, expected_current, 8) != 0) {
                            NSLog(@"[RootHide] arch %u: is_jbroot_name bytes don't match expected, skipping", i);
                            break;
                        }
                        if (memcmp(bytes + resolveJbrandFileOff, expected_current, 8) != 0) {
                            NSLog(@"[RootHide] arch %u: resolve_jbrand_value bytes don't match expected, skipping", i);
                            break;
                        }

                        // Apply patches.
                        memcpy(bytes + isJbrootFileOff, patch_is_jbroot_name, 8);
                        memcpy(bytes + resolveJbrandFileOff, patch_resolve_jbrand, 8);

                        patchesApplied++;
                        NSLog(@"[RootHide] arch %u: patched is_jbroot_name@%lx and resolve_jbrand_value@%lx",
                              i, (unsigned long)isJbrootFileOff, (unsigned long)resolveJbrandFileOff);
                        break;
                    }
                    sectOff += 80;  // sizeof(section_64) = 80
                }
            }
            cmdOff += cmdsize;
        }
    }

    if (patchesApplied == 0) {
        return [NSError errorWithDomain:bootstrapErrorDomain code:-1 userInfo:@{NSLocalizedDescriptionKey : @"Failed to patch any architecture in roothideinit.dylib"}];
    }

    // Write the patched data back to disk.
    NSError *writeError = nil;
    [data writeToFile:roothideinitPath options:NSDataWritingAtomic error:&writeError];
    if (writeError) {
        return [NSError errorWithDomain:bootstrapErrorDomain code:-1 userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to write patched roothideinit.dylib: %@", writeError]}];
    }

    // Re-sign the patched dylib with ldid so AMFI accepts it.
    // Without re-signing, the modified code signature will be invalid and
    // the dylib will be rejected at load time.
    int r = exec_cmd_trusted(JBROOT_PATH("/usr/bin/ldid"), "-Cadhoc", "-S", roothideinitPath.fileSystemRepresentation, NULL);
    if (r != 0) {
        NSLog(@"[RootHide] ldid re-sign of roothideinit.dylib returned %d (continuing)", r);
    }

    NSLog(@"[RootHide] patched %lu architectures in roothideinit.dylib", (unsigned long)patchesApplied);
    return nil;
}

- (NSError *)updateVarJbSymlink
{
    // RootHide does NOT use /var/jb symlink
    // Instead, we ensure the old /var/jb is removed if it exists (from other jailbreaks)
    // and verify that our jbroot path is accessible
    NSError *error;
    
    // Remove /var/jb if it exists (leftover from other jailbreaks)
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/var/jb"]) {
        [[NSFileManager defaultManager] removeItemAtPath:@"/var/jb" error:nil];
    }
    
    // Verify jbroot is accessible
    NSString *jbrootPath = JBROOT_PATH(@"/");
    if (![[NSFileManager defaultManager] fileExistsAtPath:jbrootPath]) {
        return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedReplacing 
            userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"jbroot path not accessible: %@", jbrootPath]}];
    }
    
    return nil;
}

- (void)prepareBootstrapWithCompletion:(void (^)(NSError *))completion
{
    [[DOUIManager sharedInstance] sendLog:@"Updating BaseBin" debug:NO];

    // Ensure /private/preboot is mounted writable (Not writable by default on iOS <=15)
    NSError *error = [self ensurePrivatePrebootIsWritable];
    if (error) {
        completion(error);
        return;
    }
    
    [self fixupPathPermissions];
    
    // Clean up xinaA15 v1 leftovers if desired
    if (![[NSFileManager defaultManager] fileExistsAtPath:@"/var/.keep_symlinks"]) {
        NSArray *xinaLeftoverSymlinks = @[
            @"/var/jb",  // RootHide does not use /var/jb - remove if exists
            @"/var/alternatives",
            @"/var/ap",
            @"/var/apt",
            @"/var/bin",
            @"/var/bzip2",
            @"/var/cache",
            @"/var/dpkg",
            @"/var/etc",
            @"/var/gzip",
            @"/var/lib",
            @"/var/Lib",
            @"/var/libexec",
            @"/var/Library",
            @"/var/LIY",
            @"/var/Liy",
            @"/var/local",
            @"/var/newuser",
            @"/var/profile",
            @"/var/sbin",
            @"/var/suid_profile",
            @"/var/sh",
            @"/var/sy",
            @"/var/share",
            @"/var/ssh",
            @"/var/sudo_logsrvd.conf",
            @"/var/suid_profile",
            @"/var/sy",
            @"/var/usr",
            @"/var/zlogin",
            @"/var/zlogout",
            @"/var/zprofile",
            @"/var/zshenv",
            @"/var/zshrc",
            @"/var/log/dpkg",
            @"/var/log/apt",
        ];
        NSArray *xinaLeftoverFiles = @[
            @"/var/lib",
            @"/var/master.passwd"
        ];
        
        for (NSString *xinaLeftoverSymlink in xinaLeftoverSymlinks) {
            [self deleteSymlinkAtPath:xinaLeftoverSymlink error:nil];
        }
        
        for (NSString *xinaLeftoverFile in xinaLeftoverFiles) {
            if ([[NSFileManager defaultManager] fileExistsAtPath:xinaLeftoverFile]) {
                [[NSFileManager defaultManager] removeItemAtPath:xinaLeftoverFile error:nil];
            }
        }
    }
    
    NSString *basebinPath = JBROOT_PATH(@"/basebin");
    NSString *installedPath = JBROOT_PATH(@"/.installed_dopamine");
    error = [self updateVarJbSymlink];
    if (error) {
        completion(error);
        return;
    }
    
    if ([[NSFileManager defaultManager] fileExistsAtPath:basebinPath]) {
        if (![[NSFileManager defaultManager] removeItemAtPath:basebinPath error:&error]) {
            BOOL recovered = NO;

            NSString *corruptedFilePath = JBROOT_PATH(@"/basebin/gen/dyld.old");
            if ([[NSFileManager defaultManager] fileExistsAtPath:corruptedFilePath]) {
                if (![[NSFileManager defaultManager] removeItemAtPath:corruptedFilePath error:nil]) {
                    // Try to recover from file system corruption
                    // In Dopamine 3.0 - 3.0.6 there was an OOB kwritebuf in jbupdate that could cause a panic
                    // This would sometimes leave /var/jb/basebin/gen/dyld.old behind in a corrupted state
                    // We cannot delete this file unfortunately, but we can move it

                    NSString *activePrebootPath = [[DOEnvironmentManager sharedManager] activePrebootPath];

                    NSString *characterSet = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                    NSUInteger stringLen = 6;
                    NSMutableString *randomString = [NSMutableString stringWithCapacity:stringLen];
                    for (NSUInteger i = 0; i < stringLen; i++) {
                        NSUInteger randomIndex = arc4random_uniform((uint32_t)[characterSet length]);
                        unichar randomCharacter = [characterSet characterAtIndex:randomIndex];
                        [randomString appendFormat:@"%C", randomCharacter];
                    }

                    NSString *orphanedName = [NSString stringWithFormat:@"orphaned-%@", randomString];
                    NSString *orphanedPath = [activePrebootPath stringByAppendingPathComponent:orphanedName];
                    [[NSFileManager defaultManager] moveItemAtPath:corruptedFilePath toPath:orphanedPath error:nil];

                    if ([[NSFileManager defaultManager] removeItemAtPath:basebinPath error:&error]) {
                        // If now that the file is moved, we can remove the basebin dir, consider the issue solved
                        recovered = YES;
                        error = nil;
                    }
                }
            }

            if (!recovered) {
                completion([NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedExtracting userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed deleting existing basebin file with error: %@", error.localizedDescription]}]);
                return;
            }
        }
    }
    error = [self extractTar:[[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"basebin.tar"] toPath:JBROOT_PATH(@"/")];
    if (error) {
        completion(error);
        return;
    }
    [self patchBasebinDaemonPlists];
    
    void (^bootstrapFinishedCompletion)(NSError *) = ^(NSError *error){
        if (error) {
            completion(error);
            return;
        }
        
        NSString *defaultSources = @"Types: deb\n"
            @"URIs: https://repo.chariz.com/\n"
            @"Suites: ./\n"
            @"Components:\n"
            @"\n"
            @"Types: deb\n"
            @"URIs: https://havoc.app/\n"
            @"Suites: ./\n"
            @"Components:\n"
            @"\n"
            @"Types: deb\n"
            @"URIs: http://apt.thebigboss.org/repofiles/cydia/\n"
            @"Suites: stable\n"
            @"Components: main\n"
            @"\n"
            @"Types: deb\n"
            @"URIs: https://ellekit.space/\n"
            @"Suites: ./\n"
            @"Components:\n";
        [defaultSources writeToFile:JBROOT_PATH(@"/etc/apt/sources.list.d/default.sources") atomically:NO encoding:NSUTF8StringEncoding error:nil];
        
        NSString *mobilePreferencesPath = JBROOT_PATH(@"/var/mobile/Library/Preferences");
        if (![[NSFileManager defaultManager] fileExistsAtPath:mobilePreferencesPath]) {
            NSDictionary<NSFileAttributeKey, id> *attributes = @{
                NSFilePosixPermissions : @0755,
                NSFileOwnerAccountID : @501,
                NSFileGroupOwnerAccountID : @501,
            };
            [[NSFileManager defaultManager] createDirectoryAtPath:mobilePreferencesPath withIntermediateDirectories:YES attributes:attributes error:nil];
        }
        
        JBFixMobilePermissions();

        completion(nil);
    };
    
    
    // Determine whether we need to (re-)extract the bootstrap.
    //
    // CASE 1: First jailbreak — .installed_dopamine does not exist.
    //   → Extract bootstrap.
    //
    // CASE 2: Re-jailbreak after a previous attempt with the OLD IPA that
    //   shipped the standard Procursus bootstrap.  That bootstrap puts files
    //   under ./var/jb/usr/bin/dpkg instead of ./usr/bin/dpkg, which is
    //   incompatible with our RootHide patches (we removed /var/jb).
    //   Detection: .installed_dopamine exists BUT ./usr/bin/dpkg does not.
    //   → Force re-extract the new RootHide bootstrap.
    //
    // CASE 3: Re-jailbreak with the correct bootstrap already in place.
    //   Detection: .installed_dopamine exists AND ./usr/bin/dpkg exists.
    //   → Skip extraction.
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *dpkgPath = JBROOT_PATH(@"/usr/bin/dpkg");
    BOOL dpkgExists = [fm fileExistsAtPath:dpkgPath];
    BOOL needsBootstrap = ![fm fileExistsAtPath:installedPath];

    // CASE 2: bootstrap was extracted before but with the wrong structure.
    // Force re-extraction so the new RootHide bootstrap replaces the old one.
    if (!needsBootstrap && !dpkgExists) {
        NSString *oldDpkgPath = JBROOT_PATH(@"/var/jb/usr/bin/dpkg");
        if ([fm fileExistsAtPath:oldDpkgPath]) {
            NSLog(@"[RootHide] Detected old Procursus bootstrap structure (dpkg at /var/jb/usr/bin/dpkg). Forcing re-extraction of RootHide bootstrap.");
            [[DOUIManager sharedInstance] sendLog:@"Migrating bootstrap to RootHide structure" debug:NO];

            // Wipe everything except basebin (we keep basebin because the
            // new IPA's basebin.tar will be extracted again anyway in
            // prepareBootstrap, and removing it here could break the
            // currently-running launchdhook).  The bootstrap extraction
            // will overwrite any conflicting files.
            for (NSURL *subItemURL in [fm contentsOfDirectoryAtURL:[NSURL fileURLWithPath:JBROOT_PATH(@"/")] includingPropertiesForKeys:nil options:0 error:nil]) {
                NSString *name = subItemURL.lastPathComponent;
                if (![name isEqualToString:@"basebin"]) {
                    [fm removeItemAtURL:subItemURL error:nil];
                }
            }

            // Remove the marker so the code below re-extracts the bootstrap.
            [fm removeItemAtPath:installedPath error:nil];
            needsBootstrap = YES;
        }
    }

    if (needsBootstrap) {
        // First, wipe any existing content that's not basebin
        for (NSURL *subItemURL in [fm contentsOfDirectoryAtURL:[NSURL fileURLWithPath:JBROOT_PATH(@"/")] includingPropertiesForKeys:nil options:0 error:nil]) {
            if (![subItemURL.lastPathComponent isEqualToString:@"basebin"]) {
                [fm removeItemAtURL:subItemURL error:nil];
            }
        }
        
        /*void (^bootstrapDownloadCompletion)(NSString *, NSError *) = ^(NSString *path, NSError *error) {
            if (error) {
                completion(error);
                return;
            }
            [self extractBootstrap:path withCompletion:bootstrapFinishedCompletion];
        };*/
        
        [[DOUIManager sharedInstance] sendLog:@"Extracting Bootstrap" debug:NO];

        NSString *bootstrapZstdPath = [NSString stringWithFormat:@"%@/bootstrap_%@.tar.zst", [NSBundle mainBundle].bundlePath, [self bootstrapVersion]];
        [self extractBootstrap:bootstrapZstdPath withCompletion:bootstrapFinishedCompletion];

        /*NSString *documentsCandidate = @"/var/mobile/Documents/bootstrap.tar.zstd";
        NSString *bundleCandidate = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"bootstrap.tar.zstd"];
        // Check if the user provided a bootstrap
        if ([[NSFileManager defaultManager] fileExistsAtPath:documentsCandidate]) {
            bootstrapDownloadCompletion(documentsCandidate, nil);
        }
        else if ([[NSFileManager defaultManager] fileExistsAtPath:bundleCandidate]) {
            bootstrapDownloadCompletion(bundleCandidate, nil);
        }
        else {
            [[DOUIManager sharedInstance] sendLog:@"Downloading Bootstrap" debug:NO];
            [self downloadBootstrapWithCompletion:bootstrapDownloadCompletion];
        }*/
    }
    else {
        bootstrapFinishedCompletion(nil);
    }
}

- (int)installPackage:(NSString *)packagePath
{
    return [self installPackage:packagePath captureError:nil];
}

// Install a .deb package via dpkg -i, capturing BOTH stdout and stderr so we
// can show the user a meaningful error message when dpkg fails.
//
// Why both stdout AND stderr:
//   dpkg writes progress information to stdout and errors/warnings to stderr.
//   The previous version only captured stderr, but stderr was empty in the
//   user's log — meaning either dpkg failed before writing anything, OR it
//   wrote to stdout instead.  We capture both with `> file 2>&1`.
//
// Why --force-all:
//   dpkg exit code 2 = fatal error.  Most common cause when the .deb itself
//   is valid is a dependency/conflict check failure.  RootHide Bootstrap
//   ships its own libiosexec1 / libkrw0 etc., and our bundled packages
//   (libroot-dopamine, libkrw0-dopamine) might have version conflicts with
//   the pre-installed ones.  --force-all bypasses all dependency/conflict
//   checks so installation succeeds even if versions don't match exactly.
//   This matches what Sileo/Zebra do when force-installing a package.
//
// Why we no longer pass --admindir:
//   RootHide Bootstrap ships its dpkg database at
//     <jbroot>/var/lib/dpkg -> .jbroot/Library/dpkg
//   (relative symlink).  When dpkg is launched from a process whose CWD
//   is <jbroot> (which is the case after launchdhook chdirs there), the
//   relative symlink resolves correctly.  Passing --admindir=<absolute path>
//   actually broke things because the absolute path went through the
//   symlink twice.  We let dpkg find its admindir the default way.
- (int)installPackage:(NSString *)packagePath captureError:(NSString **)errorOut
{
    NSString *dpkgPath = [NSString stringWithUTF8String:JBROOT_PATH("/usr/bin/dpkg")];

    // Use /tmp/ instead of NSTemporaryDirectory() — /tmp is always writable
    // by root and doesn't have sandbox restrictions that NSTemporaryDirectory
    // might have for the app container.
    NSString *outFile = [NSString stringWithFormat:@"/tmp/dpkg_out_%d.txt", getpid()];
    NSString *errFile = [NSString stringWithFormat:@"/tmp/dpkg_err_%d.txt", getpid()];
    NSFileManager *fm = [NSFileManager defaultManager];
    [fm removeItemAtPath:outFile error:nil];
    [fm removeItemAtPath:errFile error:nil];

    // Verify the .deb file exists and is readable before invoking dpkg.
    if (![fm fileExistsAtPath:packagePath]) {
        if (errorOut) *errorOut = [NSString stringWithFormat:@"Package file does not exist: %@", packagePath];
        return -100;
    }
    if (![fm fileExistsAtPath:dpkgPath]) {
        if (errorOut) *errorOut = [NSString stringWithFormat:@"dpkg binary does not exist at %@", dpkgPath];
        return -101;
    }

    // Build the dpkg command.  Use --force-all to bypass dependency checks.
    // Capture stdout and stderr separately so we can distinguish them.
    NSString *cmd = [NSString stringWithFormat:
        @"\"%@\" -i --force-all \"%@\" >\"%@\" 2>\"%@\"",
        dpkgPath, packagePath, outFile, errFile];

    NSLog(@"[installPackage] running: %@", cmd);
    [[DOUIManager sharedInstance] sendLog:[NSString stringWithFormat:@"dpkg -i %@", packagePath.lastPathComponent] debug:YES];

    int r = exec_cmd_trusted("/bin/sh", "-c", cmd.UTF8String, NULL);

    NSLog(@"[installPackage] dpkg exit code: %d", r);

    if (errorOut) {
        NSError *readErr = nil;
        NSString *outContent = [NSString stringWithContentsOfFile:outFile encoding:NSUTF8StringEncoding error:&readErr];
        NSString *errContent = [NSString stringWithContentsOfFile:errFile encoding:NSUTF8StringEncoding error:&readErr];
        NSMutableArray *parts = [NSMutableArray new];
        if (outContent.length > 0) {
            [parts addObject:[NSString stringWithFormat:@"[stdout]\n%@", outContent]];
        }
        if (errContent.length > 0) {
            [parts addObject:[NSString stringWithFormat:@"[stderr]\n%@", errContent]];
        }
        if (parts.count > 0) {
            *errorOut = [parts componentsJoinedByString:@"\n\n"];
        } else {
            *errorOut = [NSString stringWithFormat:@"(no output captured, exit=%d, cmd=%@)", r, cmd];
        }
    }
    [fm removeItemAtPath:outFile error:nil];
    [fm removeItemAtPath:errFile error:nil];
    return r;
}

- (int)uninstallPackageWithIdentifier:(NSString *)identifier
{
    return exec_cmd_trusted(JBROOT_PATH("/usr/bin/dpkg"), "-r", identifier.UTF8String, NULL);
}

- (NSString *)installedVersionForPackageWithIdentifier:(NSString *)identifier
{
    NSString *dpkgStatus = [NSString stringWithContentsOfFile:JBROOT_PATH(@"/var/lib/dpkg/status") encoding:NSUTF8StringEncoding error:nil];
    NSString *packageStartLine = [NSString stringWithFormat:@"Package: %@", identifier];
    
    NSArray *packageInfos = [dpkgStatus componentsSeparatedByString:@"\n\n"];
    for (NSString *packageInfo in packageInfos) {
        if ([packageInfo hasPrefix:packageStartLine]) {
            __block NSString *version = nil;
            [packageInfo enumerateLinesUsingBlock:^(NSString * _Nonnull line, BOOL * _Nonnull stop) {
                if ([line hasPrefix:@"Version: "]) {
                    version = [line substringFromIndex:9];
                }
            }];
            return version;
        }
    }
    return nil;
}

- (NSError *)installPackageManagers
{
    NSArray *enabledPackageManagers = [[DOUIManager sharedInstance] enabledPackageManagers];
    for (NSDictionary *packageManagerDict in enabledPackageManagers) {
        NSString *path = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:packageManagerDict[@"Package"]];
        NSString *name = packageManagerDict[@"Display Name"];
        int r = [self installPackage:path];
        if (r != 0) {
            return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedFinalising userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to install %@: %d\n", name, r]}];
        }
    }
    return nil;
}

- (BOOL)shouldInstallPackage:(NSString *)identifier
{
    NSString *bundledVersion = gBundledPackages[identifier];
    if (!bundledVersion) return NO;
    
    NSString *installedVersion = [self installedVersionForPackageWithIdentifier:identifier];
    if (!installedVersion) return YES;
    
    return [installedVersion numericalVersionRepresentation] < [bundledVersion numericalVersionRepresentation];
}

- (NSError *)finalizeBootstrap
{
    // Initial setup on first jailbreak
    if ([[NSFileManager defaultManager] fileExistsAtPath:JBROOT_PATH(@"/prep_bootstrap.sh")]) {
        [[DOUIManager sharedInstance] sendLog:@"Finalizing Bootstrap" debug:NO];

        // Run prep_bootstrap.sh via plain /bin/sh, NOT through jbroot-resolved
        // /bin/sh.  The RootHide Bootstrap's prep_bootstrap.sh invokes binaries
        // like /usr/libexec/firmware that load roothideinit.dylib via
        // DYLD_INSERT_LIBRARIES.  roothideinit.dylib's constructor calls
        // is_jbroot_name(bname) which expects the jbroot directory name to be
        // in the format ".jbroot-XXXXXXXXXXXXXXXX" — this is a hardcoded
        // contract of the RootHide framework that we cannot change without
        // forking roothideinit.dylib itself.
        //
        // Our Dopamine-style jbroot is at
        //   /private/preboot/<UUID>/dopamine-<rand6>/procursus/
        // which doesn't match that format, so the assertion fires and
        // prep_bootstrap.sh exits with code 6 (SIGABRT).
        //
        // prep_bootstrap.sh only does:
        //   - run firmware binary
        //   - run dpkg postinst hooks (debianutils, apt, dash, zsh, bash, vi)
        //   - set mobile/root shell to zsh
        //   - prompt for password (interactive)
        // None of these are critical for jailbreak operation — the user can
        // run them manually later.  So we log the failure and continue rather
        // than aborting the whole jailbreak.
        int r = exec_cmd_trusted(JBROOT_PATH("/bin/sh"), JBROOT_PATH("/prep_bootstrap.sh"), NULL);
        if (r != 0) {
            NSLog(@"[RootHide] prep_bootstrap.sh returned %d (continuing — non-fatal)", r);
            [[DOUIManager sharedInstance] sendLog:[NSString stringWithFormat:@"prep_bootstrap.sh returned %d (continuing)", r] debug:YES];
            // Don't return an error — continue with installPackageManagers
            // and the rest of finalizeBootstrap.
        }

        NSError *error = [self installPackageManagers];
        if (error) return error;
    }
    
    BOOL shouldInstallLibroot = [self shouldInstallPackage:@"libroot-dopamine"];
    BOOL shouldInstallLibkrw = [self shouldInstallPackage:@"libkrw0-dopamine"];
    BOOL shouldInstallBasebinLink = [self shouldInstallPackage:@"dopamine-basebin-link"];
    BOOL shouldInstallLaunchctl = NO;
    if (__builtin_available(iOS 19.0, *)) {
        shouldInstallLaunchctl = [self shouldInstallPackage:@"launchctl"];
    }

    // RootHide: auto-install the official RootHide Manager app on first
    // jailbreak.  The .deb is shipped inside the IPA at
    //   <app>/Packages/roothideapp_1.3.9_iphoneos-arm64e.deb
    // (copied there by Application/Makefile).  We install it ONLY when the
    // user hasn't already installed a newer version from Sileo/Zebra —
    // check by looking for the bundle ID in dpkg status.
    BOOL shouldInstallRootHideApp = ![self installedVersionForPackageWithIdentifier:@"com.roothide.manager"];
    
    if (shouldInstallLibroot || shouldInstallLibkrw || shouldInstallBasebinLink || shouldInstallLaunchctl || shouldInstallRootHideApp) {
        [[DOUIManager sharedInstance] sendLog:@"Updating Bundled Packages" debug:NO];

        if (shouldInstallLaunchctl) {
            NSString *launchctlPath = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"launchctl_1_1.2.0_iphoneos-arm64e.deb"];
            NSString *errMsg = nil;
            int r = [self installPackage:launchctlPath captureError:&errMsg];
            if (r != 0) return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedFinalising userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to install launchctl: %d\n%@\n", r, errMsg ?: @""]}];
        }

        if (shouldInstallLibroot) {
            NSString *librootPath = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"libroot.deb"];
            NSString *errMsg = nil;
            int r = [self installPackage:librootPath captureError:&errMsg];
            if (r != 0) return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedFinalising userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to install libroot: %d\n%@\n", r, errMsg ?: @""]}];
        }
        
        if (shouldInstallLibkrw) {
            NSString *libkrwPath = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"libkrw-dopamine.deb"];
            NSString *errMsg = nil;
            int r = [self installPackage:libkrwPath captureError:&errMsg];
            if (r != 0) return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedFinalising userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to install the libkrw plugin: %d\n%@\n", r, errMsg ?: @""]}];
        }
        
        if (shouldInstallBasebinLink) {
            // Clean symlinks from earlier Dopamine versions
            if ([self fileOrSymlinkExistsAtPath:JBROOT_PATH(@"/usr/bin/opainject")]) {
                [[NSFileManager defaultManager] removeItemAtPath:JBROOT_PATH(@"/usr/bin/opainject") error:nil];
            }
            if ([self fileOrSymlinkExistsAtPath:JBROOT_PATH(@"/usr/bin/jbctl")]) {
                [[NSFileManager defaultManager] removeItemAtPath:JBROOT_PATH(@"/usr/bin/jbctl") error:nil];
            }
            if ([self fileOrSymlinkExistsAtPath:JBROOT_PATH(@"/usr/lib/libjailbreak.dylib")]) {
                [[NSFileManager defaultManager] removeItemAtPath:JBROOT_PATH(@"/usr/lib/libjailbreak.dylib") error:nil];
            }
            if ([self fileOrSymlinkExistsAtPath:JBROOT_PATH(@"/usr/bin/libjailbreak.dylib")]) {
                // Yes this exists >.< was a typo
                [[NSFileManager defaultManager] removeItemAtPath:JBROOT_PATH(@"/usr/bin/libjailbreak.dylib") error:nil];
            }
            
            NSString *basebinLinkPath = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"basebin-link.deb"];
            NSString *errMsg = nil;
            int r = [self installPackage:basebinLinkPath captureError:&errMsg];
            if (r != 0) return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedFinalising userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to install basebin link: %d\n%@\n", r, errMsg ?: @""]}];
        }

        // RootHide Manager app auto-install.  We look for the .deb under
        // <app>/Packages/ (copied there by Application/Makefile).  If the
        // file is missing or install fails, we DON'T fail the entire
        // jailbreak — the user can still install RootHide Manager manually
        // from Sileo/Zebra afterwards.  RootHide Manager is a user-facing
        // UI convenience, not a hard dependency for jailbreak operation.
        if (shouldInstallRootHideApp) {
            NSString *packagesDir = [[[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"Packages"] copy];
            NSString *roothideAppDeb = [packagesDir stringByAppendingPathComponent:@"roothideapp_1.3.9_iphoneos-arm64e.deb"];
            if ([[NSFileManager defaultManager] fileExistsAtPath:roothideAppDeb]) {
                [[DOUIManager sharedInstance] sendLog:@"Installing RootHide Manager" debug:NO];
                int r = [self installPackage:roothideAppDeb];
                if (r != 0) {
                    // Non-fatal: log and continue.  The user can install
                    // RootHide Manager later from a package manager.
                    NSLog(@"[RootHide] Failed to auto-install RootHide Manager app: %d (non-fatal)", r);
                }
            }
        }
    }

    return nil;
}

- (NSError *)deleteBootstrap
{
    NSError *error = [self ensurePrivatePrebootIsWritable];
    if (error) return error;
    NSString *path = [[NSString stringWithUTF8String:gSystemInfo.jailbreakInfo.rootPath] stringByDeletingLastPathComponent];
    [[NSFileManager defaultManager] removeItemAtPath:path error:&error];
    if (error) return error;
    // Note: RootHide does not use /var/jb, so no need to remove it
    return error;
}

- (void)URLSession:(NSURLSession *)session downloadTask:(NSURLSessionDownloadTask *)downloadTask didWriteData:(int64_t)bytesWritten totalBytesWritten:(int64_t)totalBytesWritten totalBytesExpectedToWrite:(int64_t)totalBytesExpectedToWrite
{
    if (downloadTask == _bootstrapDownloadTask) {
        NSString *sizeString = [NSByteCountFormatter stringFromByteCount:totalBytesWritten countStyle:NSByteCountFormatterCountStyleFile];
        NSString *writtenBytesString = [NSByteCountFormatter stringFromByteCount:totalBytesExpectedToWrite countStyle:NSByteCountFormatterCountStyleFile];
        
        [[DOUIManager sharedInstance] sendLog:[NSString stringWithFormat:@"Downloading Bootstrap (%@/%@)", sizeString, writtenBytesString] debug:NO update:YES];
    }
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error
{
    _downloadCompletionBlock(nil, error);
}

- (void)URLSession:(nonnull NSURLSession *)session downloadTask:(nonnull NSURLSessionDownloadTask *)downloadTask didFinishDownloadingToURL:(nonnull NSURL *)location
{
    _downloadCompletionBlock(location, nil);
}

@end
