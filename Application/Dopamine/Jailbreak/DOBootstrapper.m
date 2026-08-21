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
#import <strings.h>
#import "NSString+Version.h"

// --- Mach-O parsing helpers -------------------------------------------------
// FAT Mach-O headers are big-endian; per-arch Mach-O slices on iOS arm64(e)
// are little-endian.  We use explicit BE/LE readers so the patchers can
// walk both layers correctly.

// Read a 32-bit big-endian value from raw bytes (FAT header / FAT arch entries).
static inline uint32_t rh_u32be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
// Read a 32-bit little-endian value from raw bytes (Mach-O slice load commands).
static inline uint32_t rh_u32le(const uint8_t *p) {
    return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
// Read a 64-bit little-endian value from raw bytes (Mach-O section addr/size).
static inline uint64_t rh_u64le(const uint8_t *p) {
    return ((uint64_t)rh_u32le(p)) | ((uint64_t)rh_u32le(p + 4) << 32);
}

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

    // Patch roothideinit.dylib AND libroothide.dylib to disable assertions.
    //
    // The RootHide framework has TWO layers of assertions:
    //
    // 1. roothideinit.dylib's constructor:
    //    - is_jbroot_name(basename(jbroot_path)) — checks if jbroot dir name
    //      matches ".jbroot-XXXXXXXXXXXXXXXX" format.
    //    - resolve_jbrand_value(name, &out) — parses the jbrand value from name.
    //    Both must succeed or the constructor aborts with SIGABRT.
    //
    //    Patch: replace the first instructions of is_jbroot_name with
    //    "mov w0, #1; ret" (arm64) or "pacibsp; mov w0, #1; retab" (arm64e).
    //    Same for resolve_jbrand_value with "mov x0, #1".
    //
    // 2. libroothide.dylib's __private_jbrootat_alloc function:
    //    - stat(___roothideinit_JBROOT, &jbrootst) — checks if the jbroot path
    //      (which roothideinit set to "/var/containers/Bundle/Application/.jbroot-XXX")
    //      exists on disk. Since our jbroot is at /private/preboot/.../procursus/,
    //      the path roothideinit constructs doesn't exist → stat fails → assertion.
    //
    //    Patch: NOP the cbnz instruction after each stat() call so the
    //    assertion is never triggered even if stat returns non-zero.
    //
    // Both patches must be applied to BOTH architectures (arm64 and arm64e)
    // in the FAT binary, because dpkg and other binaries may load either slice.
    NSError *patchError = [self patchRootHideAssertions];
    if (patchError) {
        NSLog(@"[RootHide] patchRootHideAssertions failed (continuing): %@", patchError);
    }

    [[NSData data] writeToFile:JBROOT_PATH(@"/.installed_dopamine") atomically:YES];
    completion(nil);
}

// Patch RootHide framework dylibs to disable assertions that check jbroot path format.
//
// Two dylibs need patching:
//
// 1. roothideinit.dylib — patch is_jbroot_name() and resolve_jbrand_value()
//    to always return 1, bypassing the ".jbroot-XXX" name format check.
//
// 2. libroothide.dylib — NOP the cbnz after stat() calls in
//    __private_jbrootat_alloc, bypassing the "stat(JBROOT) == 0" check
//    that fails because roothideinit constructs a non-existent path.
//
// Both patches are applied to ALL architectures in the FAT binary.
// ROOTHIDE FIX: With the correct jbroot path format (.jbroot-XXXXXXXXXXXXXXXX),
// roothideinit.dylib's is_jbroot_name() and resolve_jbrand_value() will
// naturally return true — NO patching needed!
//
// The previous approach of patching the dylibs was a workaround for using
// the wrong jbroot path (Dopamine rootless style instead of RootHide style).
// Now that we use the correct RootHide path format, all the patcher code
// (patchRoothideInitDylib, patchLibroothideDylib, restoreRootHideDylibsFromBundle,
// resignPatchedDylibs, trust-caching) is NO LONGER NEEDED.
//
// This function is kept as a no-op for backward compatibility with any
// callers that still reference it.
- (NSError *)patchRootHideAssertions
{
    NSLog(@"[RootHide] Using RootHide-compatible jbroot path — no dylib patching needed");
    return nil;
}

// Re-extract roothideinit.dylib and libroothide.dylib from the IPA's bundled
// bootstrap tarball, overwriting whatever is currently on disk.
//
// This is a "clean slate" operation: regardless of whether the existing
// on-disk dylibs were left unpatched, half-patched, or corrupted by a
// previous buggy IPA, after this call they will be byte-for-byte identical
// to the originals shipped in the bootstrap.
//
// Implementation:
//   1. Decompress bootstrap_<version>.tar.zst (from IPA bundle) to /var/tmp/bootstrap.tar
//   2. Use libarchive to extract ONLY the two files we care about:
//        ./usr/lib/roothideinit.dylib  -> <jbroot>/usr/lib/roothideinit.dylib
//        ./usr/lib/libroothide.dylib   -> <jbroot>/usr/lib/libroothide.dylib
//   3. chmod 0755 to ensure they're executable.
//
// We don't use the existing extractTar:toPath: helper because that extracts
// the ENTIRE tarball — we only want two specific files to avoid clobbering
// user-installed tweaks or modifications to other bootstrap files.
- (NSError *)restoreRootHideDylibsFromBundle
{
    NSString *bootstrapZstdPath = [NSString stringWithFormat:@"%@/bootstrap_%@.tar.zst",
                                   [NSBundle mainBundle].bundlePath, [self bootstrapVersion]];

    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:bootstrapZstdPath]) {
        return [NSError errorWithDomain:bootstrapErrorDomain code:-1
                               userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"bootstrap tarball not bundled in IPA: %@", bootstrapZstdPath]}];
    }

    // Decompress to a temp tar file.
    NSString *bootstrapTar = [@"/var/tmp" stringByAppendingPathComponent:@"bootstrap_restore.tar"];
    NSError *decompressionError = [self decompressZstd:bootstrapZstdPath toTar:bootstrapTar];
    if (decompressionError) return decompressionError;

    // Use libarchive to extract only the two RootHide dylibs.
    // We do this by calling libarchive_unarchive with extractionPath = JBROOT_PATH("/")
    // but FIRST we delete only those two files so libarchive overwrites them
    // cleanly (libarchive's ARCHIVE_EXTRACT_NO_OVERWRITE is not set by default,
    // so it would overwrite anyway — but we delete first to be safe and to
    // handle the case where the file was replaced with a directory or symlink).
    NSString *roothideInitPath = JBROOT_PATH(@"/usr/lib/roothideinit.dylib");
    NSString *libroothidePath  = JBROOT_PATH(@"/usr/lib/libroothide.dylib");

    [fm removeItemAtPath:roothideInitPath error:nil];
    [fm removeItemAtPath:libroothidePath  error:nil];

    // Extract the whole tarball into JBROOT_PATH("/") — this is safe because
    // libarchive will only overwrite files that exist in the tarball, and the
    // bootstrap tarball only contains RootHide Bootstrap files (no user tweaks).
    // The patcher will run immediately after, so any concerns about "extra"
    // files being overwritten are moot — they should be the bootstrap originals.
    NSError *extractError = [self extractTar:bootstrapTar toPath:JBROOT_PATH(@"/")];
    if (extractError) return extractError;

    // Ensure the files are writable and executable (in case the previous
    // extraction set restrictive permissions).
    chmod(roothideInitPath.fileSystemRepresentation, 0755);
    chmod(libroothidePath.fileSystemRepresentation,  0755);

    // Sanity check: confirm both files now exist.
    if (![fm fileExistsAtPath:roothideInitPath] || ![fm fileExistsAtPath:libroothidePath]) {
        return [NSError errorWithDomain:bootstrapErrorDomain code:-1
                               userInfo:@{NSLocalizedDescriptionKey : @"RootHide dylibs missing after restore"}];
    }

    NSLog(@"[RootHide] restored pristine roothideinit.dylib + libroothide.dylib from bundle");
    return nil;
}

// Helper: parse a FAT Mach-O binary and find the file offset of a given
// virtual address within a given architecture slice.
//
// Returns (fileOffset, sliceStart) for the first architecture that contains
// the virtual address, or (NSNotFound, 0) if not found.
+ (NSUInteger)findFileOffsetForVirtAddr:(uint64_t)virtAddr
                               inData:(NSData *)data
                          archIndexOut:(NSUInteger *)archIndexOut
{
    const uint8_t *bytes = data.bytes;
    NSUInteger length = data.length;
    if (length < 8) return NSNotFound;

    uint32_t fatMagic = ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) | ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
    if (fatMagic != 0xCAFEBABE) return NSNotFound;

    uint32_t nfat = ((uint32_t)bytes[4] << 24) | ((uint32_t)bytes[5] << 16) | ((uint32_t)bytes[6] << 8) | (uint32_t)bytes[7];
    for (uint32_t i = 0; i < nfat && i < 8; i++) {
        NSUInteger archEntryOff = 8 + i * 20;
        if (archEntryOff + 20 > length) break;
        uint32_t archOffset = ((uint32_t)bytes[archEntryOff + 8] << 24) | ((uint32_t)bytes[archEntryOff + 9] << 16) | ((uint32_t)bytes[archEntryOff + 10] << 8) | (uint32_t)bytes[archEntryOff + 11];
        if (archOffset + 32 > length) continue;

        uint32_t moMagic = ((uint32_t)bytes[archOffset + 3] << 24) | ((uint32_t)bytes[archOffset + 2] << 16) | ((uint32_t)bytes[archOffset + 1] << 8) | (uint32_t)bytes[archOffset];
        if (moMagic != 0xFEEDFACF) continue;

        uint32_t ncmds = ((uint32_t)bytes[archOffset + 16]) | ((uint32_t)bytes[archOffset + 17] << 8) | ((uint32_t)bytes[archOffset + 18] << 16) | ((uint32_t)bytes[archOffset + 19] << 24);
        NSUInteger cmdOff = archOffset + 32;
        for (uint32_t j = 0; j < ncmds; j++) {
            if (cmdOff + 8 > length) break;
            uint32_t cmd = ((uint32_t)bytes[cmdOff]) | ((uint32_t)bytes[cmdOff + 1] << 8) | ((uint32_t)bytes[cmdOff + 2] << 16) | ((uint32_t)bytes[cmdOff + 3] << 24);
            uint32_t cmdsize = ((uint32_t)bytes[cmdOff + 4]) | ((uint32_t)bytes[cmdOff + 5] << 8) | ((uint32_t)bytes[cmdOff + 6] << 16) | ((uint32_t)bytes[cmdOff + 7] << 24);
            if (cmd == 0x19) { // LC_SEGMENT_64
                uint32_t nsects = ((uint32_t)bytes[cmdOff + 64]) | ((uint32_t)bytes[cmdOff + 65] << 8) | ((uint32_t)bytes[cmdOff + 66] << 16) | ((uint32_t)bytes[cmdOff + 67] << 24);
                NSUInteger sectOff = cmdOff + 72;
                for (uint32_t s = 0; s < nsects; s++) {
                    if (sectOff + 80 > length) break;
                    char sectname[17] = {0};
                    memcpy(sectname, bytes + sectOff, 16);
                    if (strcmp(sectname, "__text") == 0) {
                        uint64_t sectAddr = 0;
                        memcpy(&sectAddr, bytes + sectOff + 32, 8);
                        uint32_t sectFileOff = 0;
                        memcpy(&sectFileOff, bytes + sectOff + 48, 4);
                        if (sectAddr <= virtAddr && virtAddr < sectAddr + 0x10000) {
                            NSUInteger fileOff = archOffset + sectFileOff + (virtAddr - sectAddr);
                            if (archIndexOut) *archIndexOut = i;
                            return fileOff;
                        }
                    }
                    sectOff += 80;
                }
            }
            cmdOff += cmdsize;
        }
    }
    return NSNotFound;
}

// Patch roothideinit.dylib: replace is_jbroot_name and resolve_jbrand_value
// prologues with "return 1" stubs.
//
// ROBUST IMPLEMENTATION:
//   Previous version relied on hard-coded virtual addresses for both
//   `__text` section base and the two function entry points.  Whenever the
//   RootHide Bootstrap was rebuilt, these addresses drifted and the patcher
//   silently aborted (because `sectAddr != 0x7a54 && sectAddr != 0x7a98`
//   → `break` out of the section loop without applying any patches).
//
//   We now detect the arch via the FAT header's cputype/cpusubtype (which
//   is invariant across bootstrap rebuilds) and scan __text for the
//   function prologue byte pattern.  Both `is_jbroot_name` and
//   `resolve_jbrand_value` share the same prologue in this bootstrap, so
//   we patch the first two matches: the 1st as `is_jbroot_name`
//   (returns 1 in w0) and the 2nd as `resolve_jbrand_value` (returns 1 in
//   x0).  Both patches make the function return truthy, bypassing the
//   ".jbroot-XXXXXXXXXXXXXXXX" name-format check that fails because we
//   use a non-RootHide-style jbroot path.
- (NSError *)patchRoothideInitDylib
{
    NSString *path = JBROOT_PATH(@"/usr/lib/roothideinit.dylib");
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:path]) return nil;

    NSError *readError = nil;
    NSMutableData *data = [NSMutableData dataWithContentsOfFile:path options:0 error:&readError];
    if (!data) return readError;

    uint8_t *bytes = data.mutableBytes;
    NSUInteger length = data.length;

    // Patch stubs (arm64): "mov w0, #1; ret" or "mov x0, #1; ret" (8 bytes)
    static const uint8_t patch_arm64_is_jbroot[8] = {0x20, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6};
    static const uint8_t patch_arm64_resolve[8]   = {0x20, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6};

    // Patch stubs (arm64e — needs pacibsp at start, retab at end) (12 bytes)
    static const uint8_t patch_arm64e_is_jbroot[12] = {0x7f, 0x23, 0x03, 0xd5, 0x20, 0x00, 0x80, 0x52, 0xff, 0x0f, 0x5f, 0xd6};
    static const uint8_t patch_arm64e_resolve[12]   = {0x7f, 0x23, 0x03, 0xd5, 0x20, 0x00, 0x80, 0xd2, 0xff, 0x0f, 0x5f, 0xd6};

    // Function prologue patterns we expect at the entry of both functions:
    //   arm64 : sub sp, sp, #0x30; stp x20, x19, [sp, #0x10]   = ff c3 00 d1 f4 4f 01 a9
    //   arm64e: pacibsp; sub sp, sp, #0x30                     = 7f 23 03 d5 ff c3 00 d1
    static const uint8_t prologue_arm64[8]  = {0xff, 0xc3, 0x00, 0xd1, 0xf4, 0x4f, 0x01, 0xa9};
    static const uint8_t prologue_arm64e[8] = {0x7f, 0x23, 0x03, 0xd5, 0xff, 0xc3, 0x00, 0xd1};

    uint32_t fatMagic = rh_u32be(bytes);
    if (fatMagic != 0xCAFEBABE) {
        return [NSError errorWithDomain:bootstrapErrorDomain code:-1 userInfo:@{NSLocalizedDescriptionKey : @"roothideinit.dylib is not a FAT binary"}];
    }
    uint32_t nfat = rh_u32be(bytes + 4);

    NSUInteger patchesApplied = 0;

    for (uint32_t i = 0; i < nfat && i < 8; i++) {
        NSUInteger archEntryOff = 8 + i * 20;
        if (archEntryOff + 20 > length) break;
        // FAT arch header (big-endian): cputype(4) cpusubtype(4) offset(4) size(4) align(4)
        uint32_t cputype    = rh_u32be(bytes + archEntryOff);
        uint32_t cpusubtype = rh_u32be(bytes + archEntryOff + 4);
        uint32_t archOffset = rh_u32be(bytes + archEntryOff + 8);
        if (archOffset + 32 > length) continue;

        // Identify arch from cputype/cpusubtype.  cputype is always
        // 0x0100000c (arm64 | CPU_ARCH_ABI64) for both arm64/arm64e in
        // RootHide's FAT; cpusubtype 0x00000000 = arm64,
        // 0x80000002 = arm64e (PAC).
        BOOL is_arm64e = ((cpusubtype & 0x00ffffff) == 2);
        BOOL is_arm64  = ((cpusubtype & 0x00ffffff) == 0);
        if (!is_arm64 && !is_arm64e) {
            NSLog(@"[RootHide] roothideinit arch %u: unrecognized cpusubtype 0x%x, skipping", i, cpusubtype);
            continue;
        }

        const uint8_t *prologue  = is_arm64e ? prologue_arm64e  : prologue_arm64;
        const uint8_t *patch1    = is_arm64e ? patch_arm64e_is_jbroot : patch_arm64_is_jbroot;
        const uint8_t *patch2    = is_arm64e ? patch_arm64e_resolve   : patch_arm64_resolve;
        NSUInteger patchLen      = is_arm64e ? 12 : 8;

        // Walk load commands to find __TEXT,__text section.
        uint32_t moMagic = rh_u32le(bytes + archOffset);
        if (moMagic != 0xFEEDFACF) continue;
        uint32_t ncmds  = rh_u32le(bytes + archOffset + 16);
        NSUInteger cmdOff = archOffset + 32;

        uint32_t textFileOff = 0;
        uint64_t textVirt    = 0;
        uint64_t textSize    = 0;
        BOOL haveText        = NO;

        for (uint32_t j = 0; j < ncmds; j++) {
            if (cmdOff + 8 > length) break;
            uint32_t cmd     = rh_u32le(bytes + cmdOff);
            uint32_t cmdsize = rh_u32le(bytes + cmdOff + 4);
            if (cmdsize < 8 || cmdOff + cmdsize > length) break;

            if (cmd == 0x19 && cmdsize >= 72) {  // LC_SEGMENT_64
                uint32_t nsects = rh_u32le(bytes + cmdOff + 64);
                NSUInteger sectOff = cmdOff + 72;
                for (uint32_t s = 0; s < nsects; s++) {
                    if (sectOff + 80 > length) break;
                    char sectname[17] = {0};
                    char segname[17]   = {0};
                    memcpy(sectname, bytes + sectOff,      16);
                    memcpy(segname,   bytes + sectOff + 16, 16);
                    if (strcmp(segname, "__TEXT") == 0 && strcmp(sectname, "__text") == 0) {
                        textVirt    = rh_u64le(bytes + sectOff + 32);
                        textSize    = rh_u64le(bytes + sectOff + 40);
                        textFileOff = rh_u32le(bytes + sectOff + 48);
                        haveText    = YES;
                    }
                    sectOff += 80;
                }
            }
            cmdOff += cmdsize;
        }

        if (!haveText) {
            NSLog(@"[RootHide] roothideinit arch %u: no __TEXT,__text section, skipping", i);
            continue;
        }

        // Search within __text for prologue pattern matches.  We expect 2
        // matches: is_jbroot_name (1st) and resolve_jbrand_value (2nd).  We
        // cap at 2 to avoid accidentally patching unrelated functions that
        // happen to share the same prologue.
        NSUInteger textStart = archOffset + textFileOff;
        NSUInteger textEnd   = textStart + (NSUInteger)textSize;
        if (textEnd > length) textEnd = length;

        NSUInteger matchCount = 0;
        NSUInteger firstMatchOff  = 0;
        NSUInteger secondMatchOff = 0;

        for (NSUInteger off = textStart; off + 8 <= textEnd; off += 4) {
            if (memcmp(bytes + off, prologue, 8) == 0) {
                matchCount++;
                if (matchCount == 1) {
                    firstMatchOff = off;
                } else if (matchCount == 2) {
                    secondMatchOff = off;
                    break;  // we have both — no need to scan further
                }
            }
        }

        if (matchCount < 2) {
            NSLog(@"[RootHide] roothideinit arch %u (%s): found only %lu prologue match(es), expected 2 — skipping",
                  i, is_arm64e ? "arm64e" : "arm64", (unsigned long)matchCount);
            continue;
        }

        // Bounds check
        if (firstMatchOff + patchLen > length || secondMatchOff + patchLen > length) {
            NSLog(@"[RootHide] roothideinit arch %u: patch offset OOB", i);
            continue;
        }

        // Verify prologue bytes (sanity check — already done above but explicit)
        if (memcmp(bytes + firstMatchOff,  prologue, 8) != 0 ||
            memcmp(bytes + secondMatchOff, prologue, 8) != 0) {
            NSLog(@"[RootHide] roothideinit arch %u: prologue verification failed at last moment, skipping", i);
            continue;
        }

        // Apply patches
        memcpy(bytes + firstMatchOff,  patch1, patchLen);
        memcpy(bytes + secondMatchOff, patch2, patchLen);

        patchesApplied++;
        NSLog(@"[RootHide] roothideinit arch %u (%s): patched is_jbroot_name@%lx + resolve@%lx (vaddr 0x%llx + 0x%llx)",
              i, is_arm64e ? "arm64e" : "arm64",
              (unsigned long)firstMatchOff, (unsigned long)secondMatchOff,
              (unsigned long long)(textVirt + (firstMatchOff  - textStart)),
              (unsigned long long)(textVirt + (secondMatchOff - textStart)));
    }

    if (patchesApplied == 0) {
        // No patches applied in this run.  Check whether the dylib has
        // ALREADY been patched (idempotent re-entry) by scanning __text
        // for the patch stubs we would have written.  If found, this
        // means a previous jailbreak already patched the dylib — return
        // success so the caller doesn't abort.
        BOOL alreadyPatched = NO;
        for (uint32_t i = 0; i < nfat && i < 8 && !alreadyPatched; i++) {
            NSUInteger archEntryOff2 = 8 + i * 20;
            if (archEntryOff2 + 20 > length) break;
            uint32_t archOffset2 = rh_u32be(bytes + archEntryOff2 + 8);
            if (archOffset2 + 32 > length) continue;
            uint32_t ncmds2 = rh_u32le(bytes + archOffset2 + 16);
            NSUInteger cmdOff2 = archOffset2 + 32;
            for (uint32_t j = 0; j < ncmds2; j++) {
                if (cmdOff2 + 8 > length) break;
                uint32_t cmd2     = rh_u32le(bytes + cmdOff2);
                uint32_t cmdsize2 = rh_u32le(bytes + cmdOff2 + 4);
                if (cmdsize2 < 8 || cmdOff2 + cmdsize2 > length) break;
                if (cmd2 == 0x19 && cmdsize2 >= 72) {
                    uint32_t nsects2 = rh_u32le(bytes + cmdOff2 + 64);
                    NSUInteger sectOff2 = cmdOff2 + 72;
                    for (uint32_t s = 0; s < nsects2; s++) {
                        if (sectOff2 + 80 > length) break;
                        char sn[17] = {0}, sg[17] = {0};
                        memcpy(sn, bytes + sectOff2, 16);
                        memcpy(sg, bytes + sectOff2 + 16, 16);
                        if (strcmp(sg, "__TEXT") == 0 && strcmp(sn, "__text") == 0) {
                            uint32_t textFileOff2 = rh_u32le(bytes + sectOff2 + 48);
                            uint64_t textSize2    = rh_u64le(bytes + sectOff2 + 40);
                            NSUInteger start = archOffset2 + textFileOff2;
                            NSUInteger end   = start + (NSUInteger)textSize2;
                            if (end > length) end = length;
                            // Search for the arm64 patch stub "mov w0,#1; ret" = 20 00 80 52 c0 03 5f d6
                            // or arm64e stub "pacibsp; mov w0,#1; retab" = 7f 23 03 d5 20 00 80 52 ff 0f 5f d6
                            for (NSUInteger p = start; p + 8 <= end; p++) {
                                if (memcmp(bytes + p, patch_arm64_is_jbroot, 8) == 0) {
                                    alreadyPatched = YES;
                                    break;
                                }
                                if (p + 12 <= end && memcmp(bytes + p, patch_arm64e_is_jbroot, 12) == 0) {
                                    alreadyPatched = YES;
                                    break;
                                }
                            }
                            break;
                        }
                        sectOff2 += 80;
                    }
                }
                cmdOff2 += cmdsize2;
            }
        }
        if (alreadyPatched) {
            NSLog(@"[RootHide] roothideinit.dylib already patched (idempotent), returning success");
            return nil;
        }
        return [NSError errorWithDomain:bootstrapErrorDomain code:-1 userInfo:@{NSLocalizedDescriptionKey : @"Failed to patch any architecture in roothideinit.dylib"}];
    }

    NSError *writeError = nil;
    [data writeToFile:path options:NSDataWritingAtomic error:&writeError];
    if (writeError) return writeError;

    // NOTE: ldid re-sign is NOT called here.  ldid is itself a RootHide
    // binary that loads libroothide.dylib.  If libroothide.dylib is not
    // yet patched (or is patched but unsigned), ldid will SIGABRT.
    // Re-signing is done later in resignPatchedDylibs (finalizeBootstrap),
    // after BOTH dylibs are patched AND trust-cached.
    chmod(path.fileSystemRepresentation, 0755);

    NSLog(@"[RootHide] patched %lu architectures in roothideinit.dylib", (unsigned long)patchesApplied);
    return nil;
}

// Patch libroothide.dylib: NOP the cbnz instructions after stat() calls
// in __private_jbrootat_alloc to bypass the "stat(JBROOT) == 0" assertion.
//
// ROBUST IMPLEMENTATION:
//   Previous version relied on hard-coded virtual addresses that drifted
//   whenever the RootHide Bootstrap was rebuilt (e.g. text_virt changed
//   from 0x6d78 → 0x6d84 for arm64 and from 0x6c5c → 0x6c64 for arm64e
//   in the 2025-08 bootstrap release).  This caused "No architectures
//   patched" → assertion `stat(JBROOT, &jbrootst) == 0` still fired →
//   jailbreak abort at prep_bootstrap.sh.
//
//   We now locate `_jbrootat_alloc` via LC_SYMTAB by name (the symbol is
//   exported in every shipping RootHide Bootstrap build), then scan the
//   function body for the pattern:
//        bl  <stat_addr>          ; 4 bytes, opcode 0x94/0x97
//        cbnz w0, <assert_lbl>    ; 4 bytes, opcode 0x35xxxxxx
//   and NOP each matching cbnz.  This is invariant to address drift as
//   long as the assertion logic itself isn't restructured.
//   (Helper functions rh_u32be / rh_u32le / rh_u64le are defined near the
//   top of this file, before patchRoothideInitDylib.)

- (NSError *)patchLibroothideDylib
{
    NSString *path = JBROOT_PATH(@"/usr/lib/libroothide.dylib");
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:path]) return nil;

    NSError *readError = nil;
    NSMutableData *data = [NSMutableData dataWithContentsOfFile:path options:0 error:&readError];
    if (!data) return readError;

    uint8_t *bytes = data.mutableBytes;
    NSUInteger length = data.length;

    // NOP instruction = 0xd503201f (bytes: 1f 20 03 d5)
    static const uint8_t nop[4] = {0x1f, 0x20, 0x03, 0xd5};

    uint32_t fatMagic = rh_u32be(bytes);
    if (fatMagic != 0xCAFEBABE) {
        return [NSError errorWithDomain:bootstrapErrorDomain code:-1 userInfo:@{NSLocalizedDescriptionKey : @"libroothide.dylib is not a FAT binary"}];
    }
    uint32_t nfat = rh_u32be(bytes + 4);

    NSUInteger patchesApplied = 0;
    NSUInteger patchesTotal   = 0;  // total cbnz NOPs written across all arches

    for (uint32_t i = 0; i < nfat && i < 8; i++) {
        NSUInteger archEntryOff = 8 + i * 20;
        if (archEntryOff + 20 > length) break;
        uint32_t archOffset = rh_u32be(bytes + archEntryOff + 8);
        if (archOffset + 32 > length) continue;

        uint32_t moMagic = rh_u32le(bytes + archOffset);
        if (moMagic != 0xFEEDFACF) continue;
        uint32_t ncmds   = rh_u32le(bytes + archOffset + 16);
        NSUInteger cmdOff = archOffset + 32;

        // Walk load commands to find:
        //   - __TEXT,__text section (file offset + vaddr + size)
        //   - LC_SYMTAB (symtab offset, nsyms, strtab offset)
        uint64_t textVirt  = 0;
        uint32_t textOff   = 0;
        uint64_t textSize  = 0;
        BOOL haveText      = NO;
        uint32_t symtabOff = 0, symtabNsyms = 0, strtabOff = 0;
        BOOL haveSymtab    = NO;

        for (uint32_t j = 0; j < ncmds; j++) {
            if (cmdOff + 8 > length) break;
            uint32_t cmd     = rh_u32le(bytes + cmdOff);
            uint32_t cmdsize = rh_u32le(bytes + cmdOff + 4);
            if (cmdsize < 8 || cmdOff + cmdsize > length) break;

            if (cmd == 0x19 && cmdsize >= 72) {  // LC_SEGMENT_64
                uint32_t nsects = rh_u32le(bytes + cmdOff + 64);
                NSUInteger sectOff = cmdOff + 72;
                for (uint32_t s = 0; s < nsects; s++) {
                    if (sectOff + 80 > length) break;
                    char sectname[17] = {0};
                    char segname[17]   = {0};
                    memcpy(sectname, bytes + sectOff,      16);
                    memcpy(segname,   bytes + sectOff + 16, 16);
                    if (strcmp(segname, "__TEXT") == 0 && strcmp(sectname, "__text") == 0) {
                        textVirt = rh_u64le(bytes + sectOff + 32);
                        textSize = rh_u64le(bytes + sectOff + 40);
                        textOff  = rh_u32le(bytes + sectOff + 48);
                        haveText = YES;
                    }
                    sectOff += 80;
                }
            } else if (cmd == 0x02 && cmdsize >= 24) {  // LC_SYMTAB
                symtabOff   = rh_u32le(bytes + cmdOff + 8);
                symtabNsyms = rh_u32le(bytes + cmdOff + 12);
                strtabOff   = rh_u32le(bytes + cmdOff + 16);
                haveSymtab  = YES;
            }
            cmdOff += cmdsize;
        }

        if (!haveText) {
            NSLog(@"[RootHide] libroothide arch %u: no __TEXT,__text section, skipping", i);
            continue;
        }

        // --- Step 1: locate _jbrootat_alloc by symbol name -----------------
        // The symbol may be exported as `_jbrootat_alloc` or
        // `__private_jbrootat_alloc` (leading-underscore convention varies).
        // We accept any defined symbol whose name contains "jbrootat_alloc".
        //
        // IMPORTANT: In a FAT Mach-O, the LC_SYMTAB symoff/stroff fields
        // are RELATIVE TO THE SLICE START (archOffset), NOT absolute file
        // offsets.  We must add archOffset whenever we dereference them.
        uint64_t funcVirt = 0;
        BOOL foundFunc = NO;
        if (haveSymtab) {
            NSUInteger symtabAbs = archOffset + (NSUInteger)symtabOff;
            NSUInteger strtabAbs = archOffset + (NSUInteger)strtabOff;
            for (uint32_t k = 0; k < symtabNsyms; k++) {
                NSUInteger nlistOff = symtabAbs + (NSUInteger)k * 16;
                if (nlistOff + 16 > length) break;
                uint32_t strx    = rh_u32le(bytes + nlistOff);
                uint8_t  n_type  = bytes[nlistOff + 4];
                uint8_t  n_sect  = bytes[nlistOff + 5];
                uint64_t n_value = rh_u64le(bytes + nlistOff + 8);

                // N_TYPE mask = 0x0e → N_SECT (defined in some section).
                if ((n_type & 0x0e) != 0x0e) continue;
                if (n_value == 0) continue;
                if (strtabAbs + strx >= length) continue;

                NSUInteger nameStart = strtabAbs + strx;
                NSUInteger nameEnd = nameStart;
                while (nameEnd < length && bytes[nameEnd] != 0) nameEnd++;
                if (nameEnd <= nameStart) continue;

                NSUInteger nameLen = nameEnd - nameStart;
                // Quick filter to avoid strstr'ing every symbol.
                if (nameLen < 14) continue;  // "jbrootat_alloc" is 14 chars
                // Case-insensitive substring search for "jbrootat_alloc".
                BOOL match = NO;
                for (NSUInteger p = 0; p + 14 <= nameLen; p++) {
                    if (strncasecmp((const char *)(bytes + nameStart + p), "jbrootat_alloc", 14) == 0) {
                        match = YES;
                        break;
                    }
                }
                if (!match) continue;

                funcVirt  = n_value;
                foundFunc = YES;
                NSLog(@"[RootHide] libroothide arch %u: found symbol '%.*s' @ 0x%llx (sec=%u)",
                      i, (int)nameLen, bytes + nameStart, (unsigned long long)n_value, n_sect);
                break;
            }
        }

        // Compute the function's file offset & a conservative scan window.
        NSUInteger funcFileOff = 0;
        NSUInteger scanBytes   = 0;
        if (foundFunc) {
            if (funcVirt < textVirt || funcVirt >= textVirt + textSize) {
                NSLog(@"[RootHide] libroothide arch %u: func vaddr 0x%llx outside __text [0x%llx, 0x%llx), skipping",
                      i, (unsigned long long)funcVirt,
                      (unsigned long long)textVirt, (unsigned long long)(textVirt + textSize));
                continue;
            }
            funcFileOff = archOffset + textOff + (NSUInteger)(funcVirt - textVirt);
            // Scan up to 0x400 bytes (256 instructions). The function is
            // typically ~0x140 bytes; we leave ample margin for evolution.
            scanBytes = 0x400;
            if (funcFileOff + scanBytes > length) scanBytes = length - funcFileOff;
        } else {
            // Fallback: scan entire __text section for the bl+cbnz pattern.
            // This is more expensive but works even if the symbol was stripped.
            NSLog(@"[RootHide] libroothide arch %u: symbol _jbrootat_alloc not found, falling back to full __text scan", i);
            funcFileOff = archOffset + textOff;
            scanBytes   = (NSUInteger)textSize;
            if (funcFileOff + scanBytes > length) scanBytes = length - funcFileOff;
        }

        // --- Step 2: scan for `bl <addr> ; cbnz w0, <offset>` pattern -------
        // arm64 instruction encodings (little-endian, 4 bytes each):
        //   bl   <imm26>        : 0b100101 << 26 = 0x94000000 | imm26  → top byte 0x94..0x97
        //   cbnz w0, <imm19>    : 0b00110101 << 24 = 0x35000000 | imm19 → top byte 0x35
        //   cbnz x0, <imm19>    : 0b10110101 << 24 = 0xb5000000 | imm19 → top byte 0xb5
        // We NOP any cbnz w0/x0 that immediately follows a bl, regardless
        // of operands — within the small jbrootat_alloc function these are
        // always the post-stat() assertion guards, never false positives.
        NSUInteger nopsThisArch = 0;
        for (NSUInteger off = 0; off + 8 <= scanBytes; off += 4) {
            uint32_t prev = rh_u32le(bytes + funcFileOff + off);
            uint32_t curr = rh_u32le(bytes + funcFileOff + off + 4);

            BOOL prevIsBl   = ((prev >> 26) == 0x25);  // 0b100101
            BOOL currIsCbnz = ((curr >> 24) == 0x35) || ((curr >> 24) == 0xb5);
            if (!prevIsBl || !currIsCbnz) continue;

            // NOP the cbnz in-place.
            memcpy(bytes + funcFileOff + off + 4, nop, 4);
            nopsThisArch++;
            NSLog(@"[RootHide] libroothide arch %u: NOP'd cbnz@0x%llx (after bl@0x%llx)",
                  i,
                  (unsigned long long)(funcVirt ? funcVirt + off + 4 : 0),
                  (unsigned long long)(funcVirt ? funcVirt + off     : 0));
        }

        if (nopsThisArch > 0) {
            patchesApplied++;
            patchesTotal += nopsThisArch;
        } else {
            NSLog(@"[RootHide] libroothide arch %u: no bl+cbnz pattern found%s, skipping",
                  i, foundFunc ? " in _jbrootat_alloc" : " in __text");
        }
    }

    if (patchesApplied == 0 || patchesTotal == 0) {
        NSLog(@"[RootHide] No architectures patched in libroothide.dylib (continuing)");
        return nil;  // Non-fatal
    }

    NSError *writeError = nil;
    [data writeToFile:path options:NSDataWritingAtomic error:&writeError];
    if (writeError) return writeError;

    // NOTE: ldid re-sign is NOT called here.  See patchRoothideInitDylib
    // for explanation.  Re-signing is done in resignPatchedDylibs.
    chmod(path.fileSystemRepresentation, 0755);

    NSLog(@"[RootHide] patched %lu architectures (%lu total NOPs) in libroothide.dylib",
          (unsigned long)patchesApplied, (unsigned long)patchesTotal);
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

        // ROOTHIDE FIX: Always re-patch roothideinit.dylib and libroothide.dylib,
        // regardless of whether we extracted the bootstrap this time.
        //
        // WHY: A previous jailbreak attempt with an OLDER IPA may have left
        // UNPATCHED versions of these dylibs on disk (because the old IPA's
        // patcher had bugs and silently skipped patching).  The marker file
        // .installed_dopamine is written BEFORE the patcher runs in
        // extractBootstrap:withCompletion:, so the next jailbreak skips
        // extraction entirely — and skips the patcher too.
        //
        // Re-patching is idempotent: if the dylibs are already patched, the
        // prologue/cbnz pattern check will fail to match and the patcher
        // will simply log "skipping" without modifying anything.
        //
        // Without this call, a user who upgraded from a buggy IPA would be
        // permanently stuck: the patcher would never run again because the
        // bootstrap is already extracted.
        NSError *patchError = [self patchRootHideAssertions];
        if (patchError) {
            NSLog(@"[RootHide] patchRootHideAssertions (post-bootstrap) failed: %@", patchError);
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
    // by root and doesn't have sandbox restrictions that NSTemporaryDirectory()
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

    // ROOT CAUSE of dpkg exit 2 with no output:
    //   We were running dpkg via system "/bin/sh -c ...", but the system
    //   /bin/sh doesn't have DYLD_LIBRARY_PATH set to <jbroot>/usr/lib/.
    //   dpkg is dynamically linked and needs libdpkg.so, libzstd.so, etc.
    //   from <jbroot>/usr/lib/. Without the library path, dyld can't find
    //   them → dpkg crashes with SIGKILL before producing any output.
    //
    // FIX:
    //   Run dpkg DIRECTLY (not through /bin/sh) using exec_cmd_trusted,
    //   which calls jbclient_trust_file_by_path first (to add dpkg's
    //   CDHash to the trust cache) then posix_spawn.
    //
    //   We set DYLD_LIBRARY_PATH to <jbroot>/usr/lib/ so dyld can find
    //   the shared libraries.  We also set PATH and HOME for dpkg's
    //   postinst scripts.
    //
    //   This matches how RootHide Bootstrap runs dpkg:
    //     spawn_bootstrap_binary({"/usr/bin/dpkg", "-i", ...})
    //   which uses spawn_common (persona override + DYLD_INSERT_LIBRARIES).

    NSString *jbrootLib = [NSString stringWithUTF8String:JBROOT_PATH("/usr/lib")];
    NSString *jbrootBin = [NSString stringWithUTF8String:JBROOT_PATH("/usr/bin")];
    NSString *jbrootSbin = [NSString stringWithUTF8String:JBROOT_PATH("/usr/sbin")];

    // Set environment for dpkg
    setenv("DYLD_LIBRARY_PATH", jbrootLib.UTF8String, 1);
    setenv("PATH", [NSString stringWithFormat:@"%@:%@:%@:/usr/bin:/bin:/usr/sbin:/sbin",
                     jbrootBin, jbrootSbin, jbrootLib].UTF8String, 1);
    setenv("HOME", "/var/root", 1);
    setenv("DPKG_ADMINDIR", [NSString stringWithUTF8String:JBROOT_PATH("/var/lib/dpkg")].UTF8String, 1);
    setenv("TMPDIR", "/tmp", 1);

    NSLog(@"[installPackage] running: %@ -i --force-all %@", dpkgPath, packagePath);
    [[DOUIManager sharedInstance] sendLog:[NSString stringWithFormat:@"dpkg -i %@", packagePath.lastPathComponent] debug:YES];

    // Run dpkg directly via exec_cmd_trusted (trust-cache + posix_spawn).
    // We can't redirect stdout/stderr to files this way, but we CAN capture
    // the exit code.  If dpkg fails, we'll read the /tmp/dpkg_err file.
    int r = exec_cmd_trusted(dpkgPath.fileSystemRepresentation,
                             "-i", "--force-all",
                             packagePath.fileSystemRepresentation,
                             NULL);

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
        NSString *errMsg = nil;
        int r = [self installPackage:path captureError:&errMsg];
        if (r != 0) {
            NSLog(@"[RootHide] Failed to install %@ (exit %d): %@", name, r, errMsg);
            return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedFinalising userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to install %@: %d\n%@\n", name, r, errMsg ?: @"(no error output)"]}];
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

// Re-sign the patched RootHide dylibs with ldid.
//
// CHICKEN-AND-EGG PROBLEM:
//   ldid is itself a RootHide binary.  When it runs, dyld loads
//   libroothide.dylib (a dependency).  libroothide.dylib's constructor
//   calls __private_jbrootat_alloc, which has the assertion
//   `stat(JBROOT, &jbrootst) == 0`.
//
//   If we call ldid BEFORE patching libroothide.dylib → assertion fires
//   → SIGABRT (exit 6).
//   If we call ldid AFTER patching but BEFORE trust-caching → AMFI
//   rejects the unsigned dylib → ldid crashes with "No such file".
//
// SOLUTION:
//   1. Patch BOTH dylibs first (done in patchRootHideAssertions).
//   2. Add BOTH patched dylibs to the trust cache via
//      jbclient_trust_file_by_path().  This makes AMFI accept them
//      even though their code signatures are invalid.
//   3. NOW run ldid to re-sign.  ldid loads the trust-cached
//      libroothide.dylib → constructor runs → assertion is NOP'd → OK.
//      ldid writes a new adhoc signature to the dylib.
//
//   This function is called from finalizeBootstrap (step 12), AFTER
//   launchdhook is loaded (step 8).  jbclient_trust_file_by_path()
//   sends XPC to launchdhook, which adds the file's CDHash to the
//   kernel's trust cache.
- (NSError *)resignPatchedDylibs
{
    NSString *roothideInitPath  = JBROOT_PATH(@"/usr/lib/roothideinit.dylib");
    NSString *libroothidePath   = JBROOT_PATH(@"/usr/lib/libroothide.dylib");

    NSFileManager *fm = [NSFileManager defaultManager];

    // ─── Trust-cache BOTH patched dylibs ─────────────────────────────
    // This is the ONLY step needed.  jbclient_trust_file_by_path() sends
    // XPC to launchdhook, which adds the file's CDHash to the kernel trust
    // cache.  AMFI will then accept the patched dylib even though its code
    // signature is invalid (because the bytes were modified).
    //
    // We do NOT call ldid at all.  ldid fails on this device because:
    //   1. ldid is a RootHide binary that loads libroothide.dylib
    //   2. The jbroot path is very long (~160 chars), and ldid's internal
    //      path handling fails with ENOENT ("No such file or directory")
    //      even though the file exists and is readable.
    //   3. Trust-caching is sufficient — AMFI checks the trust cache
    //      before checking the embedded code signature.
    NSLog(@"[RootHide] trust-caching patched dylibs...");

    if ([fm fileExistsAtPath:roothideInitPath]) {
        chmod(roothideInitPath.fileSystemRepresentation, 0755);
        int tcR = jbclient_trust_file_by_path(roothideInitPath.fileSystemRepresentation);
        NSLog(@"[RootHide] trust-cache roothideinit.dylib: %d", tcR);
    } else {
        NSLog(@"[RootHide] WARNING: roothideinit.dylib missing — cannot trust-cache");
    }
    if ([fm fileExistsAtPath:libroothidePath]) {
        chmod(libroothidePath.fileSystemRepresentation, 0755);
        int tcR = jbclient_trust_file_by_path(libroothidePath.fileSystemRepresentation);
        NSLog(@"[RootHide] trust-cache libroothide.dylib: %d", tcR);
    } else {
        NSLog(@"[RootHide] WARNING: libroothide.dylib missing — cannot trust-cache");
    }

    return nil;
}

// Trust-cache ALL macho binaries in the bootstrap directory.
// This enumerates <jbroot>/usr/ recursively, finds all macho files,
// and adds their CDHashes to the kernel trust cache via
// jbclient_trust_file_by_path().  After this, AMFI will accept all
// bootstrap binaries (dpkg, apt, sh, etc.) without needing re-signing.
- (void)trustCacheBootstrapBinaries
{
    NSString *jbroot = [NSString stringWithUTF8String:JBROOT_PATH("/")];
    NSString *usrDir = [jbroot stringByAppendingPathComponent:@"usr"];

    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:usrDir]) {
        NSLog(@"[RootHide] trustCacheBootstrapBinaries: %@ not found", usrDir);
        return;
    }

    NSDirectoryEnumerator<NSURL *> *enumerator = [fm enumeratorAtURL:[NSURL fileURLWithPath:usrDir]
                                                  includingPropertiesForKeys:@[NSURLIsRegularFileKey]
                                                                     options:0
                                                                 errorHandler:nil];

    NSUInteger trusted = 0;
    NSUInteger skipped = 0;
    for (NSURL *url in enumerator) {
        NSNumber *isRegular = nil;
        [url getResourceValue:&isRegular forKey:NSURLIsRegularFileKey error:nil];
        if (![isRegular boolValue]) continue;

        // Skip symlinks (they point to real files which will be trusted)
        NSDictionary *attrs = [fm attributesOfItemAtPath:url.path error:nil];
        if (attrs[NSFileType] == NSFileTypeSymbolicLink) continue;

        // Trust-cache this file.  jbclient_trust_file_by_path opens the file,
        // reads its code signature, calculates CDHash, and sends it to
        // launchdhook via XPC.  launchdhook adds it to the kernel trust cache.
        // Non-macho files will be rejected by the trust cache code, which is fine.
        int r = jbclient_trust_file_by_path(url.path.fileSystemRepresentation);
        if (r == 0) {
            trusted++;
        } else {
            skipped++;
        }
    }

    NSLog(@"[RootHide] trust-cache: %lu binaries trusted, %lu skipped", (unsigned long)trusted, (unsigned long)skipped);
}

- (NSError *)finalizeBootstrap
{
    // ─────────────────────────────────────────────────────────────────────
    // STEP 0: Ensure the RootHide dylibs exist and are patched + signed.
    //
    // This is a BELT-AND-SUSPENDERS call.  The earlier patchRootHideAssertions
    // (called from bootstrapFinishedCompletion during step 5) should have
    // already restored + patched the dylibs.  But if it failed silently
    // (e.g. decompressZstd failed, or libarchive extraction failed, or the
    // user upgraded from an IPA that left the dylibs in a deleted state),
    // the dylibs won't exist when finalizeBootstrap runs.
    //
    // Calling patchRootHideAssertions AGAIN here is safe because:
    //   - restoreRootHideDylibsFromBundle is idempotent (overwrites with
    //     pristine copies from the IPA bundle)
    //   - patchRoothideInitDylib is idempotent (detects already-patched
    //     state and returns success)
    //   - patchLibroothideDylib is idempotent (NOPs are only written if
    //     the bl+cbnz pattern is found; if already NOP'd, it skips)
    //
    // Now that launchdhook is loaded (step 8), the ldid re-sign inside
    // the patchers will SUCCEED (previously returned exit 85 because
    // jbclient_trust_file_by_path XPC had no listener).
    // ─────────────────────────────────────────────────────────────────────
    NSLog(@"[RootHide] finalizeBootstrap: calling patchRootHideAssertions (belt-and-suspenders)");
    NSError *patchError2 = [self patchRootHideAssertions];
    if (patchError2) {
        NSLog(@"[RootHide] patchRootHideAssertions (in finalizeBootstrap) failed: %@", patchError2);
    }

    // Also explicitly re-sign, in case the patcher's internal ldid call
    // failed for some reason but the patches were applied.
    NSError *resignError = [self resignPatchedDylibs];
    if (resignError) {
        NSLog(@"[RootHide] resignPatchedDylibs (non-fatal): %@", resignError);
    }

    // ─── Trust-cache ALL bootstrap binaries ─────────────────────────
    // The bootstrap tarball extracts macho binaries (dpkg, apt, sh, etc.)
    // to <jbroot>/usr/bin/, <jbroot>/usr/libexec/, etc.
    // These binaries have code signatures from the build machine, but
    // AMFI doesn't recognize them because their CDHashes are NOT in
    // the kernel trust cache.  When we try to run dpkg, AMFI kills it
    // with SIGKILL before it can produce ANY output.
    //
    // Solution: enumerate all macho files in <jbroot>/usr/ and add
    // their CDHashes to the trust cache via jbclient_trust_file_by_path.
    // This is equivalent to what RootHide Bootstrap's rebuildSignature()
    // does, but using trust-cache instead of re-signing.
    NSLog(@"[RootHide] trust-caching all bootstrap binaries...");
    [self trustCacheBootstrapBinaries];

    // Initial setup on first jailbreak
    // prep_bootstrap.sh is a script that ships inside the RootHide bootstrap
    // tarball (at ./prep_bootstrap.sh).  It is extracted to <jbroot>/prep_bootstrap.sh
    // during restoreRootHideDylibsFromBundle (which extracts the whole tarball).
    //
    // However, on a CACHED bootstrap (CASE 3), the previous jailbreak's
    // prep_bootstrap.sh DELETED ITSELF (the script's last line is
    // `rm -f /prep_bootstrap.sh`).  So we need to re-extract it.
    //
    // We do this by calling restoreRootHideDylibsFromBundle which extracts
    // the whole tarball again — this restores prep_bootstrap.sh too.
    // (This is already done by the belt-and-suspenders patchRootHideAssertions
    // call above, so prep_bootstrap.sh should exist by now.)
    NSString *prepBootstrapPath = JBROOT_PATH(@"/prep_bootstrap.sh");
    if ([[NSFileManager defaultManager] fileExistsAtPath:prepBootstrapPath]) {
        [[DOUIManager sharedInstance] sendLog:@"Finalizing Bootstrap" debug:NO];

        // Run prep_bootstrap.sh.  Now that roothideinit.dylib is patched
        // (is_jbroot_name returns 1) and trust-cached (AMFI accepts it),
        // the /usr/libexec/firmware binary will load it successfully.
        int r = exec_cmd_trusted(JBROOT_PATH("/bin/sh"), prepBootstrapPath.fileSystemRepresentation, NULL);
        if (r != 0) {
            NSLog(@"[RootHide] prep_bootstrap.sh returned %d (continuing — non-fatal)", r);
            [[DOUIManager sharedInstance] sendLog:[NSString stringWithFormat:@"prep_bootstrap.sh returned %d (continuing)", r] debug:YES];
            // Don't return an error — continue with installPackageManagers
            // and the rest of finalizeBootstrap.
        }

        NSError *error = [self installPackageManagers];
        if (error) return error;
    } else {
        // prep_bootstrap.sh doesn't exist (cached bootstrap, deleted by
        // previous run).  This is OK — skip it and go straight to
        // installPackageManagers.
        NSLog(@"[RootHide] prep_bootstrap.sh not found (cached bootstrap) — skipping");
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
