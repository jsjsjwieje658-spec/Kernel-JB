#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <choma/MachO.h>
#include <choma/Fat.h>
#include <choma/MemoryStream.h>
#include <choma/FileStream.h>
#include <choma/CSBlob.h>
#include <choma/CodeDirectory.h>
#include <choma/Util.h>
#include <choma/Host.h>
#include <mach-o/dyld.h>
#include <libkern/OSByteOrder.h>
#include "trustcache.h"
#include "util.h"
#include "kernel.h"
#include "primitives.h"
#include "codesign.h"
// RootHide port (Relaxin upstream): bounds validation for the code signature
// blob before hashing (ROOTHIDE_SIGNATURE_MAX_BLOB_SIZE + superblob sanity).
#include "roothider/signature_policy.h"

bool macho_is_mappable(MachO *macho)
{
        // Determine if there is any case in which the macho could be mapped

        static cpu_type_t hostCpuType;
        static cpu_subtype_t hostCpuSubtype;
        static dispatch_once_t onceToken = 0;
        dispatch_once(&onceToken, ^{
                host_get_cpu_information(&hostCpuType, &hostCpuSubtype);
        });

        bool hostIsArm64e = (hostCpuType == CPU_TYPE_ARM64) && ((hostCpuSubtype & ~0xff000000) == CPU_SUBTYPE_ARM64E);

        struct mach_header *header = macho_get_mach_header(macho);

        cpu_type_t cputype = header->cputype;
        cpu_subtype_t cpusubtype = header->cpusubtype;
        bool isLibrary = (header->filetype == MH_EXECUTE);

        if (cputype != CPU_TYPE_ARM64) return false;

        if (hostIsArm64e) {
                if (cpusubtype == (CPU_SUBTYPE_ARM64E | CPU_SUBTYPE_ARM64E_ABI_V2)) {
                        // New arm64e ABI always mappable on arm64e
                        return true;
                }
                else if (cpusubtype == CPU_SUBTYPE_ARM64E && isLibrary) {
                        // Old arm64e ABI only mappable for libraries on arm64e iOS 14.6+
                        return true;
                }
        }

        // Anything arm64 is always mappable on all dvices
        if ((cpusubtype == CPU_SUBTYPE_ARM64_V8) || (cpusubtype == CPU_SUBTYPE_ARM64_ALL)) return true;

        return false;
}

bool csd_superblob_is_adhoc_signed(CS_DecodedSuperBlob *superblob)
{
        // FIX (LỖI 3 — Apps cài qua dev-cert crash sau JB):
        //
        // Bản gốc Dopamine rootless KHÔNG chấp nhận binary có CMS signature
        // (sign bằng Apple Developer certificate). Nếu SIGNATURESLOT > 8 bytes
        // (tức là có CMS blob PKCS#7 thực sự), hàm return false → binary
        // không được add vào trustcache → AMFI kill app với SIGKILL khi
        // SpringBoard launch app → user thấy "app crash ngay sau JB".
        //
        // Trên Dopamine rootless chính thức điều này OK vì rootless KHÔNG
        // hỗ trợ app dev-cert: user phải ldid -S (adhoc) trước khi cài.
        // Trên RootHide, nhiều deb (.deb roothide arm64e) chứa binary
        // sign với dev-cert (qua esign/TrollStore), và người dùng cài app
        // dev-cert thông qua RootHide Bootstrap → binary phải được trust.
        //
        // FIX: luôn return true để binary có cdhash được add vào trustcache.
        // AMFI sẽ accept binary dựa trên cdhash match (không cần CMS chain).
        // CMS signature vẫn được kiểm tra bởi AMFI (nếu có) nhưng trustcache
        // có quyền ưu tiên cao hơn.
        //
        // Đối với Dopamine app gốc (ad-hoc sign), logic này không thay đổi
        // hành vi vì ad-hoc signature luôn có SIGNATURESLOT ≤ 8 bytes.
        (void)superblob;
        return true;
}

bool code_signature_calculate_adhoc_cdhash(CS_SuperBlob *superblob, cdhash_t cdhashOut)
{
        bool isAdhocSigned = false;

        CS_DecodedSuperBlob *decodedSuperblob = csd_superblob_decode(superblob);
        if (decodedSuperblob) {
                if (csd_superblob_is_adhoc_signed(decodedSuperblob)) {
                        if (csd_superblob_calculate_best_cdhash(decodedSuperblob, cdhashOut, NULL) == 0) {
                                isAdhocSigned = true;
                        }
                }
                csd_superblob_free(decodedSuperblob);
        }

        return isAdhocSigned;
}

bool macho_parse_code_signature(MachO *macho, cdhash_t cdhashOut)
{
        bool isAdhocSigned = false;

        CS_SuperBlob *superblob = macho_read_code_signature(macho);
        if (superblob) {
                isAdhocSigned = code_signature_calculate_adhoc_cdhash(superblob, cdhashOut);
                free(superblob);
        }

        return isAdhocSigned;
}

// RootHide port (Relaxin signatures.c:79-95): the REAL cdhash calculator used
// by the roothide trust flow (roothider/signatures.m:247 calls this while
// recursively trusting an executable's dependencies). The previous compat
// stub always returned false, which made isAdhocSigned=false for every
// slice, so the randomized-cdhash path (ensure_randomized_cdhash_for_slice)
// never ran and the recursive trust never completed — apps signed with an
// Apple developer certificate were then killed by AMFI (the dev-cert crash).
//
// The superblob sanity check below is an inline equivalent of Relaxin's
// roothide_signature_superblob_is_valid() (roothider/signature_policy.c).
// It is inlined here (instead of calling the signature_policy.c version) so
// that signatures.c — a core D3 source — keeps zero new cross-object
// dependencies; referencing it across objects previously left an unresolved
// binding inside libjailbreak.dylib that broke linking roothidehooks.dylib.
//
// Kept difference vs Relaxin: csd_superblob_is_adhoc_signed() retains
// Kernel-JB's local fix (returns true) so that CMS-signed (dev-cert) binaries
// are accepted.
static bool signatures_superblob_sanity_valid(const CS_SuperBlob *superblob, uint32_t availableSize)
{
        if (!superblob || availableSize < sizeof(CS_SuperBlob)) return false;

        uint32_t length = OSSwapBigToHostInt32(superblob->length);
        uint32_t count  = OSSwapBigToHostInt32(superblob->count);

        // CSMAGIC_EMBEDDED_SIGNATURE / CSMAGIC_DETACHED_SIGNATURE
        uint32_t magic = OSSwapBigToHostInt32(superblob->magic);
        if (magic != 0xfade0cc0 && magic != 0xfade0cc1) return false;

        if (length < sizeof(CS_SuperBlob) || length > availableSize) return false;
        if (count > (length - sizeof(CS_SuperBlob)) / sizeof(CS_BlobIndex)) return false;

        // Verify every blob index entry points inside the declared superblob
        uint32_t indexTableEnd = sizeof(CS_SuperBlob) + (count * sizeof(CS_BlobIndex));
        for (uint32_t i = 0; i < count; i++) {
                uint32_t blobOffset = OSSwapBigToHostInt32(superblob->index[i].offset);
                if (blobOffset < indexTableEnd || blobOffset > length - sizeof(CS_BlobIndex)) return false;

                // generic blob header (magic + length) must fit
                if (blobOffset + 8 > length) return false;
        }
        return true;
}

bool macho_calculate_adhoc_cdhash(MachO *macho, cdhash_t cdhashOut)
{
        if (!macho || !cdhashOut) return false;

        uint32_t signatureSize = 0;
        if (macho_find_code_signature_bounds(macho, NULL, &signatureSize) != 0 || signatureSize == 0
                || signatureSize > ROOTHIDE_SIGNATURE_MAX_BLOB_SIZE)
                return false;

        bool isAdhocSigned = false;
        CS_SuperBlob *superblob = macho_read_code_signature(macho);
        if (superblob) {
                if (signatures_superblob_sanity_valid(superblob, signatureSize)) {
                        isAdhocSigned = code_signature_calculate_adhoc_cdhash(superblob, cdhashOut);
                }
                free(superblob);
        }

        return isAdhocSigned;
}

void fat_collect_untrusted_cdhashes(Fat *fat, cdhash_t **cdhashesOut, uint32_t *cdhashCountOut)
{
        __block cdhash_t *cdhashes = NULL;
        __block uint32_t cdhashCount = 0;
        fat_enumerate_slices(fat, ^(MachO *macho, bool *stop) {
                if (macho_is_mappable(macho)) {
                        cdhash_t cdhash;
                        if (macho_parse_code_signature(macho, cdhash)) {
                                if (!is_cdhash_trustcached(cdhash)) {
                                        cdhashCount++;
                                        cdhashes = realloc(cdhashes, cdhashCount * sizeof(cdhash_t));
                                        memcpy(cdhashes[cdhashCount-1], cdhash, sizeof(cdhash));
                                }
                        }
                }
        });

        *cdhashesOut = cdhashes;
        *cdhashCountOut = cdhashCount;
}

void file_collect_untrusted_cdhashes(int fd, cdhash_t **cdhashesOut, uint32_t *cdhashCountOut)
{
        MemoryStream *s = file_stream_init_from_file_descriptor(fd, 0, FILE_STREAM_SIZE_AUTO, 0);
        if (!s) return;

        Fat *fat = fat_init_from_memory_stream(s);
        if (!fat) {
                memory_stream_free(s);
                return;
        }

        fat_collect_untrusted_cdhashes(fat, cdhashesOut, cdhashCountOut);

        fat_free(fat);
}

void file_collect_untrusted_cdhashes_by_path(const char *path, cdhash_t **cdhashesOut, uint32_t *cdhashCountOut)
{
        int fd = open(path, O_RDONLY);
        if (fd < 0) return;
        file_collect_untrusted_cdhashes(fd, cdhashesOut, cdhashCountOut);
        close(fd);
}

void fat_collect_signatures(Fat *fat, struct siginfo **sigInfosOut, uint32_t *sigInfoCountOut)
{
        __block struct siginfo *sigInfos = NULL;
        __block uint32_t sigInfoCount = 0;
        fat_enumerate_slices(fat, ^(MachO *macho, bool *stop) {
                if (macho_is_mappable(macho)) {
                        CS_SuperBlob *superblob = macho_read_code_signature(macho);
                        if (superblob) {
                                sigInfoCount++;
                                sigInfos = realloc(sigInfos, sigInfoCount * sizeof(struct siginfo));
                                struct siginfo *curSigInfo = &sigInfos[sigInfoCount-1];

                                curSigInfo->source = SIGNATURE_SOURCE_ALLOCATION;
                                curSigInfo->signature.fs_file_start = macho->archDescriptor.offset;
                                curSigInfo->signature.fs_blob_start = superblob;
                                curSigInfo->signature.fs_blob_size = OSSwapBigToHostInt32(superblob->length);
                        }
                }
        });

        if (sigInfosOut) *sigInfosOut = sigInfos;
        if (sigInfoCountOut) *sigInfoCountOut = sigInfoCount;
}

void file_collect_signatures(int fd, struct siginfo **sigInfosOut, uint32_t *sigInfoCountOut)
{
        MemoryStream *s = file_stream_init_from_file_descriptor(fd, 0, FILE_STREAM_SIZE_AUTO, 0);
        if (!s) return;

        Fat *fat = fat_init_from_memory_stream(s);
        if (!fat) {
                memory_stream_free(s);
                return;
        }

        fat_collect_signatures(fat, sigInfosOut, sigInfoCountOut);

        fat_free(fat);
}


CS_SuperBlob *siginfo_resolve_superblob(struct siginfo *siginfo, int pid, int fd)
{
        if (!siginfo) return NULL;
        if (siginfo->signature.fs_blob_size == 0) return NULL;

        size_t superblobSize = siginfo->signature.fs_blob_size;
        CS_SuperBlob *superblob = malloc(superblobSize);
        if (!superblob) return NULL;

        bool success = false;

        switch (siginfo->source) {
                case SIGNATURE_SOURCE_ALLOCATION: {
                        memcpy(superblob, siginfo->signature.fs_blob_start, superblobSize);
                        success = true;
                        break;
                }
                case SIGNATURE_SOURCE_FILE: {
                        uintptr_t superblobStart = siginfo->signature.fs_file_start + (uintptr_t)siginfo->signature.fs_blob_start;
                        uintptr_t superblobEnd   = superblobStart + superblobSize;
                        struct stat st = {};

                if (fstat(fd, &st) != 0) break;
                        if (superblobEnd > st.st_size) break;
                        if (lseek(fd, superblobStart, SEEK_SET) != superblobStart) break;
                        if (read(fd, superblob, superblobSize) != superblobSize) break;

                        success = true;
                        break;
                }
                case SIGNATURE_SOURCE_PROC: {
                        uint64_t proc = proc_find(pid);

                        if (!proc) break;
                        if (proc_vreadbuf(proc, siginfo->signature.fs_blob_start, superblob, superblobSize) != 0) break;

                        success = true;
                        break;
                }
        }

        if (!success) {
                free(superblob);
                superblob = NULL;
        }

        return superblob;
}

int trust_signatures(int pid, int fd, struct siginfo *sigInfos, uint32_t sigInfoCount)
{
        if (sigInfoCount == 0) return 0;

    cdhash_t *cdhashes = malloc(sizeof(cdhash_t) * sigInfoCount);
        if (!cdhashes) return -2;
    uint32_t cdhashesCount = 0;

        struct siginfo **sigInfosToAttach = malloc(sizeof(struct siginfo *) * sigInfoCount);
        if (!sigInfosToAttach) return -2;
        uint32_t sigInfosToAttachCount = 0;

        for (uint32_t i = 0; i < sigInfoCount; i++) {
                struct siginfo *curSigInfo = &sigInfos[i];
                CS_SuperBlob *superblob = siginfo_resolve_superblob(curSigInfo, pid, fd);
                if (superblob) {
                        CS_DecodedSuperBlob *decodedSuperblob = csd_superblob_decode(superblob);
                        free(superblob);

                        if (decodedSuperblob) {
                                if (csd_superblob_is_adhoc_signed(decodedSuperblob)) {
                                        CS_DecodedBlob *bestCDBlob = csd_superblob_find_best_code_directory(decodedSuperblob);
                                        if (bestCDBlob) {
                                                if (ksymbol(SPTMArgs)) {
                                                        uint32_t flags = csd_code_directory_get_flags(bestCDBlob);
                                                        bool hasTeamId = false;
                                                        char *teamId = csd_code_directory_copy_team_id(bestCDBlob, NULL);
                                                        if (teamId) {
                                                                free(teamId);
                                                                hasTeamId = true;
                                                        }

                                                        if (!!(flags & CS_ADHOC) == hasTeamId) {
                                                                // According to TXM, either CS_ADHOC or TeamID is fine
                                                                // Both or neither are not
                                                                // Neither: We give it CS_ADHOC
                                                                // Both: We strip CS_ADHOC

                                                                if (curSigInfo->source == SIGNATURE_SOURCE_ALLOCATION) {
                                                                        if (hasTeamId) {
                                                                                // Has both TeamID and CS_ADHOC, strip CS_ADHOC
                                                                                csd_code_directory_set_flags(bestCDBlob, flags & ~CS_ADHOC);
                                                                        }
                                                                        else {
                                                                                // Has neither TeamID or CS_ADHOC, add CS_ADHOC
                                                                                csd_code_directory_set_flags(bestCDBlob, flags | CS_ADHOC);
                                                                        }

                                                                        free(curSigInfo->signature.fs_blob_start);
                                                                        superblob = csd_superblob_encode(decodedSuperblob);
                                                                        curSigInfo->signature.fs_blob_start = superblob;
                                                                        curSigInfo->signature.fs_blob_size = OSSwapBigToHostInt32(superblob->length);

                                                                        sigInfosToAttach[sigInfosToAttachCount++] = curSigInfo;
                                                                }
                                                                else {
                                                                        // If the signature does not reside inside our own address space, there is nothing we can do
                                                                        // Such a signature should have been caught by dyldhook so in reality this code path will probably never fire
                                                                        csd_superblob_free(decodedSuperblob);
                                                                        free(cdhashes);
                                                                        free(sigInfosToAttach);
                                                                        return -1;
                                                                }
                                                        }
                                                }

                                                cdhash_t cdhash;
                                                csd_code_directory_calculate_hash(bestCDBlob, &cdhash);
                                                if (!is_cdhash_trustcached(cdhash)) {
                                                        memcpy(&cdhashes[cdhashesCount++], &cdhash, sizeof(cdhash_t));
                                                }
                                        }
                                }
                                csd_superblob_free(decodedSuperblob);
                        }
                }
        }

        if (cdhashesCount > 0) {
                jb_trustcache_add_cdhashes(cdhashes, cdhashesCount);
        }

        int r = 0;
        if (sigInfosToAttachCount > 0) {
                // For every signature we have modified, we need to attach them to fd now
                for (uint32_t i = 0; i < sigInfosToAttachCount; i++) {
                        struct siginfo *curSigInfo = sigInfosToAttach[i];
                        int fd_r = fd_attach_signature(fd, &curSigInfo->signature);
                        if (fd_r != 0) r = fd_r;
                }
        }
        
        free(sigInfosToAttach);
        free(cdhashes);
        return r;
}