#!/usr/bin/env python3
"""
verify-signed.py — fail-fast check: mọi Mach-O trong thư mục phải có code signature.

TẠI SAO TỒN TẠI (bài học build cf1e9ff, 2026-08-30):
  roothidehooks.dylib được build KHÔNG có LC_CODE_SIGNATURE. Hậu quả trên device:
    1. `trustcache create` bỏ qua file không ký → không vào basebin.tc
    2. Patched dyld's fcntl LV-bypass chỉ fire khi dyld attach signature —
       binary không ký thì không bao giờ được trust động
    → dlopen() trả NULL → ASSERT(roothidehooks != NULL) tại
      systemhook/src/roothider_main.c:68 → MỌI root binary trong jbroot
      (sh, dpkg, killall...) chết exit 6 → bootstrap finalization hỏng.
  Lỗi chỉ phát hiện TRÊN DEVICE (CI vẫn xanh). Script này chặn lỗi tương tự
  ngay từ lúc build: nếu có Mach-O không ký trong .build → FAIL build.

Cách chạy: python3 verify-signed.py <thư-mục>   (exit 0 = OK, exit 1 = có lỗi)
Pure-python, không phụ thuộc otool — parse Mach-O header trực tiếp.
"""
import struct
import sys
import os

LC_CODE_SIGNATURE = 0x1D


def is_macho(data: bytes) -> bool:
    if len(data) < 4:
        return False
    magic_be = struct.unpack('>I', data[0:4])[0]
    magic_le = struct.unpack('<I', data[0:4])[0]
    # FAT big-endian: 0xCAFEBABE / 0xCAFEBABF
    if magic_be in (0xCAFEBABE, 0xCAFEBABF):
        return True
    # Thin: MH_MAGIC_64 / MH_MAGIC (little-endian)
    if magic_le in (0xFEEDFACF, 0xFEEDFACE):
        return True
    return False


def slice_has_codesig(sl: bytes) -> bool:
    """Kiểm tra 1 slice Mach-O có LC_CODE_SIGNATURE không."""
    if len(sl) < 32:
        return False
    magic = struct.unpack('<I', sl[0:4])[0]
    if magic not in (0xFEEDFACF, 0xFEEDFACE):
        return False
    is64 = magic == 0xFEEDFACF
    ncmds = struct.unpack('<I', sl[16:20])[0]
    cmdoff = 32 if is64 else 28
    for _ in range(ncmds):
        if cmdoff + 8 > len(sl):
            break
        cmd, _cmdsize = struct.unpack('<II', sl[cmdoff:cmdoff + 8])
        if cmd == LC_CODE_SIGNATURE:
            return True
        cmdoff += _cmdsize
    return False


def check_file(path: str) -> bool:
    """True nếu file không phải Mach-O hoặc MỌI slice đều có code signature."""
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError:
        return True  # không đọc được — bỏ qua (không phải trường hợp của ta)

    if not is_macho(data):
        return True  # không phải Mach-O → không yêu cầu signature

    magic_be = struct.unpack('>I', data[0:4])[0]
    slices = []
    if magic_be in (0xCAFEBABE, 0xCAFEBABF):
        nfat = struct.unpack('>I', data[4:8])[0]
        if nfat > 32:  # số liệu bất thường — coi như không hợp lệ
            return True
        for i in range(nfat):
            off = 8 + i * 20
            if off + 20 > len(data):
                break
            _cpu, _sub, soff, size = struct.unpack('>4I', data[off:off + 16])
            if soff + size <= len(data):
                slices.append(data[soff:soff + size])
    else:
        slices.append(data)

    if not slices:
        return True
    return all(slice_has_codesig(sl) for sl in slices)


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <directory>", file=sys.stderr)
        return 2
    root = sys.argv[1]
    if not os.path.isdir(root):
        print(f"ERROR: not a directory: {root}", file=sys.stderr)
        return 2

    bad = []
    checked = 0
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            p = os.path.join(dirpath, name)
            if name == '.DS_Store':
                continue
            with open(p, 'rb') as f:
                head = f.read(4)
            if not head or not is_macho(head):
                continue
            checked += 1
            if not check_file(p):
                bad.append(p)

    if bad:
        print("FAIL: các Mach-O sau KHÔNG có code signature (LC_CODE_SIGNATURE):", file=sys.stderr)
        for p in bad:
            print(f"  {p}", file=sys.stderr)
        print("Chúng sẽ bị AMFI từ chối trên device và không vào được basebin.tc!", file=sys.stderr)
        print("Hãy thêm 'ldid -Cadhoc -S' vào rule build tương ứng.", file=sys.stderr)
        return 1

    print(f"verify-signed: OK ({checked} Mach-O đều đã ký)")
    return 0


if __name__ == '__main__':
    sys.exit(main())
