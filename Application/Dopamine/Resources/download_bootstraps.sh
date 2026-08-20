#!/bin/bash
# Download RootHide bootstraps and package manager debs that will be
# embedded into Dopamine.app.
#
# WHY RootHide Bootstrap instead of standard Procursus:
#   The standard Procursus bootstrap from apt.procurs.us puts ALL files under
#   ./var/jb/... (e.g. ./var/jb/usr/bin/dpkg).  This is fine for upstream
#   rootless Dopamine which keeps /var/jb as a symlink to jbroot.  But our
#   RootHide patches intentionally REMOVED /var/jb — so files like dpkg are
#   no longer reachable at <jbroot>/usr/bin/dpkg, causing:
#     "Failed to install libroot: -101 dpkg binary does not exist"
#
#   The RootHide Bootstrap (https://github.com/RootHide/Bootstrap) is a
#   repackaged Procursus bootstrap with the correct RootHide structure:
#     - Files at ./usr/bin/dpkg, ./usr/lib/..., ./Library/dpkg/... (NO ./var/jb prefix)
#     - ./.jbroot symlink at root (resolves to .) for relative path support
#     - ./var/lib/dpkg -> .jbroot/Library/dpkg (relative symlink, works in jbroot)
#     - Pre-installed RootHide core package, libiosexec1, libkrw0, etc.
#
# WHY arm64e sileo.deb / zebra.deb from RootHide repo:
#   The RootHide bootstrap uses arm64e (PAC) architecture.  The standard
#   rootless sileo.deb and zebra.deb from Chariz/Havoc are arm64 — they
#   CANNOT be installed by dpkg on an arm64e RootHide bootstrap:
#     "dpkg: error processing archive sileo.deb (--install):
#      package architecture (iphoneos-arm64) does not match system (iphoneos-arm64e)"
#   The RootHide/Bootstrap repo provides arm64e-compiled versions of both
#   Sileo and Zebra that are compatible with the RootHide bootstrap.

set -e

# ─── Download bootstrap tarballs ───
URLS_AND_OUTPUTS=(
  "https://raw.githubusercontent.com/RootHide/Bootstrap/main/strapfiles/bootstrap-1800.tar.zst bootstrap_1800.tar.zst"
  "https://raw.githubusercontent.com/RootHide/Bootstrap/main/strapfiles/bootstrap-1900.tar.zst bootstrap_1900.tar.zst"
)

MIN_SIZE=$((10 * 1024 * 1024))  # 10 MB minimum — real bootstrap is ~19 MB

for entry in "${URLS_AND_OUTPUTS[@]}"; do
  url="${entry%% *}"
  out="${entry##* }"

  echo "Downloading $url -> $out"
  curl -fL --retry 3 --retry-delay 5 -C - "$url" --output "$out"

  size=$(stat -c%s "$out" 2>/dev/null || stat -f%z "$out")
  echo "  Downloaded $out ($size bytes)"
  if [ "$size" -lt "$MIN_SIZE" ]; then
    echo "ERROR: $out is only $size bytes (expected > $MIN_SIZE). Bootstrap download failed." >&2
    echo "       First bytes of file:" >&2
    head -c 256 "$out" >&2
    exit 1
  fi

  # Verify the file is a valid zstd archive (magic bytes 0x28 0xB5 0x2F 0xFD).
  magic=$(od -An -tx1 -N4 "$out" 2>/dev/null | tr -d ' \n')
  if [ "$magic" != "28b52ffd" ]; then
    echo "ERROR: $out does not have zstd magic bytes (got: $magic)." >&2
    echo "       First bytes of file:" >&2
    head -c 256 "$out" >&2
    exit 1
  fi
  echo "  Verified: $out is a valid zstd archive"
done

# ─── Download arm64e package manager debs ───
# These MUST be arm64e (not arm64) to install on the RootHide bootstrap.
# Source: https://github.com/RootHide/Bootstrap (root of repo)
DEB_URLS_AND_OUTPUTS=(
  "https://raw.githubusercontent.com/RootHide/Bootstrap/main/sileo.deb sileo.deb"
  "https://raw.githubusercontent.com/RootHide/Bootstrap/main/zebra.deb zebra.deb"
)

DEB_MIN_SIZE=$((100 * 1024))  # 100 KB minimum

for entry in "${DEB_URLS_AND_OUTPUTS[@]}"; do
  url="${entry%% *}"
  out="${entry##* }"

  echo "Downloading $url -> $out"
  curl -fL --retry 3 --retry-delay 5 -C - "$url" --output "$out"

  size=$(stat -c%s "$out" 2>/dev/null || stat -f%z "$out")
  echo "  Downloaded $out ($size bytes)"
  if [ "$size" -lt "$DEB_MIN_SIZE" ]; then
    echo "ERROR: $out is only $size bytes (expected > $DEB_MIN_SIZE). Deb download failed." >&2
    head -c 256 "$out" >&2
    exit 1
  fi

  # Verify it's a valid Debian package (ar archive magic: "!<arch>\n")
  magic=$(od -An -tx1 -N8 "$out" 2>/dev/null | tr -d ' \n')
  if [ "$magic" != "213c617263683e0a" ]; then
    echo "ERROR: $out does not have ar archive magic bytes (got: $magic)." >&2
    head -c 256 "$out" >&2
    exit 1
  fi
  echo "  Verified: $out is a valid Debian package"
done

echo "All RootHide bootstraps and package manager debs downloaded successfully."
