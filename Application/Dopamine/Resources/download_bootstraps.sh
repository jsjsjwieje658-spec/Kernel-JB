#!/bin/bash
# Download RootHide bootstraps that will be embedded into Dopamine.app.
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
#   This matches what the official RootHide jailbreak ships and what our
#   package Makefiles expect (./usr/lib/libroot.dylib, etc.).

set -e

URLS_AND_OUTPUTS=(
  "https://raw.githubusercontent.com/RootHide/Bootstrap/main/strapfiles/bootstrap-1800.tar.zst bootstrap_1800.tar.zst"
  "https://raw.githubusercontent.com/RootHide/Bootstrap/main/strapfiles/bootstrap-1900.tar.zst bootstrap_1900.tar.zst"
)

MIN_SIZE=$((10 * 1024 * 1024))  # 10 MB minimum — real bootstrap is ~19 MB

for entry in "${URLS_AND_OUTPUTS[@]}"; do
  url="${entry%% *}"
  out="${entry##* }"

  echo "Downloading $url -> $out"
  # -f: fail on HTTP 4xx/5xx (so a 404 page is NOT saved as the output)
  # -L: follow redirects
  # --retry: retry 3 times on transient errors
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
  # This catches the case where a CDN returns a 404 HTML page instead of the
  # real bootstrap.  We don't verify internal tar structure here because
  # macOS's native tar may not support zstd decompression; the URL is
  # hardcoded to the RootHide Bootstrap repo which ships the correct
  # ./usr/bin/dpkg layout (no ./var/jb prefix).
  magic=$(od -An -tx1 -N4 "$out" 2>/dev/null | tr -d ' \n')
  if [ "$magic" != "28b52ffd" ]; then
    echo "ERROR: $out does not have zstd magic bytes (got: $magic)." >&2
    echo "       First bytes of file:" >&2
    head -c 256 "$out" >&2
    exit 1
  fi
  echo "  Verified: $out is a valid zstd archive"
done

echo "All RootHide bootstraps downloaded successfully."
