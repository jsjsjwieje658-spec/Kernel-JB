#!/bin/bash
# Download Procursus bootstraps that will be embedded into Dopamine.app.
#
# NOTE: Procursus only publishes bootstrap tarballs for the `arm64`
# architecture (NOT `arm64e`). The previous URL used the suffix
# `-iphoneos-arm64e.tar.zst` which returned a 404 HTML error page of only
# 153 bytes. That bogus HTML file was then copied into the IPA by Xcode's
# CpResource build phase, producing a 14 MB IPA instead of the expected ~52 MB.
#
# The arm64 bootstrap works perfectly on arm64e devices because arm64 is a
# strict subset of arm64e at the userspace ABI level (the bootstrap only
# contains userspace binaries, which the kernel happily runs).

set -e

URLS_AND_OUTPUTS=(
  "https://apt.procurs.us/bootstraps/1800/bootstrap-iphoneos-arm64.tar.zst bootstrap_1800.tar.zst"
  "https://apt.procurs.us/bootstraps/1900/bootstrap-iphoneos-arm64.tar.zst bootstrap_1900.tar.zst"
)

MIN_SIZE=$((10 * 1024 * 1024))  # 10 MB minimum — real bootstrap is ~20 MB

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
done

echo "All bootstraps downloaded successfully."
