#!/usr/bin/env bash
# Download a specific kernel version for virtme-ng testing.
# Usage: download-kernel.sh <version>
# Example: download-kernel.sh 5.15
# Optional: DRY_RUN=1 to resolve and validate URL without downloading.

set -euo pipefail

VERSION="${1:?Usage: download-kernel.sh <version>}"
BASE_URL="https://kernel.ubuntu.com/mainline"

KERNEL_DIR="/tmp/kernel"
mkdir -p "$KERNEL_DIR"

echo "Downloading kernel ${VERSION}..."

# Restrict to expected matrix versions.
case "$VERSION" in
    5.4|5.14|5.15|6.1|6.8) ;;
    *)
        echo "Unknown kernel version: $VERSION"
        echo "Supported versions: 5.4, 5.14, 5.15, 6.1, 6.8"
        exit 1
        ;;
esac

version_re="$(printf '%s' "$VERSION" | sed 's/\./\\./g')"

echo "Resolving latest Ubuntu mainline directory for ${VERSION}.x..."
mainline_index="$(curl -fsSL "${BASE_URL}/")"
latest_dir="$(
    printf '%s\n' "$mainline_index" \
    | grep -Eo "href=\"v${version_re}\.[0-9]+/\"" \
    | sed -E 's/^href="(v[^"]+)\/"$/\1/' \
    | sort -V \
    | tail -n 1
)"

if [ -z "$latest_dir" ]; then
    echo "ERROR: No Ubuntu mainline directory found for ${VERSION}.x under ${BASE_URL}/" >&2
    exit 1
fi

amd64_dir_url="${BASE_URL}/${latest_dir}/amd64/"
echo "Resolved directory: ${latest_dir}"
echo "Searching package list in ${amd64_dir_url}"

amd64_index="$(curl -fsSL "$amd64_dir_url")"
deb_name="$(
    printf '%s\n' "$amd64_index" \
    | grep -Eo 'href="linux-image-unsigned-[^"]*-generic[^"]*_amd64\.deb"' \
    | sed -E 's/^href="([^"]+)"$/\1/' \
    | sort -V \
    | tail -n 1
)"

if [ -z "$deb_name" ]; then
    echo "ERROR: No linux-image-unsigned generic amd64 .deb found in ${amd64_dir_url}" >&2
    exit 1
fi

URL="${amd64_dir_url}${deb_name}"
echo "Resolved package: ${deb_name}"
echo "Validating URL: ${URL}"
if ! curl -fsI "$URL" >/dev/null; then
    echo "ERROR: Resolved kernel URL is not reachable: ${URL}" >&2
    exit 1
fi

if [ "${DRY_RUN:-0}" = "1" ]; then
    echo "DRY_RUN=1 set; metadata resolution and URL validation succeeded."
    echo "Would download: ${URL}"
    exit 0
fi

DEB_FILE="$KERNEL_DIR/linux-image.deb"

echo "Fetching: $URL"
curl -fsSL -o "$DEB_FILE" "$URL"

echo "Extracting vmlinuz..."
cd "$KERNEL_DIR"
ar x "$DEB_FILE"
tar xf data.tar.* 2>/dev/null || tar xf data.tar

# Find vmlinuz
VMLINUZ=$(find "$KERNEL_DIR" -name "vmlinuz-*" -type f | head -1)
if [ -z "$VMLINUZ" ]; then
    echo "ERROR: vmlinuz not found in kernel package"
    exit 1
fi

cp "$VMLINUZ" "$KERNEL_DIR/vmlinuz"
echo "Kernel ready: $KERNEL_DIR/vmlinuz"
echo "Version: $(file "$KERNEL_DIR/vmlinuz")"
