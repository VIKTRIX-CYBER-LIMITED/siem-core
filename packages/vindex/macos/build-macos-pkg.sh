#!/bin/bash
# Build the Vindex agent macOS packages (Apple silicon and Intel). Runs on macOS.
# Copyright (C) Viktrix Cyber Limited.
#
# The agent is the official Wazuh 4.14.9-1 component package (SHA-512 pinned in manifest.json),
# wrapped in a Vindex product archive: Vindex title, background, welcome and licence pages, plus
# the vindex-agent command (/usr/local/bin) that enrols with a console install code, and its
# copy of the agent's register_configure_agent.sh (/usr/local/libexec/vindex).
# Install paths (/Library/Ossec), the launchd job and package receipts are unchanged.
#
# Usage: build-macos-pkg.sh <upstream-dir> <output-dir>
# Signing (needed for MDM and double-click installs; set both or neither):
#   VINDEX_INSTALLER_IDENTITY="Developer ID Installer: Viktrix Cyber Limited (TEAMID)"
#   VINDEX_NOTARY_PROFILE=<xcrun notarytool keychain profile>
set -euo pipefail

[ "$(uname -s)" = "Darwin" ] || { echo "build-macos-pkg.sh runs on macOS (pkgbuild, productbuild)" >&2; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
VINDEX="$(cd "$HERE/.." && pwd)"
UPSTREAM="$(cd "${1:?upstream dir}" && pwd)"
OUT="$(mkdir -p "${2:?output dir}" && cd "$2" && pwd)"
VERSION="4.14.9"
REVISION="1"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

expected_sha() {
    /usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["upstream"]["sha512"][sys.argv[2]])' \
        "$VINDEX/manifest.json" "$1"
}

# vindex-agent command, shared by both architectures.
mkdir -p "$WORK/tools-root/usr/local/bin"
install -m 0755 "$VINDEX/common/vindex-agent" "$WORK/tools-root/usr/local/bin/vindex-agent"
mkdir -p "$WORK/tools-root/usr/local/libexec/vindex"
install -m 0755 "$VINDEX/../../src/init/register_configure_agent.sh" \
    "$WORK/tools-root/usr/local/libexec/vindex/register_configure_agent.sh"
pkgbuild --root "$WORK/tools-root" --identifier uk.co.viktrixcyber.vindex.tools \
    --version "$VERSION" --install-location / "$WORK/vindex-tools.pkg" >/dev/null

mkdir -p "$WORK/resources"
cp "$HERE"/resources/* "$WORK/resources/"
cp "$VINDEX/../../LICENSE" "$WORK/resources/LICENSE.txt"

for pair in "arm64:arm64" "intel64:x86_64"; do
    upstream_arch="${pair%%:*}"; host_arch="${pair##*:}"
    agent="wazuh-agent-${VERSION}-${REVISION}.${upstream_arch}.pkg"
    want="$(expected_sha "$agent")"
    got="$(shasum -a 512 "$UPSTREAM/$agent" | cut -d' ' -f1)"
    [ "$got" = "$want" ] || { echo "SHA-512 mismatch: $agent" >&2; exit 1; }
    pkgutil --check-signature "$UPSTREAM/$agent" | grep -q "signed by a developer certificate issued by Apple" || \
        { echo "upstream signature check failed: $agent" >&2; exit 1; }
    cp "$UPSTREAM/$agent" "$WORK/"

    sed -e "s/@ARCH@/$host_arch/" -e "s/@VERSION@/$VERSION/" -e "s/@AGENT_PKG@/$agent/" \
        "$HERE/Distribution.xml.in" > "$WORK/Distribution-$upstream_arch.xml"
    name="vindex-agent-${VERSION}-${REVISION}.${upstream_arch}.pkg"
    productbuild --distribution "$WORK/Distribution-$upstream_arch.xml" --resources "$WORK/resources" \
        --package-path "$WORK" "$WORK/$name"

    if [ -n "${VINDEX_INSTALLER_IDENTITY:-}" ]; then
        productsign --sign "$VINDEX_INSTALLER_IDENTITY" --timestamp "$WORK/$name" "$OUT/$name"
        if [ -n "${VINDEX_NOTARY_PROFILE:-}" ]; then
            xcrun notarytool submit "$OUT/$name" --keychain-profile "$VINDEX_NOTARY_PROFILE" --wait
            xcrun stapler staple "$OUT/$name"
        fi
        pkgutil --check-signature "$OUT/$name"
    else
        cp "$WORK/$name" "$OUT/$name"
        echo "warning: $name is unsigned; Gatekeeper blocks double-click installs (sudo installer still works)" >&2
    fi
    (cd "$OUT" && shasum -a 512 "$name" > "$name.sha512")
    echo "built $name"
done
