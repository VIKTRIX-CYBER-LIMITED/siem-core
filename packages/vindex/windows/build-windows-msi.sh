#!/bin/bash
# Build vindex-agent-<version>.msi on Linux: cross-compile the agent from this tree, then link the
# MSI with WiX 3.14 under Wine (msi-builder image). Needs Docker.
# Copyright (C) Viktrix Cyber Limited.
#
# Usage: build-windows-msi.sh <work-dir> <output-dir> [jobs]
#
# Before release, on Windows: sign the binaries and the MSI with the Viktrix code-signing
# certificate (generate_wazuh_msi.ps1 -SIGN yes shows the file list) and run ICE validation
# (light.exe without -sval, or smoke.exe), which Wine cannot do.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
WORK="$(mkdir -p "${1:?work dir}" && cd "$1" && pwd)"
OUT="$(mkdir -p "${2:?output dir}" && cd "$2" && pwd)"
JOBS="${3:-4}"
VERSION="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$REPO/VERSION.json")"
REVISION="1"
MSI="vindex-agent-${VERSION}-${REVISION}.msi"
ZIP="vindex-agent-${VERSION}-win-compiled.zip"

# 1. Cross-compile (upstream builder: mingw-w64 in Docker).
(cd "$REPO/packages/windows" && \
    bash generate_compiled_windows_agent.sh --sources "$REPO" -o "$ZIP" -j "$JOBS" -s "$WORK")

# 2. Unpack the compiled tree and link the MSI.
rm -rf "$WORK/tree" && mkdir -p "$WORK/tree"
(cd "$WORK/tree" && unzip -q "$WORK/$ZIP")
SRC="$WORK/tree/wazuh-local-src"
docker build -q -t vindex-msi-builder:wix314 "$HERE/msi-builder" >/dev/null
docker run --rm -v "$SRC:/src" vindex-msi-builder:wix314 /src/src/win32 "$MSI"

cp "$SRC/src/win32/$MSI" "$OUT/$MSI"
(cd "$OUT" && sha512sum "$MSI" > "$MSI.sha512")
echo "built $OUT/$MSI"
