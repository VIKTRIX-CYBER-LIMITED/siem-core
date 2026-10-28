#!/bin/bash
# Runs inside the msi-builder image. $1 = path to the compiled tree's src/win32, $2 = MSI name.
#
# Wine 6.0 cannot create the cabinet WiX asks for, so files are linked uncompressed and
# embed_cab.py builds and embeds simple.cab natively (gcab + msitools). The installed result is
# the same as a WiX build on Windows. Windows release builds can use generate_wazuh_msi.ps1.
set -euo pipefail
cd "$1"
sed -e 's/<File Id="\([^"]*\)"/<File Compressed="no" Id="\1"/' wazuh-installer.wxs > vindex-build.wxs
wine /opt/wix/candle.exe -nologo vindex-build.wxs -out vindex-build.wixobj -ext WixUtilExtension -ext WixUIExtension
# ICE validation needs the Windows Installer validation engine; run it on Windows before release.
mkdir -p vindex-out
wine /opt/wix/light.exe -nologo vindex-build.wixobj -out "vindex-out\\$2" -ext WixUtilExtension -ext WixUIExtension -sval -spdb
wineserver -w
mv "vindex-out/$2" "$2"
rm -rf vindex-out vindex-build.wixobj
python3 /usr/local/bin/embed_cab.py "$2" vindex-build.wxs .
rm -f vindex-build.wxs
ls -la "$2"
