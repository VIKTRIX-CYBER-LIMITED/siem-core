# Linux MSI builder for the Vindex agent: WiX Toolset 3.14 under Wine with wine-mono.
# Windows release builds can use generate_wazuh_msi.ps1 with WiX 3.14 instead; both read the same
# src/win32/wazuh-installer.wxs.
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive WINEDEBUG=-all WINEPREFIX=/opt/wine WINEARCH=win64
RUN dpkg --add-architecture i386 && apt-get update && \
    apt-get install -y --no-install-recommends wine wine64 wine32 msitools gcab python3 ca-certificates curl unzip xvfb && \
    rm -rf /var/lib/apt/lists/*
# wine 6.0.x pairs with wine-mono 5.1.1 (https://wiki.winehq.org/Wine_Mono).
RUN curl -fsSL -o /tmp/mono.msi https://dl.winehq.org/wine/wine-mono/5.1.1/wine-mono-5.1.1-x86.msi && \
    wineboot --init && wine msiexec /i /tmp/mono.msi /qn && wineserver -w && rm /tmp/mono.msi
RUN curl -fsSL -o /tmp/wix.zip https://github.com/wixtoolset/wix3/releases/download/wix3141rtm/wix314-binaries.zip && \
    echo "6ac824e1642d6f7277d0ed7ea09411a508f6116ba6fae0aa5f2c7daa2ff43d31  /tmp/wix.zip" | sha256sum -c - && \
    mkdir -p /opt/wix && unzip -q /tmp/wix.zip -d /opt/wix && rm /tmp/wix.zip
COPY embed_cab.py /usr/local/bin/embed_cab.py
COPY build-msi-in-container.sh /usr/local/bin/build-msi
ENTRYPOINT ["/usr/local/bin/build-msi"]
