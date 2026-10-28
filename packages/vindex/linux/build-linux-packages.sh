#!/bin/bash
# Build vindex-agent .deb and .rpm packages (amd64/x86_64, arm64/aarch64).
# Copyright (C) Viktrix Cyber Limited.
#
# The agent binaries are the official Wazuh 4.14.9-1 packages, built from the same v4.14.9 tag
# as branch vindex/4.14.9 and pinned by SHA-512 (manifest.json). This script renames the package
# to vindex-agent, rebrands its metadata and systemd description, and adds:
#   /usr/sbin/vindex-agent                         enrol/status CLI (install codes)
#   /var/ossec/vindex/vindex-postinstall.sh        auditd rules, auditd enabled, audit.log, AR perms
#   /var/ossec/vindex/register_configure_agent.sh  enrolment settings writer (src/init, used by the CLI)
#   /var/ossec/vindex/audit/50-soc-audit.rules     Linux audit baseline (#1058)
#   /var/ossec/active-response/bin/soc-block-ip    SOC containment AR (soc-block-ip-linux)
# Paths, service name (wazuh-agent), user and group (wazuh) are unchanged on purpose.
#
# Usage: build-linux-packages.sh <upstream-dir> <output-dir>
#   <upstream-dir> holds the official packages and their .sha512 files.
# Runs the packaging in a rockylinux:9 container (EPEL dpkg-deb, rpm-build, rpmrebuild); needs Docker.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
VINDEX="$(cd "$HERE/.." && pwd)"
UPSTREAM="$(cd "${1:?upstream dir}" && pwd)"
OUT="$(mkdir -p "${2:?output dir}" && cd "$2" && pwd)"
VERSION="4.14.9"
REVISION="1"

# Verify every upstream package against manifest.json before touching it.
python3 - "$VINDEX/manifest.json" "$UPSTREAM" <<'EOF'
import hashlib, json, os, sys
m = json.load(open(sys.argv[1]))
for name, want in m["upstream"]["sha512"].items():
    if not name.endswith((".deb", ".rpm")):
        continue
    p = os.path.join(sys.argv[2], name)
    got = hashlib.sha512(open(p, "rb").read()).hexdigest()
    if got != want:
        sys.exit(f"SHA-512 mismatch: {name}")
    print(f"verified {name}")
EOF

docker run --rm -i \
    -v "$UPSTREAM:/upstream:ro" -v "$VINDEX:/vindex:ro" -v "$OUT:/out" \
    -v "$VINDEX/../../src/init/register_configure_agent.sh:/register_configure_agent.sh:ro" \
    -e VERSION="$VERSION" -e REVISION="$REVISION" -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
    rockylinux:9 bash -s <<'EOS'
set -euo pipefail
dnf -q -y install epel-release >/dev/null && dnf -q -y install dpkg rpm-build rpmrebuild cpio file xz >/dev/null

DESC_SHORT="Vindex agent"
MAINT="Viktrix Cyber Limited <info@viktrixcyber.co.uk>"
URL="https://viktrixcyber.co.uk"

stage_extras() {  # $1 = package root
    local root="$1"
    install -D -m 0755 /vindex/common/vindex-agent "$root/usr/sbin/vindex-agent"
    install -D -m 0750 /vindex/linux/vindex-postinstall.sh "$root/var/ossec/vindex/vindex-postinstall.sh"
    install -D -m 0750 /register_configure_agent.sh "$root/var/ossec/vindex/register_configure_agent.sh"
    install -D -m 0640 /vindex/linux/audit/50-soc-audit.rules "$root/var/ossec/vindex/audit/50-soc-audit.rules"
    install -D -m 0750 /vindex/common/active-response/linux/soc-block-ip "$root/var/ossec/active-response/bin/soc-block-ip"
    # /etc/systemd/system/wazuh-agent.service stays byte-identical: it is a conffile (a changed
    # copy prompts during migration) and the upstream postinst deletes it in favour of /usr/lib.
    for unit in "$root"/usr/lib/systemd/system/wazuh-agent.service \
                "$root"/var/ossec/packages_files/agent_installation_scripts/src/init/templates/wazuh-agent.service; do
        [ -f "$unit" ] && sed -i 's/^Description=Wazuh agent$/Description=Vindex agent/' "$unit"
    done
    return 0
}

# ---------- deb ----------
for arch in amd64 arm64; do
    src="/upstream/wazuh-agent_${VERSION}-${REVISION}_${arch}.deb"
    w="/tmp/deb-$arch"; rm -rf "$w"; dpkg-deb -R "$src" "$w"
    stage_extras "$w"
    c="$w/DEBIAN/control"
    sed -i \
        -e "s/^Package: wazuh-agent$/Package: vindex-agent/" \
        -e "s/^Maintainer: .*/Maintainer: $MAINT/" \
        -e "s|^Homepage: .*|Homepage: $URL|" \
        -e "s/^Depends: \(.*\)$/Depends: \1, auditd, openssl/" \
        -e "s/^Conflicts: \(.*\)$/Conflicts: \1, wazuh-agent/" \
        "$c"
    sed -i '/^Description:/,$d' "$c"
    cat >> "$c" <<EOF
Provides: wazuh-agent
Replaces: wazuh-agent
Description: $DESC_SHORT
 Connects this server to the Vindex security console: log analysis, file
 integrity monitoring, Linux audit telemetry (auditd), intrusion detection
 and policy monitoring. Based on the Wazuh agent ${VERSION} (GPLv2).
EOF
    # Hooks run just before each script's final 'exit 0'.
    sed -i '$ d' "$w/DEBIAN/postinst"
    printf '%s\n' 'if [ "$1" = "configure" ]; then /var/ossec/vindex/vindex-postinstall.sh configure || true; fi' 'exit 0' >> "$w/DEBIAN/postinst"
    tail -n1 "$w/DEBIAN/prerm" | grep -qx 'exit 0'
    sed -i '$ d' "$w/DEBIAN/prerm"
    printf '%s\n' 'if [ "$1" = "remove" ]; then /var/ossec/vindex/vindex-postinstall.sh remove || true; fi' 'exit 0' >> "$w/DEBIAN/prerm"
    sed -i "1,3s/postinst script for wazuh-agent/postinst script for vindex-agent/" "$w/DEBIAN/postinst"
    # Migration from wazuh-agent: apt removes it first, and its postrm renames /var/ossec/etc/* to
    # *.save. Hand those to the upstream restore step (postinst restores client.keys, ossec.conf
    # and local_internal_options.conf from agent_config_files), so the agent keeps its enrolment.
    sed -i '0,/^set -e$/s//set -e\
\
# Vindex: migrating from wazuh-agent (see build-linux-packages.sh).\
if [ "$1" = "install" ] \&\& [ -f \/var\/ossec\/etc\/client.keys.save ] \&\& [ ! -f \/var\/ossec\/etc\/client.keys ]; then\
    mkdir -p \/var\/ossec\/packages_files\/agent_config_files\
    for f in client.keys ossec.conf local_internal_options.conf; do\
        if [ -f "\/var\/ossec\/etc\/$f.save" ]; then cp -p "\/var\/ossec\/etc\/$f.save" "\/var\/ossec\/packages_files\/agent_config_files\/$f"; fi\
    done\
fi/' "$w/DEBIAN/preinst"
    grep -q "Vindex: migrating from wazuh-agent" "$w/DEBIAN/preinst"
    (cd "$w" && find . -path ./DEBIAN -prune -o -type f -print0 | sed -z 's|^\./||' | sort -z | xargs -0 md5sum > DEBIAN/md5sums)
    size=$(du -sk --exclude=DEBIAN "$w" | cut -f1)
    sed -i "s/^Installed-Size: .*/Installed-Size: $size/" "$c"
    dpkg-deb --root-owner-group -Zxz -b "$w" "/out/vindex-agent_${VERSION}-${REVISION}_${arch}.deb" >/dev/null
    echo "built vindex-agent_${VERSION}-${REVISION}_${arch}.deb"
done

# ---------- rpm ----------
mkdir -p /root/rpmbuild
# rpmrebuild runs 'setarch <arch> rpm|rpmbuild ...'. Packaging needs no compiler or emulation, so
# a cross-arch rebuild only needs rpmbuild's --target; this shim provides that on any host.
cat > /usr/local/bin/setarch <<'EOF2'
#!/bin/bash
arch="$1"; shift
if [ "$(basename "$1")" = "rpmbuild" ]; then exec "$@" --target "$arch"; fi
exec "$@"
EOF2
chmod +x /usr/local/bin/setarch
for arch in x86_64 aarch64; do
    src="/upstream/wazuh-agent-${VERSION}-${REVISION}.${arch}.rpm"
    cat > /tmp/preamble.sh <<EOF
sed -e 's/^Name: .*/Name: vindex-agent/' \
    -e 's/^Summary: .*/Summary: $DESC_SHORT/' \
    -e 's/^Vendor: .*/Vendor: Viktrix Cyber Limited/' \
    -e 's/^Packager: .*/Packager: $MAINT/' \
    -e 's|^URL: .*|URL: $URL|' \
    -e 's/^License: .*/License: GPLv2/' \
    -e '/^BuildArch:/d'
# Conflicts, not Obsoletes: an obsoleted wazuh-agent runs its own %postun with \$1 = 0 after this
# package is installed, which deletes /var/ossec/bin, queue, logs and the wazuh user. install.sh
# migrates rpm hosts explicitly (back up enrolment, remove wazuh-agent, install, restore).
echo 'Conflicts: wazuh-agent'
echo 'Requires: audit'
echo 'Requires: openssl'
EOF
    cat > /tmp/files.sh <<'EOF'
cat
echo '%attr(0755, root, root) "/usr/sbin/vindex-agent"'
echo '%dir %attr(0750, root, wazuh) "/var/ossec/vindex"'
echo '%attr(0750, root, root) "/var/ossec/vindex/vindex-postinstall.sh"'
echo '%attr(0750, root, root) "/var/ossec/vindex/register_configure_agent.sh"'
echo '%dir %attr(0750, root, root) "/var/ossec/vindex/audit"'
echo '%attr(0640, root, root) "/var/ossec/vindex/audit/50-soc-audit.rules"'
echo '%attr(0750, root, wazuh) "/var/ossec/active-response/bin/soc-block-ip"'
EOF
    cat > /tmp/description.sh <<EOF
echo 'Connects this server to the Vindex security console: log analysis, file integrity monitoring,'
echo 'Linux audit telemetry (auditd), intrusion detection and policy monitoring.'
echo 'Based on the Wazuh agent ${VERSION} (GPLv2).'
EOF
    # %post: \$1 = 1 install, 2 upgrade. %preun: \$1 = 0 on erase.
    cat > /tmp/post.sh <<'EOF'
cat
echo '/var/ossec/vindex/vindex-postinstall.sh configure || :'
EOF
    cat > /tmp/preun.sh <<'EOF'
cat
echo 'if [ $1 = 0 ]; then /var/ossec/vindex/vindex-postinstall.sh remove || :; fi'
EOF
    # rpmrebuild runs --modify with the build root as its argument (older releases: in $PWD).
    cat > /tmp/modify.sh <<'EOF2'
r="${1:-}"
[ -d "$r/var/ossec" ] || r="$(ls -d /root/.tmp/rpmrebuild.*/work/root 2>/dev/null | tail -1)"
[ -d "$r/var/ossec" ] || { echo "modify: build root not found" >&2; exit 1; }
install -D -m 0755 /vindex/common/vindex-agent "$r/usr/sbin/vindex-agent"
install -D -m 0750 /vindex/linux/vindex-postinstall.sh "$r/var/ossec/vindex/vindex-postinstall.sh"
install -D -m 0750 /register_configure_agent.sh "$r/var/ossec/vindex/register_configure_agent.sh"
install -D -m 0640 /vindex/linux/audit/50-soc-audit.rules "$r/var/ossec/vindex/audit/50-soc-audit.rules"
install -D -m 0750 /vindex/common/active-response/linux/soc-block-ip "$r/var/ossec/active-response/bin/soc-block-ip"
for u in "$r"/usr/lib/systemd/system/wazuh-agent.service \
         "$r"/var/ossec/packages_files/agent_installation_scripts/src/init/templates/wazuh-agent.service; do
    [ -f "$u" ] && sed -i 's/^Description=Wazuh agent$/Description=Vindex agent/' "$u"
done
exit 0
EOF2
    rm -rf /root/rpmbuild/RPMS
    rpmrebuild --package --notest-install \
        --change-spec-preamble="bash /tmp/preamble.sh" \
        --change-spec-provides="sed '/^Provides:[[:space:]]*wazuh-agent/d'" \
        --change-spec-files="bash /tmp/files.sh" \
        --change-spec-description="bash /tmp/description.sh" \
        --change-spec-post="bash /tmp/post.sh" \
        --change-spec-preun="bash /tmp/preun.sh" \
        --modify='bash /tmp/modify.sh' \
        --directory=/tmp/rpmout "$src" 2>&1 | grep -v "Missing build-id\|NOKEY" || true
    built=$(find /tmp/rpmout -name "vindex-agent-*.rpm" | head -1)
    [ -n "$built" ] || { echo "rpmrebuild produced nothing for $arch"; exit 1; }
    cp "$built" "/out/vindex-agent-${VERSION}-${REVISION}.${arch}.rpm"
    rm -rf /tmp/rpmout
    echo "built vindex-agent-${VERSION}-${REVISION}.${arch}.rpm"
done
chown -R "$HOST_UID:$HOST_GID" /out
EOS

(cd "$OUT" && for f in vindex-agent*; do case "$f" in *.sha512) ;; *) sha512sum "$f" > "$f.sha512" ;; esac; done)

# install.sh for the console's one-line command, with this build's checksums pinned.
# VINDEX_DOWNLOAD_BASE is the public HTTPS location the packages are published to.
sha() { cut -d' ' -f1 "$OUT/$1.sha512"; }
sed -e "s|@BASE_URL@|${VINDEX_DOWNLOAD_BASE:-https://downloads.vindex.example/agent/${VERSION}-${REVISION}}|" \
    -e "s|@VERSION@|${VERSION}-${REVISION}|" \
    -e "s|@SHA_DEB_AMD64@|$(sha "vindex-agent_${VERSION}-${REVISION}_amd64.deb")|" \
    -e "s|@SHA_DEB_ARM64@|$(sha "vindex-agent_${VERSION}-${REVISION}_arm64.deb")|" \
    -e "s|@SHA_RPM_X86_64@|$(sha "vindex-agent-${VERSION}-${REVISION}.x86_64.rpm")|" \
    -e "s|@SHA_RPM_AARCH64@|$(sha "vindex-agent-${VERSION}-${REVISION}.aarch64.rpm")|" \
    "$HERE/install.sh.in" > "$OUT/install.sh"
chmod 0755 "$OUT/install.sh"
(cd "$OUT" && sha512sum install.sh > install.sh.sha512)
ls -la "$OUT"
