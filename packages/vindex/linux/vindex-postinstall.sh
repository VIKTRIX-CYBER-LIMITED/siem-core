#!/bin/sh
# Vindex agent package hook for Linux (deb postinst/prerm, rpm %post/%preun).
# Copyright (C) Viktrix Cyber Limited. GPLv2, as the Wazuh agent it ships with.
#
#   vindex-postinstall.sh configure   install/upgrade: audit rules, auditd, audit.log, AR perms
#   vindex-postinstall.sh remove      uninstall: remove the Vindex audit rules
#
# The audit rules are soc-ai-triage deploy/linux/endpoint/50-soc-audit.rules (#1058). Their keys
# are the stock audit-wazuh-* keys the manager's audit rules match on; do not rename them.
# Failures are reported, never fatal: the agent itself must still install and report.

DIR="/var/ossec"
VDIR="${DIR}/vindex"
RULES_SRC="${VDIR}/audit/50-soc-audit.rules"
RULES_DST="/etc/audit/rules.d/50-soc-audit.rules"
CONF="${DIR}/etc/ossec.conf"

log() { echo "vindex: $*"; }

has_systemd() { command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; }

load_audit_rules() {
    if command -v augenrules >/dev/null 2>&1; then
        augenrules --load >/dev/null 2>&1 || log "augenrules --load failed; the rules load at next boot"
    elif command -v auditctl >/dev/null 2>&1; then
        auditctl -R "$RULES_DST" >/dev/null 2>&1 || log "auditctl -R failed; the rules load at next boot"
    fi
    # '-e 2' (immutable) in another rules file blocks live loading until a reboot.
    if command -v auditctl >/dev/null 2>&1 && auditctl -s 2>/dev/null | grep -q "enabled 2"; then
        log "audit rules are locked (immutable mode); reboot to activate the Vindex rules"
    fi
}

configure() {
    # 0. Migration from wazuh-agent: its removal renamed authd.pass to authd.pass.save; the
    #    preinst handed client.keys and ossec.conf to the upstream restore step already.
    if [ ! -f "${DIR}/etc/authd.pass" ] && [ -f "${DIR}/etc/authd.pass.save" ]; then
        cp -p "${DIR}/etc/authd.pass.save" "${DIR}/etc/authd.pass"
        chown root:wazuh "${DIR}/etc/authd.pass" && chmod 0640 "${DIR}/etc/authd.pass"
    fi

    # 1. auditd: installed through the package dependency; make sure it runs at boot.
    if [ -f "$RULES_SRC" ] && [ -d /etc/audit ]; then
        mkdir -p /etc/audit/rules.d
        install -m 0640 -o root -g root "$RULES_SRC" "$RULES_DST"
        if has_systemd; then
            systemctl enable auditd >/dev/null 2>&1 || true
            systemctl is-active --quiet auditd || systemctl start auditd >/dev/null 2>&1 || \
                service auditd start >/dev/null 2>&1 || log "could not start auditd"
        else
            service auditd start >/dev/null 2>&1 || true
        fi
        load_audit_rules
        log "audit rules installed ($(grep -c '^-' "$RULES_DST") rules)"
    else
        log "auditd is not installed; Linux command and file auditing is off"
    fi

    # 2. Read audit.log. The tenant's group agent.conf may declare the same file; the agent keeps
    #    the first declaration, and both use log_format audit, so either one is equivalent.
    if [ -f "$CONF" ] && ! grep -q "<location>/var/log/audit/audit.log</location>" "$CONF"; then
        cat >> "$CONF" <<'EOF'

<ossec_config>
  <!-- Vindex: Linux audit events (auditd rules in /etc/audit/rules.d/50-soc-audit.rules) -->
  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>
</ossec_config>
EOF
        log "audit.log collection added to ossec.conf"
    fi

    # 3. Active-response scripts run as root under wazuh-execd and must not be writable by others.
    for f in "${DIR}"/active-response/bin/soc-*; do
        [ -f "$f" ] || continue
        chown root:wazuh "$f" && chmod 0750 "$f"
    done
    chmod 0755 /usr/sbin/vindex-agent 2>/dev/null || true
}

remove() {
    if [ -f "$RULES_DST" ]; then
        rm -f "$RULES_DST"
        load_audit_rules
        log "Vindex audit rules removed"
    fi
}

case "$1" in
    configure) configure ;;
    remove)    remove ;;
    *)         echo "usage: $0 configure|remove" >&2 ;;
esac
exit 0
