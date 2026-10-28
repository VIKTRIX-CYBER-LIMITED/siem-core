# Vindex agent packaging

Vindex-branded endpoint agent installers for Windows (MSI), Linux (deb/rpm with auditd) and macOS
(pkg). They are built from branch `vindex/4.14.9`, which is upstream Wazuh `v4.14.9` plus
Vindex branding and the files in this directory.

**Why 4.14.9 and not `main`:** `main` is Wazuh 5.1.0-alpha. A Wazuh manager refuses agents newer
than itself, and the live manager is 4.14.9. Agent releases follow the manager version, so the
next branch is cut when the manager is upgraded.

## What the customer gets

| | Windows | Linux | macOS |
| --- | --- | --- | --- |
| Package | `vindex-agent-4.14.9-1.msi` (x86/x64) | `vindex-agent_4.14.9-1_{amd64,arm64}.deb`, `vindex-agent-4.14.9-1.{x86_64,aarch64}.rpm`, `install.sh` | `vindex-agent-4.14.9-1.{arm64,intel64}.pkg` |
| Enrolment | `INSTALL_CODE=` or install-code page | `install.sh --code` or `vindex-agent enrol` | `vindex-agent enrol` |
| Telemetry extras | Sysmon with `sysmon-baseline.xml` | auditd + `50-soc-audit.rules`, audit.log collected | none (unified logs from the agent) |
| SOC response scripts | `soc-block-ip*`, `soc-hash-file`, `soc-investigate-ip` | `soc-block-ip` | none |
| Housekeeping | `Vindex Sysmon archive prune` task; Sysmon log capped at 256 MB, overwriting | none | none |

"Wazuh" is replaced wherever a customer sees it: product name, publisher, Add/Remove Programs,
service display name, file properties, the agent manager window, Start menu, installer pages,
package metadata, systemd description, and CLI output. Deliberately unchanged:
- **Paths and identifiers:** install paths, the service name `WazuhSvc`, the `wazuh-agent`
  unit and binaries, the `wazuh` user and group, the `audit-wazuh-*` audit keys, and the agent's
  protocol banner. The manager, upgrades and the SOC's rules depend on them.
- **GPL attribution:** the copyright notices and "Based on Wazuh" lines stay.

Assets from soc-ai-triage are copied unchanged (see `manifest.json`, `assets_from`): the Sysmon
baseline, the SOC active-response scripts and the Linux audit rules. When they change there,
re-copy them here and rebuild.

## Building

All builds run on Linux with Docker, except macOS, which needs a Mac or a macOS CI runner.
`<upstream>` holds the official 4.14.9-1 packages; every build checks them against the SHA-512
values in `manifest.json`.

```bash
packages/vindex/windows/build-windows-msi.sh ~/build/win ~/build/dist
```
```bash
VINDEX_DOWNLOAD_BASE=https://<bucket-host>/agent/4.14.9-1 packages/vindex/linux/build-linux-packages.sh <upstream> ~/build/dist
```
```bash
packages/vindex/macos/build-macos-pkg.sh <upstream> ~/build/dist
```

- **Windows:** cross-compiles the agent from this tree (upstream mingw builder), then links the
  MSI with WiX 3.14 under Wine (`windows/msi-builder`). Wine cannot write WiX cabinets, so
  `embed_cab.py` builds and embeds the cabinet with msitools. The result holds the official
  4.14.9 file set plus the 10 Vindex files.
- **Linux:** repackages the official packages as `vindex-agent` and writes `install.sh` with
  this build's checksums pinned.
- **macOS:** wraps the official signed component in a Vindex product archive and adds
  `/usr/local/bin/vindex-agent`. Set `VINDEX_INSTALLER_IDENTITY` and `VINDEX_NOTARY_PROFILE` to
  sign and notarise.

## Hosting in the bucket

Publish everything for one release under a versioned prefix, and never overwrite a released file:

```
agent/4.14.9-1/install.sh
agent/4.14.9-1/vindex-agent-4.14.9-1.msi
agent/4.14.9-1/vindex-agent_4.14.9-1_amd64.deb   (and arm64)
agent/4.14.9-1/vindex-agent-4.14.9-1.x86_64.rpm  (and aarch64)
agent/4.14.9-1/vindex-agent-4.14.9-1.arm64.pkg   (and intel64)
agent/4.14.9-1/*.sha512
agent/latest/install.sh                          (copy of the current release's install.sh)
```

- Serve over HTTPS only (install.sh refuses plain HTTP), with public read on these objects and
  nothing else in the bucket.
- `VINDEX_DOWNLOAD_BASE` must be the exact versioned prefix (`https://…/agent/4.14.9-1`).
  `install.sh` downloads `$VINDEX_DOWNLOAD_BASE/<package>` and checks it against its pinned
  SHA-512. The URL is only baked in at build time, so set it before building.
- Short cache lifetime for `latest/`, long (immutable) for versioned paths.
- Content types: `application/x-msi`, `application/vnd.debian.binary-package`,
  `application/x-rpm`, `application/octet-stream` for `.pkg`, `text/x-shellscript` for `install.sh`.
- The console's download buttons and commands (DeviceSetupSheet) should point at the bucket. It
  currently shows the placeholder `get.vindex.example`.

## Release checklist

1. Manager version still matches the agent (agents must not be newer than the manager).
2. Build all three platforms from a clean `vindex/<version>` checkout. Record the commit.
3. **Sign:**
   - Windows: Authenticode-sign the `.exe`/`.dll` files and the MSI with the Viktrix
     code-signing certificate (EV certificates avoid SmartScreen warnings).
   - macOS: Developer ID Installer signing plus notarisation.
   - Linux (optional): GPG-sign packages, or serve an apt/yum repository.
   - Unsigned builds work for testing only.
4. Windows: run ICE validation on a Windows host (the Linux build skips it).
5. Smoke-test on clean VMs (Windows 10/11 and Server 2019/2022, Ubuntu 22.04/24.04, RHEL/Rocky 9,
   macOS 14/15):
   - silent and interactive install, then the device appears in the console;
   - uninstall leaves no task and removes Sysmon only if this installer added it;
   - upgrade over an existing Wazuh agent keeps its agent ID.
6. Upload to the bucket under the versioned prefix, then update `latest/`.
7. Publish the source for this release (`vindex/<version>` branch). The agent is GPLv2, so
   customers receiving binaries are entitled to the corresponding source.

## Known gaps (need decisions or other repos)

- **Enrolment is open.** The manager's authd has `use_password no`, so anyone who can reach port
  1515 can enrol into any tenant group. Fix this before internet-facing customers install (see
  `docs/install-code.md`).
- **The console cannot issue install codes yet** (#961/B17). The contract is
  `docs/install-code.md`, with a reference encoder in `tools/make_install_code.py`.
- **`soc-block-ip` signed acknowledgements:** the sidecar (`soc-block-ip.secrets.json`) needs the
  agent ID the manager assigns *after* enrolment, so no installer can write it. The scripts are
  installed, but signed-ack containment stays off until the backend delivers the sidecar per
  agent. Stock `netsh`/`firewall-drop` responses are unaffected.
- **Collection config comes from the tenant's group `agent.conf`.** The Windows installer does not
  add a Sysmon `<localfile>`: a local copy would win over the group's filtered one and undo its
  noise suppression. Every tenant group's `agent.conf` must carry the Sysmon and
  Security channels (see the `acme` group). Linux adds audit.log locally, because both copies are
  identical.
- **Manager-pushed upgrades (WPK) install the upstream Wazuh agent and undo the branding.** Upgrade
  by shipping a new Vindex package instead, or build Vindex WPKs (`packages/wpk`).
- **Sysmon is downloaded at install time** from Sysinternals and must carry a valid Microsoft
  signature. It is not bundled, because the Sysinternals licence restricts redistribution. Offline
  sites pass `SYSMON_ZIP=<path to Sysmon.zip>`; `SYSMON=required` makes a missing Sysmon fail the
  install.
- **macOS:** one package per architecture, because both official components share one identifier.
  The console needs an arm64/Intel choice, or a universal package as follow-up work. Full Disk
  Access for the agent is granted by the customer or through an MDM privacy profile.

## Installer reference

**Windows MSI properties:**
- `INSTALL_CODE`
- `VINDEX_MANAGER`, `VINDEX_AGENT_GROUP`, `VINDEX_REGISTRATION_SERVER`,
  `VINDEX_REGISTRATION_PORT`, `VINDEX_REGISTRATION_PASSWORD`, `VINDEX_AGENT_NAME`,
  `VINDEX_MANAGER_PORT`, `VINDEX_PROTOCOL`
- `SYSMON` (`install` | `required` | `skip`), `SYSMON_CONFIG` (`keep` | `replace`), `SYSMON_ZIP`

The setup log is `C:\Program Files (x86)\ossec-agent\vindex\setup.log`. Secrets are hidden from
verbose MSI logs.

**Linux/macOS:** `vindex-agent enrol <code> [--name n] [--force]`, `vindex-agent status`,
`vindex-agent restart` and `vindex-agent version`. `install.sh` also takes
`--manager/--group/--password/--name`. If a Wazuh agent is already installed, `install.sh` keeps
its enrolment and does not use the code.
