# Install code contract (v1)

The Vindex console's **Endpoints → Add a device** sheet shows one install code. Every Vindex
installer accepts it, so the customer pastes a single value:

| Platform | Command shown by the console |
| --- | --- |
| Windows | `msiexec /i vindex-agent.msi INSTALL_CODE=<code> /qn` (the interactive MSI asks for it) |
| macOS | `sudo installer -pkg vindex-agent.pkg -target / && sudo vindex-agent enrol <code>` |
| Linux | `curl -fsSL <bucket>/install.sh \| sudo sh -s -- --code <code>` |

The console has no route that issues codes yet (soc-ai-triage #961, portal B17). This file is
the contract that route must implement. `tools/make_install_code.py` is the reference encoder,
and the installers' decoders are tested against it.

## Format

```
VDX1.<base64url(payload), no padding>
payload = application/x-www-form-urlencoded, ASCII only
```

| Key | Required | Meaning | Allowed value |
| --- | --- | --- | --- |
| `m` | yes | Manager address(es) the agent reports to (comma-separated) | `[][A-Za-z0-9.:,-]{1,512}` |
| `g` | yes | Agent group(s): the tenant's Wazuh group, e.g. `tenant_acme` | `[A-Za-z0-9_.,-]{1,255}` |
| `r` | no | Enrolment (authd) server; defaults to `m` | as `m` |
| `p` | no | Agent port; default 1514 | digits |
| `rp` | no | Enrolment port; default 1515 | digits |
| `k` | no | Enrolment password (`authd.pass`) | printable ASCII except `" & < >`, 1 to 128 characters |
| `x` | no (set it) | Expiry, Unix seconds UTC | digits |

Unknown keys are ignored, so later fields stay backwards compatible. Any invalid value rejects the
whole code: values are written into `ossec.conf`, so the checks also block XML injection.
Explicit installer parameters (`VINDEX_MANAGER=…`, `--manager …`) override fields from the code.

## Security notes for the issuing route

- **The code is a bearer secret.** Show it once, only to tenant administrators. The portal
  already does this.
- **Expiry is checked by the installer only.** The Wazuh manager's authd cannot check a code, so
  an expired code still holds a usable `k`. Rotating the enrolment password is the real revocation.
- **Enrolment is currently open.** The live manager runs authd with
  `<use_password>no</use_password>`, so anyone who can reach port 1515 can enrol into any group,
  with or without a code. Before customers install from the internet, turn on
  `use_password` (put `k` in every code) or agent-certificate verification, and restrict 1515 at
  the edge. Until then, `g` decides the tenant and nothing checks it.
- The group must already exist on the manager and carry the tenant label
  (`scripts/provision_tenant.py`). An agent that enrols into a missing group is refused.
