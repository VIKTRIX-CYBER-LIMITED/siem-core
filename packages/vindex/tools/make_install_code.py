#!/usr/bin/env python3
"""Make a Vindex install code (reference implementation of packages/vindex/docs/install-code.md).

The console's enrolment route should mint codes exactly like this; installers decode them in
windows/vindex-installer.vbs and common/vindex-agent.

  make_install_code.py --manager agents.example.com --group tenant_acme [--password P]
                       [--registration-server H] [--port 1514] [--registration-port 1515]
                       [--ttl-hours 24]
"""
import argparse
import base64
import re
import time
import urllib.parse

RULES = {
    "m": r"[A-Za-z0-9.:,\[\]-]{1,512}",
    "r": r"[A-Za-z0-9.:,\[\]-]{1,512}",
    "g": r"[A-Za-z0-9_.,-]{1,255}",
    "k": r"[ !#-%'-;=?-~]{1,128}",  # printable ASCII except " & < >
    "p": r"[0-9]{1,10}",
    "rp": r"[0-9]{1,10}",
    "x": r"[0-9]{1,10}",
}


def make_code(fields):
    for key, value in fields.items():
        if not re.fullmatch(RULES[key], value):
            raise ValueError(f"invalid value for {key!r}")
    query = urllib.parse.urlencode(fields, quote_via=urllib.parse.quote)
    return "VDX1." + base64.urlsafe_b64encode(query.encode()).decode().rstrip("=")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--manager", required=True)
    ap.add_argument("--group", required=True)
    ap.add_argument("--password")
    ap.add_argument("--registration-server")
    ap.add_argument("--port", type=int)
    ap.add_argument("--registration-port", type=int)
    ap.add_argument("--ttl-hours", type=float, default=24.0)
    a = ap.parse_args()
    fields = {"m": a.manager, "g": a.group}
    if a.registration_server:
        fields["r"] = a.registration_server
    if a.port:
        fields["p"] = str(a.port)
    if a.registration_port:
        fields["rp"] = str(a.registration_port)
    if a.password:
        fields["k"] = a.password
    fields["x"] = str(int(time.time() + a.ttl_hours * 3600))
    print(make_code(fields))


if __name__ == "__main__":
    main()
