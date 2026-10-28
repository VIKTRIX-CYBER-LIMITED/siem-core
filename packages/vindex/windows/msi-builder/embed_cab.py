#!/usr/bin/env python3
"""Embed the agent payload cabinet into an MSI linked by WiX under Wine.

Wine's cabinet.dll cannot write the cabinet WiX asks for, so the Linux build links every file as
uncompressed (File/@Compressed="no") and this step does what light.exe does on Windows:
build simple.cab from the File table (keys as names, in Sequence order, MSZIP), embed it as
the "simple.cab" stream, point Media.Cabinet at "#simple.cab" and clear the per-file
"noncompressed" attribute so the package installs from the embedded cabinet.

usage: embed_cab.py <msi> <wxs> <wxs-dir>
"""
import csv
import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

NONCOMPRESSED = 0x2000
WIX = "{http://schemas.microsoft.com/wix/2006/wi}"


def sources(wxs, base):
    out = {}
    for f in ET.parse(wxs).iter(WIX + "File"):
        src = f.get("Source").replace("\\", "/")
        out[f.get("Id")] = os.path.normpath(os.path.join(base, src))
    return out


def export(msi, table, workdir):
    text = subprocess.run(["msiinfo", "export", msi, table], check=True,
                          capture_output=True, text=True).stdout
    path = os.path.join(workdir, table + ".idt")
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
    rows = list(csv.reader(text.splitlines(), delimiter="\t"))
    return path, rows


def main(msi, wxs, base):
    src = sources(wxs, base)
    work = tempfile.mkdtemp(prefix="vindex-cab-")
    try:
        path, rows = export(msi, "File", work)
        head, data = rows[:3], rows[3:]
        cols = head[0]
        i_key, i_attr, i_seq = cols.index("File"), cols.index("Attributes"), cols.index("Sequence")
        data.sort(key=lambda r: int(r[i_seq]))
        stage = os.path.join(work, "cab")
        os.mkdir(stage)
        names = []
        for r in data:
            key = r[i_key]
            if key not in src:
                sys.exit(f"no Source for File {key}")
            shutil.copyfile(src[key], os.path.join(stage, key))
            names.append(key)
            attr = int(r[i_attr] or 0) & ~NONCOMPRESSED
            r[i_attr] = str(attr) if attr else ""
        cab = os.path.join(work, "simple.cab")
        subprocess.run(["gcab", "-c", "-z", cab] + names, cwd=stage, check=True)
        with open(path, "w", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh, delimiter="\t", lineterminator="\r\n")
            w.writerows(head + data)
        subprocess.run(["msibuild", msi, "-i", path], check=True)
        subprocess.run(["msibuild", msi, "-a", "simple.cab", cab], check=True)
        subprocess.run(["msibuild", msi, "-q",
                        "UPDATE `Media` SET `Cabinet` = '#simple.cab' WHERE `DiskId` = 1"], check=True)
        print(f"embedded {len(names)} files ({os.path.getsize(cab)} bytes) into {msi}")
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main(*sys.argv[1:4])
