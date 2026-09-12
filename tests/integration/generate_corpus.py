#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: CaseKey contributors
#
# Offline generator for the CaseKey integration test corpus.
#
# It creates synthetic encrypted artifacts with KNOWN passwords for the
# supported formats, plus edge-case fixtures, and writes a manifest.json the
# integration test consumes. It only produces fixtures for formats whose tool
# is installed on this (disconnected) workstation; everything else is skipped
# with a clear message. No network access is used.
#
# Usage:  python3 generate_corpus.py <output-dir>
# Then:   set CASEKEY_CORPUS=<output-dir> before running the integration test.

import json, os, shutil, subprocess, sys

# Passwords exercised across formats (kept short so a tiny wordlist cracks fast).
PW_SIMPLE  = "Password1"
PW_SPACE   = "pass word"
PW_COLON   = "pa:ss:wd"
PW_UNICODE = "caféñ"   # café ñ

def have(tool):
    return shutil.which(tool) is not None

def run(args, **kw):
    return subprocess.run(args, check=True, **kw)

def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    fixtures = []
    made, skipped = [], []

    def add(name, typ, encrypted, password=None, note=""):
        fixtures.append({"file": name, "type": typ, "encrypted": encrypted,
                         "password": password, "note": note})
        made.append(name)

    plain_src = os.path.join(outdir, "_plain_source.txt")
    with open(plain_src, "w", encoding="utf-8") as f:
        f.write("secret document body for CaseKey integration testing\n")

    # --- Edge cases that need no crypto tool ---
    # Non-encrypted artifact.
    shutil.copyfile(plain_src, os.path.join(outdir, "plain.txt"))
    add("plain.txt", "unknown", False, note="non-encrypted")
    # Malformed/corrupted artifact (PDF magic then garbage).
    with open(os.path.join(outdir, "malformed.pdf"), "wb") as f:
        f.write(b"%PDF-1.6\n" + os.urandom(64))
    add("malformed.pdf", "pdf", False, note="malformed/corrupted")

    # --- ZIP (ZipCrypto) via `zip -P` ---
    if have("zip"):
        for pw, tag in [(PW_SIMPLE, "simple"), (PW_SPACE, "space"),
                        (PW_COLON, "colon"), (PW_UNICODE, "unicode")]:
            name = f"zip_{tag}.zip"
            path = os.path.join(outdir, name)
            if os.path.exists(path):
                os.remove(path)
            run(["zip", "-j", "-P", pw, path, plain_src])
            add(name, "zip", True, pw, f"zip {tag}")
        # Misleading extension: a real ZIP named .pdf.
        mis = os.path.join(outdir, "zip_as.pdf")
        run(["zip", "-j", "-P", PW_SIMPLE, mis, plain_src])
        add("zip_as.pdf", "zip", True, PW_SIMPLE, "misleading extension (zip named .pdf)")
    else:
        skipped.append("zip (install `zip`)")

    # --- 7-Zip via `7z`/`7za` ---
    sevenzip = "7z" if have("7z") else ("7za" if have("7za") else None)
    if sevenzip:
        for pw, tag in [(PW_SIMPLE, "simple"), (PW_SPACE, "space")]:
            name = f"7z_{tag}.7z"
            path = os.path.join(outdir, name)
            if os.path.exists(path):
                os.remove(path)
            run([sevenzip, "a", f"-p{pw}", "-mhe=on", path, plain_src],
                stdout=subprocess.DEVNULL)
            add(name, "7z", True, pw, f"7z {tag}")
    else:
        skipped.append("7z (install p7zip)")

    # --- PDF via qpdf ---
    if have("qpdf"):
        # qpdf needs a real PDF input; make a trivial one if we have a producer.
        base_pdf = os.path.join(outdir, "_base.pdf")
        produced_base = False
        if have("libreoffice"):
            run(["libreoffice", "--headless", "--convert-to", "pdf",
                 "--outdir", outdir, plain_src], stdout=subprocess.DEVNULL)
            cand = os.path.join(outdir, "_plain_source.pdf")
            if os.path.exists(cand):
                shutil.move(cand, base_pdf); produced_base = True
        if produced_base:
            for pw, tag in [(PW_SIMPLE, "simple"), (PW_SPACE, "space")]:
                name = f"pdf_{tag}.pdf"
                run(["qpdf", "--encrypt", pw, pw, "256", "--", base_pdf,
                     os.path.join(outdir, name)])
                add(name, "pdf", True, pw, f"pdf {tag}")
        else:
            skipped.append("pdf (need a PDF producer, e.g. libreoffice, for qpdf input)")
    else:
        skipped.append("pdf (install qpdf)")

    # --- Office / RAR / KeePass: require proprietary or specialized tooling ---
    if not (have("msoffice-crypt") or have("msoffice-crypt.exe")):
        skipped.append("ms-office (drop in a password-protected .docx/.xlsx manually)")
    if not have("rar"):
        skipped.append("rar (proprietary; drop in a .rar made with `rar a -p` manually)")
    if not (have("keepassxc-cli")):
        skipped.append("keepass-kdbx (drop in a .kdbx made with keepassxc-cli manually)")

    with open(os.path.join(outdir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump({"fixtures": fixtures}, f, indent=2, ensure_ascii=False)

    print(f"Corpus written to {outdir}")
    print(f"  produced: {', '.join(made) or '(none)'}")
    print(f"  skipped:  {', '.join(skipped) or '(none)'}")
    print("Set CASEKEY_CORPUS to this directory to enable the integration test.")
    print("For skipped formats, add a fixture file + a manifest.json entry "
          "{file,type,encrypted,password} manually.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: generate_corpus.py <output-dir>", file=sys.stderr)
        sys.exit(2)
    main(sys.argv[1])
