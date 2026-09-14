#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: CaseKey contributors
#
# Assemble the third-party recovery engines into a CaseKey Windows release
# bundle, laid out to match CaseKey's portable discovery so everything resolves
# with no configuration.
#
# Sources and pinned versions live in tools/engines.lock.json. Integrity is
# FAIL-CLOSED: every engine must carry a matching sha256 or nothing is bundled,
# so an unverified third-party binary never ships in a forensic tool.
#
# Usage:
#   python tools/fetch_engines.py --check                    # verify the lockfile is bootstrapped (no download)
#   python tools/fetch_engines.py --dest <bundle-dir>        # download, verify, lay out
#   python tools/fetch_engines.py --print-hashes             # download + print sha256 only
#   python tools/fetch_engines.py --dest <d> --only bkcrack  # a subset
#
# Extraction of .7z archives shells out to `7z` (present on GitHub Windows
# runners and via p7zip); .zip is handled in-process. file:// URLs are accepted
# so the layout/verify logic can be exercised offline in tests.

import argparse
import fnmatch
import glob
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
LOCK = os.path.join(HERE, "engines.lock.json")


def load_lock():
    with open(LOCK, "r", encoding="utf-8") as f:
        return json.load(f)


def download(url, dest):
    # file:// and http(s):// both handled by urllib; proxies honored from env.
    with urllib.request.urlopen(url) as r, open(dest, "wb") as out:
        shutil.copyfileobj(r, out)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def normalized_sha256(engine):
    """Return the engine's lower-cased sha256 if it is a valid 64-hex digest, else None."""
    want = (engine.get("sha256") or "").strip().lower()
    if len(want) == 64 and all(c in "0123456789abcdef" for c in want):
        return want
    return None


def do_check(lock, only):
    """Fail-closed preflight: confirm every (selected) engine carries a valid sha256.

    Downloads nothing. Used at the start of the release workflow so a lockfile that
    has not been bootstrapped fails in seconds with an actionable message, instead of
    after a full build. Exit 0 when the lockfile is ready to bundle, 2 otherwise.
    """
    unlocked = [e["id"] for e in lock["engines"]
                if not (only and e["id"] not in only) and normalized_sha256(e) is None]
    if unlocked:
        print("ERROR: the engine lockfile is not bootstrapped; the full bundle cannot be built.",
              file=sys.stderr)
        print(f"  missing a valid sha256 for: {', '.join(unlocked)}", file=sys.stderr)
        print("  Integrity is fail-closed: CaseKey never ships an unverified third-party binary.",
              file=sys.stderr)
        print("  To fix (once, on a networked machine or via this workflow):", file=sys.stderr)
        print("    1. Run this workflow with 'bootstrap_hashes = true' (Actions -> Run workflow),",
              file=sys.stderr)
        print("       or run: python tools/fetch_engines.py --print-hashes", file=sys.stderr)
        print("    2. Confirm each 'url'/'version' in tools/engines.lock.json is the intended",
              file=sys.stderr)
        print("       official artifact, then paste the printed digests into the 'sha256' fields.",
              file=sys.stderr)
        print("    3. Commit engines.lock.json and re-run this workflow to publish the bundle.",
              file=sys.stderr)
        return 2
    print("OK: every bundled engine has a valid sha256; the lockfile is ready to bundle.")
    return 0


def extract(archive_path, kind, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    if kind == "zip":
        with zipfile.ZipFile(archive_path) as z:
            z.extractall(out_dir)
    elif kind == "7z":
        exe = shutil.which("7z") or shutil.which("7za") or shutil.which("7z.exe")
        if not exe:
            raise RuntimeError("a 7-Zip CLI (7z/7za) is required to extract " + archive_path)
        subprocess.run([exe, "x", "-y", "-o" + out_dir, archive_path],
                       check=True, stdout=subprocess.DEVNULL)
    else:
        raise RuntimeError("unknown archive kind: " + kind)


def source_root(extracted, strip_top_dir):
    if not strip_top_dir:
        return extracted
    entries = [e for e in os.listdir(extracted) if not e.startswith(".")]
    if len(entries) == 1 and os.path.isdir(os.path.join(extracted, entries[0])):
        return os.path.join(extracted, entries[0])
    return extracted


def copy_tree(src, dst):
    os.makedirs(dst, exist_ok=True)
    for root, _dirs, files in os.walk(src):
        rel = os.path.relpath(root, src)
        target = dst if rel == "." else os.path.join(dst, rel)
        os.makedirs(target, exist_ok=True)
        for fn in files:
            shutil.copy2(os.path.join(root, fn), os.path.join(target, fn))


def collect_licenses(src_root, globs, license_dir, engine_id):
    os.makedirs(license_dir, exist_ok=True)
    found = []
    for pattern in globs:
        for path in glob.glob(os.path.join(src_root, pattern)):
            if os.path.isfile(path):
                base = os.path.basename(path)
                shutil.copy2(path, os.path.join(license_dir, f"{engine_id}-{base}"))
                found.append(base)
    return found


def do_print_hashes(lock, only):
    print("# Paste these into tools/engines.lock.json (sha256 fields):")
    rc = 0
    for e in lock["engines"]:
        if only and e["id"] not in only:
            continue
        with tempfile.TemporaryDirectory() as td:
            arc = os.path.join(td, "dl")
            try:
                download(e["url"], arc)
            except Exception as ex:  # noqa: BLE001
                print(f"  {e['id']:<10} DOWNLOAD FAILED: {ex}", file=sys.stderr)
                rc = 1
                continue
            print(f"  {e['id']:<10} {sha256_file(arc)}  ({e['url']})")
    return rc


def do_bundle(lock, dest, only):
    licenses_dir = os.path.join(dest, "LICENSES")
    bundled = []
    for e in lock["engines"]:
        if only and e["id"] not in only:
            continue
        want = normalized_sha256(e)
        if want is None:
            print(f"ERROR: {e['id']} has no valid sha256 in engines.lock.json; refusing to "
                  f"bundle an unverified binary. Run --print-hashes and commit the digest.",
                  file=sys.stderr)
            return 2
        with tempfile.TemporaryDirectory() as td:
            arc = os.path.join(td, "dl")
            download(e["url"], arc)
            got = sha256_file(arc)
            if got != want:
                print(f"ERROR: {e['id']} sha256 mismatch\n  expected {want}\n  got      {got}\n"
                      f"  url {e['url']}", file=sys.stderr)
                return 3
            ex = os.path.join(td, "x")
            extract(arc, e["archive"], ex)
            root = source_root(ex, e.get("strip_top_dir", False))
            copy_tree(root, os.path.join(dest, e["dest"]))
            for extra in e.get("also_copy", []):
                frm = os.path.join(root, extra["from"])
                if os.path.isdir(frm):
                    copy_tree(frm, os.path.join(dest, extra["to"]))
            lic = collect_licenses(root, e.get("license_globs", []), licenses_dir, e["id"])
            bundled.append({"id": e["id"], "version": e["version"], "sha256": want,
                            "license": e.get("license", ""), "source": e.get("source", ""),
                            "licenseFiles": lic})
            print(f"  bundled {e['id']} {e['version']} -> {e['dest']} "
                  f"(licenses: {', '.join(lic) or 'NONE FOUND'})")

    _write_source_offer(dest, bundled)
    with open(os.path.join(dest, "LICENSES", "BUNDLED-ENGINES.json"), "w", encoding="utf-8") as f:
        json.dump({"engines": bundled}, f, indent=2)
    missing = [b["id"] for b in bundled if not b["licenseFiles"]]
    if missing:
        print(f"WARNING: no license file was found in the archive for: {', '.join(missing)}. "
              f"Add it to LICENSES/ manually before publishing.", file=sys.stderr)
    return 0


def _write_source_offer(dest, bundled):
    lines = [
        "# Written offer for source code (bundled third-party tools)",
        "",
        "This CaseKey release bundles the recovery engines listed below. Each is",
        "redistributed under its own license (see the LICENSES/ directory). For the",
        "components licensed under the GPL, the complete corresponding source for the",
        "exact version bundled is publicly available at the URL given, and is offered",
        "on request for as long as this release is distributed.",
        "",
    ]
    for b in bundled:
        lines += [f"- **{b['id']} {b['version']}** — {b['license']}",
                  f"  - source: {b['source']}",
                  f"  - sha256 (downloaded archive): `{b['sha256']}`"]
    lines.append("")
    with open(os.path.join(dest, "SOURCE_OFFER.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main():
    ap = argparse.ArgumentParser(description="Assemble CaseKey's bundled recovery engines.")
    ap.add_argument("--dest", help="bundle root directory to populate")
    ap.add_argument("--print-hashes", action="store_true",
                    help="download each source and print its sha256, then exit")
    ap.add_argument("--check", action="store_true",
                    help="verify the lockfile is bootstrapped (valid sha256 for every engine) "
                         "without downloading, then exit")
    ap.add_argument("--only", nargs="*", default=None,
                    help="restrict to these engine ids (default: all)")
    args = ap.parse_args()

    lock = load_lock()
    only = set(args.only) if args.only else None

    if args.check:
        return do_check(lock, only)
    if args.print_hashes:
        return do_print_hashes(lock, only)
    if not args.dest:
        ap.error("--dest is required unless --print-hashes is given")
    os.makedirs(args.dest, exist_ok=True)
    return do_bundle(lock, args.dest, only)


if __name__ == "__main__":
    sys.exit(main())
