#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: CaseKey contributors
#
# Release-time sanity check for a packaged CaseKey `dictionaries/` directory.
#
# CaseKey resolves its built-in wordlists from <appDir>/dictionaries/manifest.json.
# The manifest DECLARES the built-in dictionaries; the wordlist data itself is
# supplied separately (repository policy keeps password data out of source
# control -- see resources/dictionaries/README.md). This script keeps a release
# honest about what it actually ships:
#
#   * the manifest must be present and parseable;
#   * every entry marked  "required": true  must have its wordlist file present
#     and non-empty (a release that PROMISES a built-in must actually carry it);
#   * entries not marked required may be absent -- CaseKey lists them as
#     "file not supplied" and never fabricates candidates.
#
# It never inspects or prints wordlist contents. Exit status is non-zero when a
# required file is missing, so packaging fails loudly instead of shipping a
# dictionary that is declared present but is not.
#
# Usage:  python3 tools/check_release_dictionaries.py <dictionaries-dir>

import json
import os
import sys


def main(dictdir):
    manifest = os.path.join(dictdir, "manifest.json")
    if not os.path.isfile(manifest):
        print(f"ERROR: no manifest at {manifest}", file=sys.stderr)
        return 2
    try:
        with open(manifest, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        print(f"ERROR: cannot parse {manifest}: {e}", file=sys.stderr)
        return 2

    entries = data.get("dictionaries", [])
    missing_required = []
    present, declared = [], []
    for e in entries:
        name = e.get("path", "")
        eid = e.get("id", "(no id)")
        declared.append(eid)
        if not name:
            continue
        path = os.path.join(dictdir, name)
        has = os.path.isfile(path) and os.path.getsize(path) > 0
        if has:
            present.append(eid)
        elif e.get("required", False):
            missing_required.append((eid, name))

    print(f"manifest: {manifest}")
    print(f"  declared:        {', '.join(declared) or '(none)'}")
    print(f"  files present:   {', '.join(present) or '(none)'}")
    if missing_required:
        print("  MISSING (required):")
        for eid, name in missing_required:
            print(f"    - {eid} -> {name}")
        print("\nERROR: a release declares the above built-in dictionaries as "
              "required, but their files were not provisioned. Supply them (see "
              "resources/dictionaries/README.md) or clear their \"required\" flag.",
              file=sys.stderr)
        return 1
    print("OK: manifest present and all required wordlist files supplied.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: check_release_dictionaries.py <dictionaries-dir>", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
