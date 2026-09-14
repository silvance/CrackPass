# Bundled dictionaries

This directory holds the **manifest** for CaseKey's built-in wordlists
(`manifest.json`). It declares the built-in dictionaries the app offers for a
Dictionary attack. It intentionally contains **no password data** — only
metadata (id, display name, description, source, license, and integrity
fields).

## Supplying the wordlist files

The built-in wordlist files themselves are **supplied separately** and are not
committed to this repository. Each entry in `manifest.json` names the file it
expects (its `path`, resolved relative to this directory), for example
`casekey-common.txt`.

- When a wordlist file is present, CaseKey resolves it, and (via the Dictionary
  Manager) can compute its SHA-256 and candidate count.
- When a wordlist file is **absent**, CaseKey still lists the entry but marks it
  as "file not supplied" and will not run an attack against a file that does not
  exist. The application **never fabricates** candidate data to fill the gap,
  and the build and test suite do not depend on these files being present.

To provision a deployment, drop the wordlist file next to this manifest under
the name its entry declares, then use **Settings → Dictionaries** to validate
it (record its SHA-256 and candidate count).

## Licensing

CaseKey does **not** bundle proprietary wordlists (e.g. Passware dictionaries)
or breach-derived corpora that lack a documented redistribution basis. The
built-in lists are curated by CaseKey contributors from openly redistributable
sources. Per-source attribution and license obligations for any bundled or
recommended wordlist are recorded in
[`../../docs/THIRD_PARTY.md`](../../docs/THIRD_PARTY.md) and mirrored in each
entry's `source` / `license` fields.

Imported wordlists that an examiner adds at runtime carry whatever
source/license the examiner records for them; CaseKey stores that provenance
alongside the entry so reports can cite it.
