# CaseKey — Deployment on a disconnected Windows forensic workstation

CaseKey is designed to run **fully offline** on an examiner workstation. It has
**no cloud dependencies**: no telemetry, no update checks, no network calls. All
compute happens locally on the workstation's CPU/GPU. This document describes how
to locate, bundle and configure the third-party components CaseKey drives.

> CaseKey is an orchestration GUI. It does **not** ship or replace hashcat or
> John the Ripper. On a licensed forensic workstation the examiner supplies those
> engines; CaseKey locates or bundles them and records exactly what it used.

## 1. Components to provide

CaseKey resolves each engine through a single authority (`ToolchainService`),
which the **Dependency Doctor** (Advanced → Dependency Doctor) reports on. For
every engine the resolution order is the same:

1. an explicit **settings** path (`hashcatPath` / `johnPath` / `bkcrackPath`);
2. a **portable** layout beside the binary (`tools/hashcat/`, `tools/john/run/`,
   `tools/bkcrack/`);
3. the system **PATH**.

The same service records the resolved path, version banner and (best-effort)
SHA-256 of the executable onto every job for provenance.

| Component | Purpose | How CaseKey finds it |
| --- | --- | --- |
| **hashcat** (v7.x) | Primary cracking engine | `hashcatPath` → portable `tools/hashcat/` → PATH; invoked attached with `--status-json` |
| **John the Ripper Jumbo** (engine) | Second cracking engine (auto-detects the hash format) | `johnPath` → portable `tools/john/run/` → PATH |
| **bkcrack** | ZipCrypto known-plaintext cryptanalysis (legacy ZIP only) | `bkcrackPath` → portable `tools/bkcrack/` → PATH |
| **John the Ripper Jumbo** `*2john` utilities | Hash extraction from encrypted files/containers | Per-tool path under settings keys `tools/<id>` (`office2john`, `pdf2john`, `zip2john`, `rar2john`, `7z2john`, `keepass2john`, `bitlocker2john`) |
| **Runtime libraries** | Qt 6 + UCRT runtime for the GUI itself | Bundled next to `casekey.exe` by `windeployqt6` (see the release workflow) |
| **Managed dictionaries** | The normal Dictionary attack source (e.g. CaseKey Common) | Manifest at `<appDir>/dictionaries/manifest.json` (packaged by the release workflow); managed via Settings → Dictionaries |
| **Default rules** | Rule files for the "Wordlist + Rules" template | Bundled read-only under `tools/rules/` (e.g. hashcat's `rules/best64.rule`) |
| **Approved wordlists** (legacy/advanced) | An arbitrary external wordlist for the Advanced planner | Optional `commonWordlist` default path — legacy/advanced only; the managed dictionary library is the normal source |

## 2. Recommended on-disk layout

A self-contained, portable install directory (nothing is written outside it except
case folders the examiner chooses):

```
CaseKey\
  casekey.exe
  Qt6*.dll, platforms\, styles\   # from windeployqt6
  ucrt\ or vc_redist runtime       # UCRT dependencies
  dictionaries\
    manifest.json                   # managed dictionary library (packaged)
    casekey-common.txt, casekey-quick.txt  # supplied per policy (see below)
  tools\
    hashcat\hashcat.exe
    hashcat\OpenCL\ , modules\ , kernels\
    john\run\john.exe               # JtR Jumbo cracking engine
    john\run\*2john(.exe|.pl|.py)   # JtR Jumbo extraction utilities (incl. bitlocker2john)
    bkcrack\bkcrack.exe             # ZipCrypto known-plaintext (optional)
    rules\best64.rule , dive.rule , ...
  wordlists\
    <approved wordlists>.txt        # optional, for the Advanced planner only
  docs\
    README.md CHANGELOG.md FAQ.md LICENSE THIRD_PARTY.md
```

The `dictionaries\` directory is the normal Dictionary attack source and is
packaged next to the binary by the release workflow. The wordlist data itself is
supplied per policy (repository policy keeps password data out of source control
— see `resources/dictionaries/README.md`); when a file is absent CaseKey lists
the entry as "file not supplied" and never fabricates candidates.

`*2john` utilities that are Python/Perl scripts require the matching interpreter.
The `ToolResolver` model supports a resolved `{program, prefixArgs}` invocation, so
a script can be configured as `program = python.exe`, `prefixArgs = [office2john.py]`.
Prefer the compiled JtR Jumbo builds where available to avoid an interpreter
dependency on the disconnected workstation.

## 3. First-run configuration (offline)

1. Launch `casekey.exe`. Set the engine paths (or rely on the portable/PATH
   resolution above): **hashcat** (`hashcatPath`), and optionally **John**
   (`johnPath`) and **bkcrack** (`bkcrackPath`).
2. Set each extractor tool path (settings keys `tools/<id>`). CaseKey records the
   resolved program and, where available, its version into every extraction record.
3. Open **Advanced → Dependency Doctor** to confirm every engine and extractor
   resolves, with versions and SHA-256s, before working a case.
4. Manage the dictionary library under **Settings → Dictionaries**: validate a
   built-in (record its SHA-256 + candidate count) or import an examiner wordlist
   with its source/license. This is the normal Dictionary attack source; the
   legacy `commonWordlist` default only prefills the Advanced planner.
5. Add an exclusion in the endpoint AV for the hashcat process if extraction/hash
   enumeration is slow (see `FAQ.md`).

The normal end-to-end path is the **Recover Password** workflow: add an artifact,
Recover Password (auto-extracts the hash), pick **Dictionary → CaseKey Common**,
Start; the engine is chosen automatically. BitLocker rides the same path via
`bitlocker2john` (hashcat `-m 22100`); legacy ZipCrypto ZIPs can use the
ZipCrypto (bkcrack) action under Advanced.

## 4. Case storage

Each case is a self-contained folder (see the case scaffold: `case.json`,
`evidence/`, `extractions/`, `jobs/`, `results/`, `reports/`, `logs/`). It contains
no absolute dependencies on the install location and can be copied to evidence
storage. CaseKey **never modifies the original artifact**. Each artifact is added
in one of two storage modes (the examiner's choice at intake):

- **Referenced** (default): the original is left in place; only its SHA-256 and
  metadata are recorded.
- **Working copy**: a verified copy is imported into `evidence/<id>/`, checked
  byte-for-byte against the source at import and used for all later reads.
  Integrity re-verification detects any later modification of the copy (it is not
  made filesystem-immutable).

Before every re-read CaseKey re-verifies the SHA-256 and fails loudly on a
mismatch (see `FORENSIC_VALIDATION.md`).

## 5. Windows release build

The repository's `.github/workflows/build-release.yml` produces the Windows binary
via MSYS2 UCRT64 + `windeployqt6`, bundles the Qt runtime and docs, and packages
the `dictionaries/` directory (the manifest plus any provisioned wordlist files;
it fails the release if a dictionary declared `required` was not provisioned). For
a disconnected deployment, add the `tools/` (and, if used, `wordlists/`) trees
above to the release directory before transferring it to the workstation. No step
in the build or run path requires Internet access on the target.
