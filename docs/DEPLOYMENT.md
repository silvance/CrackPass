# CaseKey — Deployment on a disconnected Windows forensic workstation

CaseKey is designed to run **fully offline** on an examiner workstation. It has
**no cloud dependencies**: no telemetry, no update checks, no network calls. All
compute happens locally on the workstation's CPU/GPU. This document describes how
to locate, bundle and configure the third-party components CaseKey drives.

> CaseKey is an orchestration GUI. It does **not** ship or replace hashcat or
> John the Ripper. On a licensed forensic workstation the examiner supplies those
> engines; CaseKey locates or bundles them and records exactly what it used.

## 1. Components to provide

| Component | Purpose | How CaseKey finds it |
| --- | --- | --- |
| **hashcat** (v7.x) | The cracking engine | Path configured in Settings (`hashcatPath`); invoked attached with `--status-json` |
| **John the Ripper Jumbo** `*2john` utilities | Hash extraction from encrypted files/containers | Per-tool path configured under settings keys `tools/<id>` (`office2john`, `pdf2john`, `zip2john`, `rar2john`, `7z2john`, `keepass2john`) |
| **Runtime libraries** | Qt 6 + UCRT runtime for the GUI itself | Bundled next to `casekey.exe` by `windeployqt6` (see the release workflow) |
| **Default rules** | Rule files for the "Wordlist + Rules" template | Bundled read-only under `tools/rules/` (e.g. hashcat's `rules/best64.rule`) |
| **Approved wordlists** | Dictionaries for dictionary/hybrid attacks | Placed on the workstation; selected per-plan, or set a default `commonWordlist` path |

## 2. Recommended on-disk layout

A self-contained, portable install directory (nothing is written outside it except
case folders the examiner chooses):

```
CaseKey\
  casekey.exe
  Qt6*.dll, platforms\, styles\   # from windeployqt6
  ucrt\ or vc_redist runtime       # UCRT dependencies
  tools\
    hashcat\hashcat.exe
    hashcat\OpenCL\ , modules\ , kernels\
    john\run\*2john(.exe|.pl|.py)  # JtR Jumbo extraction utilities
    rules\best64.rule , dive.rule , ...
  wordlists\
    <approved wordlists>.txt        # provided per policy; not shipped by CaseKey
  docs\
    README.md CHANGELOG.md FAQ.md LICENSE THIRD_PARTY.md
```

`*2john` utilities that are Python/Perl scripts require the matching interpreter.
The `ToolResolver` model supports a resolved `{program, prefixArgs}` invocation, so
a script can be configured as `program = python.exe`, `prefixArgs = [office2john.py]`.
Prefer the compiled JtR Jumbo builds where available to avoid an interpreter
dependency on the disconnected workstation.

## 3. First-run configuration (offline)

1. Launch `casekey.exe` and choose **Advanced Mode → Settings** to set
   the **hashcat** path.
2. Set each extractor tool path (settings keys `tools/<id>`). CaseKey records the
   resolved program and, where available, its version into every extraction record.
3. (Optional) Set a default common-passwords wordlist path and point the planner at
   your approved wordlists / bundled rules.
4. Add an exclusion in the endpoint AV for the hashcat process if extraction/hash
   enumeration is slow (see `FAQ.md`).

## 4. Case storage

Each case is a self-contained folder (see the case scaffold: `case.json`,
`evidence/`, `extractions/`, `jobs/`, `results/`, `reports/`, `logs/`). It contains
no absolute dependencies on the install location and can be copied to evidence
storage. Original evidence is **referenced, never copied or modified**; only its
SHA-256 and metadata are recorded.

## 5. Windows release build

The repository's `.github/workflows/build-release.yml` produces the Windows binary
via MSYS2 UCRT64 + `windeployqt6` and bundles the Qt runtime and docs. For a
disconnected deployment, add the `tools/` and `wordlists/` trees above to the
release directory before transferring it to the workstation. No step in the build
or run path requires Internet access on the target.
