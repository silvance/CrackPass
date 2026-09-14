# CaseKey

CaseKey is an **offline, examiner-friendly password-recovery application for
authorized digital-forensics work**. It provides a case-centric forensic
workflow — evidence intake with integrity hashing, hash extraction from
encrypted files/containers, a one-click **Recover Password** workflow, monitored
recovery, a tamper-evident audit trail, and examiner reports — on top of
established engines: [**hashcat**](https://github.com/hashcat/hashcat/) and
**John the Ripper** for cracking, [**bkcrack**](https://github.com/kimci86/bkcrack)
for legacy ZipCrypto known-plaintext recovery, and the **John the Ripper Jumbo**
`*2john` utilities for hash extraction. CaseKey chooses the appropriate engine
automatically and records exactly which one ran.

CaseKey runs fully offline with **no cloud dependencies**.

## Built on hashcat-gui

CaseKey began as, and still contains, a fork of the excellent
[**hashcat-gui** by Rainer Größlinger (`rgroesslinger/hashcat-gui`)](https://github.com/rgroesslinger/hashcat-gui).
That project is preserved intact as **Advanced Mode** — the full
low-level hashcat interface — and CaseKey adds a **Forensic / Guided Mode**
alongside it. The fork stays close to upstream so improvements there can be
merged in; the forensic layer lives in new modules (`src/forensic/`) rather than
rewrites of the original UI.

Full credit for the underlying GUI goes to the upstream project and its authors.

## The default workflow, in five steps

Forensic Mode leads with one primary action — **Recover Password** — that keeps
implementation detail out of the way until you ask for it:

1. **New / Open Case.**
2. **Add Artifact** — reference the original in place, or import a verified
   working copy (your choice; the original is never modified by CaseKey).
3. **Recover Password** — CaseKey extracts the hash if needed, then offers a
   strategy: **Dictionary** (the recommended default; needs nothing known about
   the case), **Pattern** (a mask), or **Guided / advanced** (case knowledge and
   every attack template).
4. Keep the default **Dictionary → CaseKey Common** and click **Start** — the
   engine is chosen automatically (hashcat unless it cannot express the attack).
5. Watch the job and read the result in **Results**; generate a report.

Technical detail is one click away, never removed: an **Advanced details** panel
in the recovery dialog shows the hash type, chosen engine and the exact command,
and an **Advanced** menu holds manual Extract Hash / Plan Attack and specialized
recovery (ZipCrypto/bkcrack).

## Two modes

- **Forensic / Guided Mode** — the case-centric workflow above.
- **Advanced Mode** — the original hashcat-gui, unchanged, for full manual
  control. Nothing about hashcat is hidden; the guided mode always shows the
  exact engine command before anything runs.

## Managed dictionary library

Dictionary attacks draw on a managed wordlist library. CaseKey ships a manifest
of built-in lists (**CaseKey Common**, the default, and **CaseKey Quick**) whose
files are supplied per deployment, and the examiner can import their own via
**Advanced → Dictionaries** (copying the file into the library or referencing it
in place). Each wordlist's source, license, SHA-256 and candidate count are
recorded; a job and its report name exactly which dictionary ran, and a recovery
is refused if the wordlist's SHA-256 no longer matches what was recorded. CaseKey
bundles no proprietary or breach-derived wordlists (see
[`docs/THIRD_PARTY.md`](docs/THIRD_PARTY.md)).

## Status & scope

- Supported extraction formats: Microsoft Office, PDF, ZIP, RAR, 7-Zip, KeePass,
  and BitLocker volumes (via `bitlocker2john`, hashcat mode 22100).
- ✅ Compatible with hashcat v7.x.
- CaseKey orchestrates external tools; it does **not** bundle or replace
  hashcat or John the Ripper. See `docs/DEPLOYMENT.md` for how to provide them.

## Documentation

- [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) — deploying on a disconnected Windows
  forensic workstation; locating/bundling hashcat, the `*2john` tools, runtime
  libraries, rules and wordlists.
- [`docs/FORENSIC_VALIDATION.md`](docs/FORENSIC_VALIDATION.md) — the correctness
  and integrity invariants CaseKey enforces.
- [`docs/INTEGRATION_TESTING.md`](docs/INTEGRATION_TESTING.md) — the optional
  real-tool integration tests and diagnostic runner.
- [`docs/THIRD_PARTY.md`](docs/THIRD_PARTY.md) — third-party components and their
  licenses.
- [`docs/PASSWARE_GAP_ANALYSIS.md`](docs/PASSWARE_GAP_ANALYSIS.md) — capability
  comparison with Passware Kit Forensic.

## Configuring tools (offline)

Use **Forensic Mode → Settings** to set the hashcat, John the Ripper and bkcrack
paths, each extraction tool, a rules directory and the default case location — no
hidden configuration files. Wordlists are managed under **Advanced →
Dictionaries** rather than a single path. **Forensic Mode → Tool Status**
("Dependency Doctor") shows what was detected, versions, GPU/backend information
and a hashcat self-test.

CaseKey also auto-discovers a bundled **portable layout** next to the
executable, with manual overrides always available:

```
CaseKey/
  CaseKey(.exe)
  tools/
    hashcat/     # hashcat + backends
    john/        # John the Ripper Jumbo *2john utilities
    john/        # John the Ripper (optional second cracking engine)
    bkcrack/     # bkcrack (optional ZipCrypto known-plaintext engine)
    rules/       # default hashcat rules
    dictionaries/# manifest + built-in wordlist files
```

## Case records & compatibility

Case records (jobs, results, reports) are engine-neutral: a job records its
`engineId` ("hashcat"/"john"/"bkcrack"), the exact argv, the resolved executable
and its version, and — for a Dictionary attack — the dictionary's id, name,
SHA-256 and candidate count. Records written by earlier versions still load:
the pre-rename hashcat-only field names (`hashcatArgs`/`hashcatPath`/
`hashcatVersion`) are read as a fallback and a missing `engineId` is treated as
hashcat, so older cases open with full provenance. See
[`docs/FORENSIC_VALIDATION.md`](docs/FORENSIC_VALIDATION.md).

## Build from source

Requires CMake ≥ 3.24 and Qt 6 (Core, Gui, Widgets, Concurrent, Test).

### Linux
| Distribution | Dependencies |
| - | - |
| Debian/Ubuntu | `apt install build-essential cmake qt6-base-dev` |
| Fedora | `dnf install gcc-c++ cmake qt6-qtbase-devel` |
| openSUSE | `zypper install gcc-c++ cmake qt6-base-devel` |
| Arch | `pacman -S --needed gcc cmake qt6-base` |

```
cmake -B build
cmake --build build
ctest --test-dir build        # unit tests (offline; real-tool tests skip cleanly)
```

### Windows
Install [MSYS2](https://www.msys2.org/), launch the `MSYS2 UCRT64` terminal, then:
```
pacman -S mingw-w64-ucrt-x86_64-{gcc,cmake,qt6-base}
cmake -B build
cmake --build build
```

## License

CaseKey is licensed **GPL-3.0-or-later** (see [`LICENSE`](LICENSE)), consistent
with the upstream hashcat-gui project. Third-party components and their licenses
are inventoried in [`docs/THIRD_PARTY.md`](docs/THIRD_PARTY.md). hashcat and the
John the Ripper Jumbo utilities are separate projects with their own licenses and
are not redistributed by CaseKey by default.
