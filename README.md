# CaseKey

CaseKey is an **offline, examiner-friendly password-recovery application for
authorized digital-forensics work**. It provides a case-centric forensic
workflow — evidence intake with integrity hashing, hash extraction from
encrypted files/containers, guided attack planning, monitored cracking, a
tamper-evident audit trail, and examiner reports — on top of established
engines: [**hashcat**](https://github.com/hashcat/hashcat/) for cracking and the
**John the Ripper Jumbo** `*2john` utilities for hash extraction.

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

## Two workflows

- **Forensic / Guided Mode** — create/open a case, add an artifact (referenced
  or imported as an immutable working copy), detect its type, extract a hash,
  plan an attack from case knowledge, run and monitor it, and produce a report.
- **Advanced Mode** — the original hashcat-gui, unchanged, for full
  manual control. Nothing about hashcat is hidden; the guided mode always shows
  the exact hashcat command before anything runs.

## Status & scope

- Supported extraction formats (initial set): Microsoft Office, PDF, ZIP, RAR,
  7-Zip, KeePass.
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

Use **Forensic Mode → Settings** to set the hashcat path, each extraction tool,
a common-passwords wordlist, a rules directory and the default case location —
no hidden configuration files. **Forensic Mode → Tool Status** ("Dependency
Doctor") shows what was detected, versions, GPU/backend information and a
hashcat self-test.

CaseKey also auto-discovers a bundled **portable layout** next to the
executable, with manual overrides always available:

```
CaseKey/
  CaseKey(.exe)
  tools/
    hashcat/     # hashcat + backends
    john/        # John the Ripper Jumbo *2john utilities
    rules/       # default hashcat rules
    wordlists/   # approved wordlists
```

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
