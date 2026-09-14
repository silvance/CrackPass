# Third-party components and licenses

CaseKey orchestrates established open-source tools. This inventory lists every
third-party component the application links against or drives, and its license.
Nothing here requires network access or a commercial license to run.

> CaseKey itself is licensed **GPL-3.0-or-later** (see `LICENSE`).

## Linked into the application

| Component | Version | License | Notes |
| --- | --- | --- | --- |
| **Qt 6** (Core, Gui, Widgets, Concurrent, Test) | 6.x | LGPL-3.0 (open-source edition) | Dynamically linked; runtime bundled via `windeployqt6`. Relinkable per LGPL §4. |
| **UCRT / MSVC or MinGW-w64 runtime** | platform | MS UCRT redistributable / GCC Runtime Library Exception | Provided by the Windows toolchain used to build the release. |

## Driven as external tools (not linked; invoked as separate processes)

| Component | Purpose | License | Notes |
| --- | --- | --- | --- |
| **hashcat** | Primary cracking engine | MIT | Invoked with `--status-json`. Supplied by the examiner in the lean build; **bundled** in the full release bundle. |
| **John the Ripper Jumbo** (`john`) | Second cracking engine | GPL-2.0-or-later (with OpenSSL/other permissive parts) | The resolved binary + version is recorded on each job. Supplied by the examiner in the lean build; **bundled** in the full release bundle. |
| **John the Ripper Jumbo** — `office2john`, `pdf2john`, `zip2john`, `rar2john`, `7z2john`, `keepass2john`, `bitlocker2john` | Hash extraction from encrypted files/containers | GPL-2.0-or-later (with OpenSSL/other permissive parts) | Each extraction records the exact tool + version used. Bundled with `john` in the full bundle (the Python scripts run against the bundled embeddable Python). |
| **bkcrack** | ZipCrypto known-plaintext cryptanalysis (legacy ZIP only) | zlib | Used only for traditional PKWARE ZipCrypto, never AES ZIPs. Supplied by the examiner in the lean build; **bundled** in the full release bundle. |
| **Python (embeddable)** | Interpreter for the John `*2john` extraction scripts | PSF-2.0 | Bundled in the full release bundle only, under `runtime/python/`; not linked into CaseKey. |

### Bundled versions and provenance (full release bundle)

The full bundle (`release-bundle.yml`) redistributes the tools above. The exact
pinned versions and download URLs are in `tools/engines.lock.json`; each is
verified by SHA-256 at build time (fail-closed) and the digest is recorded in the
bundle's `LICENSES/BUNDLED-ENGINES.json`. Each tool's own license text is
collected into the bundle's `LICENSES/` directory, and `SOURCE_OFFER.md` provides
the written offer of corresponding source for the GPL component (John the
Ripper), pointing at the exact upstream source tag. Bumping a bundled version
means updating `engines.lock.json` (URL + version + re-locked SHA-256) and this
table.

## Wordlists / dictionaries

CaseKey ships a **manifest** of built-in dictionaries (`resources/dictionaries/manifest.json`)
but does **not** commit the wordlist files themselves; they are supplied
separately for a deployment (see `resources/dictionaries/README.md`). The
manifest and each library entry record the `source` and `license` of every
wordlist so a recovery report can cite exactly which dictionary was used.

| Dictionary | Origin | License / attribution | Notes |
| --- | --- | --- | --- |
| **CaseKey Common** (`casekey-common`) | Curated by CaseKey contributors from openly redistributable sources | GPL-3.0-or-later | General-purpose default for the Dictionary attack. File supplied separately; never fabricated. |
| **CaseKey Quick** (`casekey-quick`) | Curated by CaseKey contributors from openly redistributable sources | GPL-3.0-or-later | Small quick-triage list. File supplied separately; never fabricated. |
| *Imported wordlists* | Added by the examiner at runtime | As recorded by the examiner on import | CaseKey stores the examiner-supplied source/license alongside the entry. |

**Licensing policy for wordlists.** CaseKey does not bundle or redistribute
proprietary wordlists (for example, Passware dictionaries) or breach-derived
corpora that lack a documented redistribution basis. Any wordlist added to a
distribution must have its source and license recorded here and in the
manifest. Examiner-imported wordlists carry whatever provenance the examiner
records; that provenance travels with the job and report.

## GPU / compute runtimes (provided by the platform/driver)

| Component | Purpose | License | Notes |
| --- | --- | --- | --- |
| **NVIDIA CUDA runtime / driver** | GPU acceleration for hashcat on NVIDIA hardware | NVIDIA proprietary EULA | Installed with the GPU driver on the workstation; not shipped by CaseKey. |
| **OpenCL ICD** | Alternate compute backend for hashcat | Vendor-specific | Provided by the GPU vendor's driver. |

## License-compatibility notes

- CaseKey links Qt under the **LGPL**; the release ships Qt as separate DLLs so
  the library remains replaceable, satisfying LGPL relinking requirements.
- hashcat and the JtR Jumbo utilities are invoked as **separate processes** over a
  command-line boundary. They are not linked into the CaseKey binary, so their
  licenses (MIT, GPL-2.0) apply to those tools independently and do not impose
  additional obligations on CaseKey's own GPL-3.0 code beyond shipping their
  licenses if you choose to bundle the binaries.
- The **full release bundle** does bundle these engines. That is handled
  automatically: `tools/fetch_engines.py` collects each tool's own
  `LICENSE`/`COPYING` into the bundle's `LICENSES/` directory and writes
  `SOURCE_OFFER.md` (the GPL written offer, with the exact upstream source tag for
  John the Ripper). Because the engines are separate processes over a command-line
  boundary — not linked into CaseKey — their licenses (MIT, GPL-2.0-or-later,
  zlib, PSF) apply to those tools independently and impose no additional
  obligation on CaseKey's own GPL-3.0 code beyond shipping those licenses and,
  for the GPL tool, the source offer.

## How versions are captured at runtime

Every extraction record stores the resolved extractor program and its version
(when the tool reports one). Every recovery report records the hashcat version and
detected compute devices, so a report is self-describing about the exact toolchain
that produced a result.
