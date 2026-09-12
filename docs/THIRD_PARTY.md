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
| **hashcat** | Cracking engine | MIT | Path configured by the examiner; invoked with `--status-json`. Not redistributed by CaseKey by default. |
| **John the Ripper Jumbo** — `office2john`, `pdf2john`, `zip2john`, `rar2john`, `7z2john`, `keepass2john` | Hash extraction from encrypted files/containers | GPL-2.0-or-later (with OpenSSL/other permissive parts) | Supplied on the workstation; each extraction records the exact tool + version used. |

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
- If you **bundle** hashcat, JtR, rule files or wordlists into a distribution,
  include each project's own `LICENSE`/`COPYING` in `tools/<component>/` and list
  the exact versions here.

## How versions are captured at runtime

Every extraction record stores the resolved extractor program and its version
(when the tool reports one). Every recovery report records the hashcat version and
detected compute devices, so a report is self-describing about the exact toolchain
that produced a result.
