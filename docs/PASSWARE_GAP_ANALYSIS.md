# Gap analysis: CaseKey vs. Passware Kit Forensic

This assesses what CaseKey would still be missing compared with a mature
commercial suite such as Passware Kit Forensic, grouped by the effort/feasibility
of closing each gap. It reflects the architecture built so far (case workspace +
evidence intake with SHA-256/metadata + content-based type detection + `*2john`
hash extraction for Office/PDF/ZIP/RAR/7-Zip/KeePass + a guided attack planner +
an attached, `--status-json`-driven job queue + recovered-credential capture +
HTML/JSON reporting), all running fully offline.

## What CaseKey already matches
Dictionary / rules / mask / hybrid / brute-force attacks (via hashcat, GPU
accelerated); case-centric evidence handling with integrity hashing and a
tamper-evident audit trail; content-based format detection; hash extraction for an
initial set of encrypted formats; guided, transparent attack planning; live job
monitoring with pause/resume/stop; per-attempt forensic reports. These are core to
Passware's dictionary/mask workflows and are present here.

---

## Easy
Incremental work well within the current architecture (registries + planner +
report already provide the extension points).

- **More extractor formats** — additional `*2john`/`*2hashcat` adapters
  (documents, more archives, disk-image headers, macOS keychains, PDFs of every
  revision). The `ExtractorRegistry` already supports drop-in adapters.
- **PDF report export** — add `QPrinter`/`QPdfWriter` output alongside HTML/JSON.
- **Device selection & hashcat version capture** — surface `--backend-info` /
  `--version` in the UI and record devices on each job (models already carry the
  fields).
- **Batch enqueue** — plan+queue across many artifacts at once.
- **Potfile reuse** — recognize already-recovered hashes and skip work.
- **Bundled rule-library management** in the UI. (Managed *dictionary/wordlist*
  library management is **implemented** — a manifest-driven built-in library plus
  imported entries with SHA-256/candidate-count provenance and drift detection,
  managed under Settings → Dictionaries; rule-file library management is the
  remaining piece.)

## Moderate
Real engineering, but using established, documented techniques.

- **Broad automatic encryption/type identification** across hundreds of formats
  (Passware advertises ~340). Requires a large, maintained signature/structural
  detection library rather than the current focused table.
- **Full-disk / container encryption end-to-end** — BitLocker
  extraction + attack is **supported** (`bitlocker2john` → `-m 22100`); still
  open here and for VeraCrypt/TrueCrypt (137xx) and LUKS (14600 / 29xxx) is the
  rest of the chain: their extraction plus mounting/decrypting the recovered
  volume once the password is known.
- **Distributed / multi-node cracking** — coordinate multiple GPUs/hosts on an
  isolated LAN (hashcat brain, or a custom agent), analogous to Passware Agent but
  offline. (Cloud bursting is intentionally out of scope.)
- **Automated strategy escalation** — the planner materializes explicit
  attacks today; auto-sequencing and adaptive tuning is a natural extension.

## Difficult
Substantial engineering; approaches are known but complex and format-specific.

- **Memory-image key extraction** — recovering encryption keys from RAM captures,
  `hiberfil.sys`, or `pagefile.sys` for near-instant decryption of BitLocker /
  FileVault2 / TrueCrypt volumes. Needs Volatility-class memory forensics plus
  key-schedule scanning.
- **Mobile acquisition & backup decryption** — iOS/Android, iTunes backups,
  keychains: format-specific KDFs and platform constraints.
- **"Instant" recovery via escrow/recovery keys** — BitLocker recovery keys from
  Active Directory, FileVault institutional/personal recovery keys, etc.
- **Password-manager vault decryption** at breadth.

## Requires substantial reverse engineering / development
Feasibility is uncertain or gated by external factors.

- **Proprietary/undocumented or DRM-protected formats**, and brand-new
  Office/PDF variants for which no open extractor yet exists.
- **TPM-bound / hardware-sealed keys** — BitLocker sealed to a TPM, Apple Secure
  Enclave, security keys: often infeasible without the hardware present or a memory
  capture taken while unlocked.
- **Online/token-based recovery flows** — inherently require connectivity and are
  deliberately out of scope for an air-gapped tool.

## Commercial / proprietary ecosystem advantage
Gaps that are less about code and more about a sustained commercial operation.

- **Breadth + maintenance** — 340+ continuously updated format modules that track
  changing file formats; a small open project cannot match that cadence alone.
- **Curated, licensed content** — professional wordlists, attack profiles, and
  vendor support/SLAs.
- **Forensic validation & courtroom standing** — independent certification,
  reproducibility validated at scale, and expert testimony.
- **Turn-key infrastructure** — integrated distributed cracking and cloud bursting
  (AWS), plus a single-vendor acquisition-to-recovery suite (memory/mobile/disk
  imagers).
- **QA matrix** — validation across a vast device/format/OS combination space.

---

## Summary
CaseKey credibly covers the **dictionary/rules/mask/hybrid + GPU** workflow with
strong forensic hygiene (integrity, audit, reproducible reports) entirely offline.
The largest real differentiators of a commercial suite are **memory-based instant
decryption**, **full-disk/mobile coverage**, **breadth of maintained format
modules**, and the surrounding **commercial ecosystem** (validation, support,
distributed infrastructure) — roughly in increasing order of difficulty to close.
