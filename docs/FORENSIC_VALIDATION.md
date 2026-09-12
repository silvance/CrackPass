# CaseKey — Forensic validation & enforced invariants

This document records the correctness/reliability invariants CaseKey enforces
after the forensic audit. The guiding principle is that **a silent error is
worse than an explicit failure**: operations refuse to proceed rather than
continue on unverifiable state.

## 1. Evidence integrity

- The original artifact is **never modified**. It is opened read-only for
  hashing and extraction.
- A SHA-256 is computed at intake and stored on the evidence record.
- **Before any re-read** (currently: hash extraction), CaseKey recomputes the
  SHA-256 and compares it to the intake value. On mismatch or an unreadable
  artifact it **fails loudly** (no extraction) and records `integrity_mismatch`
  / `integrity_check_failed` in the audit log.
- Two storage modes are supported by the model:
  - **Referenced** (default): the original file is left in place.
  - **WorkingCopy**: an immutable copy is imported into the case
    (`evidence/<id>/source.bin`), verified byte-for-byte against the source at
    import, and used for all later reads. Deleting the original then cannot
    affect the case.
- Tests: `test_evidenceintegrity` (match, tamper-detection, extraction refusal
  on mismatch, unreadable-fails-loudly, working-copy read path).

## 2. Audit-log integrity

- The audit log is an append-only JSON-lines **hash chain** (each event hashes
  the previous head + its canonical payload).
- `AuditLog::load()` **verifies the whole chain** and returns failure on any
  tamper/truncation; `CaseWorkspace::open()` propagates that failure, so a case
  with a modified audit log **never opens as if valid**.
- `AuditLog::append()` writes and flushes the event first and only then advances
  the in-memory head. If the write fails it **reports failure and does not
  advance the chain**; `CaseWorkspace` operations surface that failure.
- Tests: `test_auditlog` (append/verify, reload, tamper→load fails,
  deletion→load fails, append-failure-does-not-advance).

## 3. Hashcat status parsing

- hashcat is driven with `--status --status-json`; **no human-readable terminal
  output is scraped**.
- stdout is reassembled with a persistent buffer (`HashcatStatusStream`): a JSON
  record split across reads is held until its terminating newline, and multiple
  records in one read are all parsed. No record is parsed half-formed or lost.
- Tests: `test_statusstream` including splitting a record at **every byte
  offset**.

## 4. Recovered credential parsing

- hashcat writes the outfile with **plaintext-only format (`--outfile-format 2`)**,
  so there is no fragile `hash:plain` split to mis-handle when a password
  contains colons or spaces.
- hashcat's `$HEX[...]` encoding (used for separators/non-printable/Unicode
  bytes) is decoded back to the literal password (UTF-8).
- The recovered credential is associated with the job's target hash (read from
  the extracted-hash file) and thereby to the artifact and case.
- Tests: `test_crackedplain` (colon, space, Unicode, literal `$`-text,
  outfile-format assertion).

## 5. Pause / stop / resume semantics

hashcat has no reliable out-of-console live "pause", so CaseKey uses hashcat's
supported **session/restore** mechanism and distinguishes:

- **Graceful stop** — `QProcess::terminate()` (SIGTERM). hashcat aborts and
  writes its `--session` restore file. State → `Stopped`.
- **Pause** — same graceful shutdown, but semantically resumable; the restore
  file is retained. State → `Paused`.
- **Forced termination** — if the process does not exit within a grace period
  (10 s) a `kill()` follows so a hung process cannot wedge the queue. No restore
  is guaranteed in this forced case.
- **Resume** — relaunch with `--session <name> --restore`, which reloads the
  original attack; CaseKey does not re-supply the attack positionals.

> Known limitation: on Windows, delivering a graceful signal to a console
> process may require a Ctrl-C/`GenerateConsoleCtrlEvent` path; until that is
> added, a Windows "stop" may fall through to the forced kill (restore not
> guaranteed). This is documented rather than hidden.

## 6. Persistence safety

- All whole-file case state (`case.json`, evidence `metadata.json`,
  `extraction.json`, `job.json`, `results/recovered.json`, reports) is written
  **atomically** via `QSaveFile` (temp file + fsync + atomic rename), so a crash
  or power loss cannot leave these half-written.
- The audit log is append-only; a torn final line from power loss is detected by
  the chain verification on next load.

## 7. Sensitive plaintext — where recovered passwords can appear

Examiner access to recovered passwords is **never removed**. Plaintext may exist
in these locations; each is documented so an examiner knows what is on disk:

| Location | Written when | Control |
| --- | --- | --- |
| `results/recovered.json` (case) | on recovery | inherent to the case record |
| hashcat **outfile** (`jobs/<id>/cracked.out`) | during a run | plaintext-only; lives in the job dir |
| hashcat **potfile** (`jobs/<id>/job.potfile`) | during a run | hashcat's own store |
| **reports** (`reports/*.html/.json`) | on report generation | **include/redact prompt** per report |
| **UI** — Results tab / Jobs "Recovered" column | while viewing | reveal/copy controls (Prompt 10) |
| **audit log** | — | plaintext is **not** written to the audit trail (only recovery metadata) |

Report generation explicitly asks whether to include or redact the plaintext;
redaction replaces it with `[REDACTED]` in both HTML and JSON while still
recording that recovery occurred. No custom cryptography is used to protect
credentials.

## 8. Tool/version provenance

- The hashcat version is probed (`hashcat --version`) and stored on each job;
  the exact hashcat executable path and full argument vector are persisted.
- Each extraction records the exact extractor program path and argv, and the
  extractor version where the tool reports one.
- Reports surface the hashcat version, devices, exact parameters and extractor
  provenance so a report is self-describing about the toolchain that produced
  the result.

## Test summary

21 unit-test suites run offline with no external tools (a fake process runner
stands in for hashcat/`*2john`). Real-tool interoperability is validated
separately by the optional integration layer.
