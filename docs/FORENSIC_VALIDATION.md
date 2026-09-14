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
  - **WorkingCopy**: a **verified working copy** is imported into the case
    (`evidence/<id>/source.bin`), verified byte-for-byte against the source at
    import, and used for all later reads. Deleting the original then cannot
    affect the case. The copy is **not** made technically immutable/read-only by
    the application; integrity re-verification (above) *detects* any later
    modification of the copy — which is different from *preventing* it.
- Tests: `test_evidenceintegrity` (match, tamper-detection, extraction refusal
  on mismatch, unreadable-fails-loudly, working-copy read path).

## 2. Audit-log integrity

- The audit log is an append-only JSON-lines **hash chain** (each event hashes
  the previous head + its canonical payload).
- `AuditLog::load()` recomputes the chain and returns failure whenever an event
  has been **modified in place** or **removed from the middle**, because either
  breaks the hash linkage between an event and its successor;
  `CaseWorkspace::open()` propagates that failure, so a case with such a
  modified audit log **never opens as if valid**.
- Removing entries from the **end** of the log (whole-tail truncation) leaves a
  shorter but internally consistent chain, which chain verification alone cannot
  catch. To detect it the log keeps a small **anchor** sidecar
  (`audit.log.jsonl.anchor`) recording the expected head hash and event count;
  `AuditLog::load()` compares the log against the anchor and **fails on any
  mismatch**, so tail truncation and whole-log deletion (anchor present, log
  gone) are both detected. `AuditLog::append()` updates the anchor atomically as
  part of each append (rolling back the log line if the anchor cannot be
  written), so the two never disagree after a successful append.
- **Residual limitation:** the anchor defends against accidental truncation and
  naive tampering. An adversary with write access who rewrites **both** the log
  and the anchor consistently can still shorten history undetectably — the chain
  hash prevents forging *different* events, but not a coordinated truncation of
  both files. Proving that against a motivated local attacker requires an
  off-box anchor (e.g. an external append-only store), which is out of scope.
- `AuditLog::append()` writes and flushes the event first and only then advances
  the in-memory head and anchor. If any step fails it **reports failure and does
  not advance the chain**; `CaseWorkspace` operations surface that failure.
- Tests: `test_auditlog` (append/verify, reload, in-place tamper→load fails,
  mid-log deletion→load fails, tail-truncation→load fails via anchor,
  whole-log-deletion→load fails via anchor, anchor-stays-in-sync-across-reload,
  append-failure-does-not-advance).

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
  bytes) is decoded back to the **exact password bytes**. A password is a byte
  string, and not every byte string is valid UTF-8 (a Latin-1 or binary
  password is legal), so the credential keeps the raw bytes (`rawPlaintext`,
  persisted as `rawHex`) as the forensic ground truth and derives a best-effort
  display form separately: the decoded text when the bytes are valid UTF-8,
  otherwise the canonical, reversible `$HEX[..]` notation. The `encoding` field
  (`utf-8` / `raw`) records which applies, and the report shows it. This avoids
  the earlier lossy `QString::fromUtf8` decode that replaced invalid bytes with
  U+FFFD and destroyed the true password. Legacy records without `rawHex` load
  with the raw bytes reconstructed from the stored display text.
- The recovered credential is associated with the job's target hash (read from
  the extracted-hash file) and thereby to the artifact and case.
- Tests: `test_crackedplain` (colon, space, Unicode, non-UTF-8 lossless
  round-trip, literal `$`-text, outfile-format assertion); `test_datamodels`
  (raw-byte and legacy credential round-trips).

## 5. Pause / stop / resume semantics

hashcat has no reliable out-of-console live "pause", so CaseKey uses hashcat's
supported **session/restore** mechanism and distinguishes:

- **Graceful stop** — a platform-appropriate graceful signal
  (`requestGracefulStop`, `src/forensic/execution/processcontrol.cpp`). hashcat
  aborts and writes its `--session` restore file (John writes its `.rec`).
  State → `Stopped`.
    - *POSIX:* `QProcess::terminate()` (SIGTERM), which hashcat and John trap to
      save their session.
    - *Windows:* a console **CTRL_BREAK** delivered to the engine's own process
      group. `QProcess::terminate()` posts WM_CLOSE, which a console engine has
      no window to receive, so it is bypassed. The engine is launched in a new
      process group (`configureForGracefulStop`) so the event reaches only it
      and its children, never the GUI; hashcat/John install console handlers
      that checkpoint and exit on that event.
- **Pause** — same graceful shutdown, but semantically resumable; the restore
  file is retained. State → `Paused`.
- **Forced termination** — if the process does not exit within a grace period
  (10 s) a `kill()` follows so a hung process cannot wedge the queue. No restore
  is guaranteed in this forced case.
- **Resume** — relaunch with `--session <name> --restore`, which reloads the
  original attack; CaseKey does not re-supply the attack positionals.
- **Resume after restart** — reopening a case rehydrates the job queue from the
  persisted job records (`RecoveryController::restoreJobs()` → `JobQueue::restore`):
  each job is re-registered with its session paths reconstructed, so resume/stop
  and reporting can target it again. A job that was still in flight when the app
  closed is normalized to `Paused` (it is no longer running) and can be resumed
  from its restore file; the backend rebuilds the run context for a job it did
  not start in this process. Restore never auto-starts a job — the examiner
  resumes explicitly.

> Best-effort caveat (Windows): the console CTRL_BREAK path is inherently
> **best-effort**, never guaranteed. It temporarily attaches to the engine's
> console to raise the event, and if any step fails (no console, attach denied)
> it falls back to `terminate()` and then the forced kill — in which case the
> restore/session is not guaranteed, exactly as on a forced termination. The
> engine must also honor CTRL_BREAK (current hashcat and John Jumbo do).

### Manual pause/resume validation (Windows) — not CI-covered

The Windows checkpoint behaviour **cannot be exercised on the Linux CI runners**
(and a console test harness cannot drive the CTRL_BREAK path either — see
`test_processcontrol`), so it is validated **manually on a Windows workstation**.
Do not read the automated suite as evidence that Windows checkpointing works.

**hashcat**
1. Start a job large enough to run for a while (e.g. a big wordlist, or a mask
   with a wide keyspace) so it will not finish before you can pause it.
2. Confirm progress advances (the status shows a rising done/percentage).
3. **Pause** the job.
4. Verify the `--session` restore file exists in the job directory and has
   plausible, non-empty content/size (hashcat writes `<session>.restore`).
5. **Resume** the job.
6. Verify it continues from where it left off — progress resumes near the paused
   position — rather than restarting from candidate zero.

**John the Ripper** — perform the equivalent check against its `.rec` session:
after Pause, confirm the `.rec` file exists with plausible content; after Resume
(`--restore=<session>`), confirm it continues rather than restarting.

**bkcrack** — bkcrack has **no session/checkpoint** support: a stop simply ends
the process and a resume **restarts the attack from the beginning**. This is
stated plainly rather than implying a checkpoint that does not exist.

If a graceful signal does not take (the best-effort caveat above), the job falls
through to the forced kill and no restore is guaranteed for that stop.

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

- The recovery engine is recorded on each job by a stable `engineId`
  ("hashcat" / "john" / "bkcrack") together with its display name, the exact
  argument vector, the resolved executable path, its version banner and a
  best-effort SHA-256 of that executable.
- Each extraction records the exact extractor program path and argv, and the
  extractor version where the tool reports one.
- Reports surface the engine, version, devices, exact parameters and extractor
  provenance so a report is self-describing about the toolchain that produced
  the result — regardless of which engine ran.

## 9. Engine-neutral records & backward compatibility

- Job records are engine-neutral. The engine-specific fields carry engine-
  neutral names (`engineArgs` / `enginePath` / `engineVersion`); records written
  before the migration used the hashcat-only names (`hashcatArgs` /
  `hashcatPath` / `hashcatVersion`), which are still read as a fallback, and a
  record with no `engineId` is loaded as hashcat. Older cases therefore open
  with full provenance and no data loss.
- A recovered result records its `kind` (password vs. key material vs. …) and
  the engine that produced it; a record with no `kind` loads as a password.
  This keeps a bkcrack ZipCrypto internal-key result from being mislabelled as a
  recovered password in the UI or a report.

## 10. Dictionary provenance & drift

- A Dictionary attack records the managed dictionary it used on the job and in
  the report: the library id, display name, file path, SHA-256 and candidate
  count.
- Before a Dictionary recovery starts, the wordlist's integrity is checked
  against the recorded SHA-256. A wordlist whose file is missing, or whose
  SHA-256 no longer matches, is refused with a clear explanation rather than run
  silently — so a result's dictionary provenance stays trustworthy. Built-in
  wordlists whose baseline SHA-256 is not recorded are reported as "not
  validated" rather than assumed unchanged. No wordlist/password data is
  fabricated by the application.

## Test summary

The unit-test suites run offline with no external tools (a fake process runner
stands in for hashcat/`*2john`), covering the invariants above — engine-neutral
job/result records and legacy-field fallback, dictionary provenance and SHA-256
drift detection included. Real-tool interoperability is validated separately by
the optional integration layer.
