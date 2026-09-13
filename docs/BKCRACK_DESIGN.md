<!--
SPDX-License-Identifier: GPL-3.0-or-later
SPDX-FileCopyrightText: CaseKey contributors
-->
# bkcrack (ZipCrypto known-plaintext) — design note

This note records how `bkcrack` fits into CaseKey. It is written before the
code so the shape can be agreed on; later slices implement it.

## Why bkcrack is different

CaseKey's existing recovery engines (hashcat, John) are **guessing** engines:
they take a hash, try candidate passwords (wordlist / mask / incremental), and
recover the password. The whole planner stack — `AttackJobSpec`, the
`RecoveryEngine` seam, `AttackCommandBuilder` / `JohnCommandBuilder` — is shaped
around that model (hash mode, attack mode, wordlists, rules, mask).

[bkcrack](https://github.com/kimci86/bkcrack) is **not** a guessing engine. It
performs Biham–Kocher's **known-plaintext** cryptanalysis against the legacy
PKWARE ("ZipCrypto") stream cipher:

- **Input** is not a wordlist or mask. It is *known plaintext* — some bytes the
  examiner already knows appear (at a known offset) inside one encrypted entry.
- **Output** is not a password. It recovers the **three 32-bit internal keys**
  (X, Y, Z) of the ZipCrypto keystream. Those keys decrypt *every* entry
  encrypted under the same password, regardless of password length or entropy.
  A password can *optionally* be reconstructed from the keys afterwards, but it
  is not required to decrypt the data.
- It does **not** apply to WinZip **AES** encryption (the common modern case).
  It applies only to traditional ZipCrypto.

Forcing this through `AttackJobSpec` would be dishonest (none of its fields fit)
and would mislead the examiner. So bkcrack gets its **own** small, explicit spec
and command builder, and its **own** execution backend — but it reuses the parts
of the pipeline that are genuinely general: the `JobQueue` (routed by
`engineId`), the `CrackingJob` provenance record, and the Jobs/Results views.

## Applicability gate: ZipCrypto only

bkcrack must be offered **only** for archives that actually use ZipCrypto. A ZIP
entry is encrypted when general-purpose bit-flag bit 0 is set in its local file
header. WinZip AES entries also set that bit, but use compression method `99`
(`0x63`) and carry an AES extra field (header id `0x9901`); ZipCrypto entries
use a normal compression method (0 = stored, 8 = deflate) with no AES extra
field.

The first slice adds a pure classifier (`zipcipher.{h,cpp}`) that scans the
local file headers and reports, per entry, whether it is unencrypted, ZipCrypto,
or AES — plus an archive-level verdict. The bkcrack action is enabled only when
at least one ZipCrypto entry is present; an AES-only archive shows a clear "not
applicable — use a password attack (zip2john → hashcat/John)" message. This
mirrors the "refuse rather than approximate" stance of the John engine.

## Known-plaintext sources (the UX)

bkcrack needs at least ~12 contiguous known plaintext bytes (and works far
faster with more). CaseKey will support the three source shapes bkcrack itself
accepts, collected in a dedicated dialog:

1. **A known plaintext file** (`-p <file>`): the examiner has (or can produce)
   the exact, complete original of one entry, or a prefix of it. Most common
   when a copy of an embedded file is known (a standard config, a bundled
   image, a template).
2. **Bytes at an offset** (`-x <offset> <hex>`): known bytes at a known offset
   inside one entry — e.g. a fixed file header/magic the entry is known to
   start with.
3. **A plaintext entry from another archive** — treated as case (1) after the
   examiner exports that entry to a file.

The dialog collects: the target encrypted entry (chosen from the ZipCrypto entry
list the classifier produced), the plaintext source, and any offset. Nothing is
guessed; if the inputs are incomplete the attack is refused with a specific
reason (same pattern as `JohnCommandBuilder`).

## Components (later slices)

- `BkcrackAttackSpec` (pure): `{ zipPath, targetEntry, plainFile | (plainHex,
  plainOffset), extraArgs }` — a fully explicit description of one bkcrack run.
- `BkcrackCommandBuilder` (pure, tested): spec → bkcrack argv
  (`-C <zip> -c <entry> -p <plainfile>` or `-x <off> <hex>` …), or a specific
  "cannot express" reason when the spec is incomplete.
- `BkcrackExecutionBackend : JobExecutionBackend`: runs bkcrack, parses its
  stdout for the recovered keys (`Keys: <X> <Y> <Z>`) and progress, and emits a
  recovered **result carrying the keys**. Registered under `engineId "bkcrack"`
  in the `JobQueue`, so provenance, persistence and the Jobs/Results views work
  unchanged. (Key→password reconstruction and archive decryption are follow-ups.)
- Detection wiring: `bkcrack` as a resolvable tool in `DependencyProbe` /
  Dependency Doctor and a `bkcrackPath` setting, like hashcat/john.
- A ZIP-artifact UI action ("ZipCrypto attack (bkcrack)") that opens the
  known-plaintext dialog and queues a bkcrack job.

## Recovered result: keys, not a password

The recovered artifact for a bkcrack job is the **key triple**, not a password.
This is a genuine forensic outcome (the archive can be decrypted with it), and
CaseKey records it as such rather than pretending a password was found. Whether
to also attempt password reconstruction (`bkcrack -k … --bruteforce`) or to
decrypt entries (`bkcrack -k … -d …`) is a follow-up decision; the recovered
keys are the deliverable of the core feature.

## Explicitly out of scope (for now)

- WinZip AES archives (bkcrack does not apply; the password path already does).
- Automatic discovery of known plaintext (the examiner supplies it).
- Password reconstruction from keys and bulk archive decryption (follow-ups).
