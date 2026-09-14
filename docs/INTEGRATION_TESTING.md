# CaseKey — real-tool integration testing

The unit tests use a fake process runner and never touch real tools. This
**optional** integration layer exercises the *actual* recovery engines deployed
in your lab — hashcat, John the Ripper Jumbo, and bkcrack — together with the
John Jumbo `*2john` extraction utilities, to prove CaseKey interoperates with
those specific versions, not just with internal mocks. It uses **no network
access**.

It never breaks normal builds: the code always compiles, and every test/tool
**skips cleanly** when a dependency or the corpus is absent.

## Components

- `tests/integration/generate_corpus.py` — offline generator producing synthetic
  encrypted artifacts with **known passwords**, plus edge cases, and a
  `manifest.json`. It only produces fixtures for formats whose tool is installed;
  others are reported as skipped for you to supply manually.
- `test_integration` — a CTest target with three groups of rows, each of which
  **QSKIPs** independently when its engine (or the corpus) is unavailable:
  - `fullChain` — the hashcat chain (skips without `CASEKEY_HASHCAT`);
  - `johnChain` — the same corpus recovered through **John** (skips without
    `CASEKEY_JOHN`);
  - `bkcrackChain` — the **bkcrack** ZipCrypto known-plaintext chain over the
    manifest's `bkcrack` fixtures (skips without `CASEKEY_BKCRACK` or fixtures).
- `crackpass_integration_diag` — a standalone diagnostic runner for a
  disconnected Windows workstation.

## The full chain each fixture exercises

**Password chains (hashcat / John).** artifact → content detection → encryption
detection → **real** extraction utility → normalized hash → mode resolution →
**real** engine run → recovered known password → case association → evidence
SHA-256 unchanged → report generation. hashcat is driven per candidate `-m`
mode; John auto-detects the format from the hash, so one pass suffices.

**BitLocker** rides this same chain: a `bitlocker` fixture is extracted with
`bitlocker2john` and recovered with hashcat `-m 22100` (or John), no special
casing.

**bkcrack chain (ZipCrypto known-plaintext).** intake → **real** bkcrack
known-plaintext cryptanalysis → recovered internal key → case association →
evidence SHA-256 unchanged. This is a cryptanalytic attack, not a password
guess, so it does not go through hash extraction or mode resolution.

On failure the result names the **exact stage** that broke.

## Corpus (per supported type, where the tool exists)

Microsoft Office, PDF, ZIP, RAR, 7-Zip, KeePass, BitLocker — with, where
practical: simple password, password with **spaces**, password with a
**colon**, a **Unicode** password, a **non-encrypted** artifact, a
**malformed/corrupted** artifact, and an artifact **renamed to a misleading
extension** (content-based detection must still identify it correctly). The
generator also builds a **ZipCrypto** archive plus a known-plaintext file for
the bkcrack fixture whenever `zip` is present.

## Running it (disconnected workstation)

```
# 1. Generate (or hand-assemble) the corpus with your installed tools:
python3 tests/integration/generate_corpus.py C:\cases\corpus

# 2. Point CaseKey at the tools and corpus (set only the engines you have;
#    each unset engine simply skips its rows):
set CASEKEY_HASHCAT=C:\CaseKey\tools\hashcat\hashcat.exe
set CASEKEY_JOHN=C:\CaseKey\tools\john\run\john.exe
set CASEKEY_BKCRACK=C:\CaseKey\tools\bkcrack\bkcrack.exe
set CASEKEY_TOOLS_DIR=C:\CaseKey\tools\john\run
set CASEKEY_CORPUS=C:\cases\corpus

# 3a. Run as part of the test suite:
ctest --test-dir build -R test_integration --output-on-failure

# 3b. Or run the diagnostic report:
build\tests\integration\crackpass_integration_diag
```

The diagnostic runner reports: hashcat path/version, GPU/backend information,
each `*2john` utility's availability/resolved path/interpreter, and per-fixture
PASS/FAIL with the exact failure stage.

## Adding fixtures for formats your generator can't build

Drop the artifact into the corpus directory and add a `manifest.json` entry:

```json
{ "file": "secret.docx", "type": "ms-office", "encrypted": true, "password": "Password1" }
```

Supported `type` values: `ms-office`, `pdf`, `zip`, `rar`, `7z`, `keepass-kdbx`,
`bitlocker`, or `unknown` (for non-encrypted/edge fixtures). Keep passwords
short so a tiny wordlist recovers them quickly.

**bkcrack fixtures** live in a separate `bkcrack` array in the same
`manifest.json`, each naming the encrypted ZIP, the entry to attack, and a
known-plaintext file for that entry (paths relative to the corpus directory):

```json
{
  "fixtures": [ ... ],
  "bkcrack": [
    { "file": "bkcrack_zipcrypto.zip", "entry": "_plain_source.txt",
      "plainFile": "bkcrack_plain.txt" }
  ]
}
```

An optional `"keysContain"` string asserts a substring of the recovered keys.

## Disable entirely

`cmake -B build -DCASEKEY_BUILD_INTEGRATION=OFF`
