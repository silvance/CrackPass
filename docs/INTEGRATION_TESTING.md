# CrackPass — real-tool integration testing

The unit tests use a fake process runner and never touch real tools. This
**optional** integration layer exercises the *actual* hashcat and John the
Ripper Jumbo binaries deployed in your lab, to prove CrackPass interoperates
with those specific versions — not just with internal mocks. It uses **no
network access**.

It never breaks normal builds: the code always compiles, and every test/tool
**skips cleanly** when a dependency or the corpus is absent.

## Components

- `tests/integration/generate_corpus.py` — offline generator producing synthetic
  encrypted artifacts with **known passwords**, plus edge cases, and a
  `manifest.json`. It only produces fixtures for formats whose tool is installed;
  others are reported as skipped for you to supply manually.
- `test_integration` — a CTest target that drives each fixture through the full
  chain and **QSKIPs** when hashcat/corpus are unavailable.
- `crackpass_integration_diag` — a standalone diagnostic runner for a
  disconnected Windows workstation.

## The full chain each fixture exercises

artifact → content detection → encryption detection → **real** extraction
utility → normalized hash → hashcat mode resolution → **real** hashcat run →
recovered known password → case association → evidence SHA-256 unchanged →
report generation. On failure the report names the **exact stage** that broke.

## Corpus (per supported type, where the tool exists)

Microsoft Office, PDF, ZIP, RAR, 7-Zip, KeePass — with, where practical:
simple password, password with **spaces**, password with a **colon**, a
**Unicode** password, a **non-encrypted** artifact, a **malformed/corrupted**
artifact, and an artifact **renamed to a misleading extension** (content-based
detection must still identify it correctly).

## Running it (disconnected workstation)

```
# 1. Generate (or hand-assemble) the corpus with your installed tools:
python3 tests/integration/generate_corpus.py C:\cases\corpus

# 2. Point CrackPass at the tools and corpus:
set CRACKPASS_HASHCAT=C:\CrackPass\tools\hashcat\hashcat.exe
set CRACKPASS_TOOLS_DIR=C:\CrackPass\tools\john\run
set CRACKPASS_CORPUS=C:\cases\corpus

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
or `unknown` (for non-encrypted/edge fixtures). Keep passwords short so a tiny
wordlist recovers them quickly.

## Disable entirely

`cmake -B build -DCRACKPASS_BUILD_INTEGRATION=OFF`
