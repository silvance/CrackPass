# CaseKey — first run (full Windows bundle)

This is the **self-contained** CaseKey bundle. It runs fully offline — no
installer, no telemetry, no network calls — and carries the recovery engines and
the managed dictionary manifest already laid out where CaseKey looks for them.

## Start here

**Double-click `CaseKey.cmd`.** It puts the bundled Python (used by the John
`*2john` extraction scripts, such as `office2john`) and the engines on the path
for this session, then launches the app. That's the whole setup.

> You can also launch `casekey.exe` directly. The engines still resolve from the
> bundled `tools\` layout, but the Python `*2john` scripts need a Python
> interpreter on your system `PATH` — which is exactly what `CaseKey.cmd`
> arranges, so it is the recommended entry point.

## The primary workflow

Add an encrypted document → **Recover Password** → **Dictionary → CaseKey
Common** → **Start**. CaseKey extracts the hash, picks the engine automatically,
and recovers the password. Watch it in **Jobs** and read the result in
**Results**; generate a report from there.

Use **Advanced → Dependency Doctor** to confirm every engine and extractor
resolved (it shows each tool's path, version and SHA-256).

## What's inside

- `casekey.exe` + the Qt runtime (LGPL, shipped as separate DLLs).
- `tools\hashcat\`, `tools\john\run\` (engine + `*2john`), `tools\bkcrack\`,
  `tools\rules\` — the recovery engines and rule files.
- `runtime\python\` — an embeddable Python for the `*2john` scripts.
- `dictionaries\manifest.json` — the managed dictionary library. Wordlist files
  are supplied per your policy; entries without a file show as "file not
  supplied" and are never fabricated.
- `LICENSES\` and `SOURCE_OFFER.md` — the license text and source offer for each
  bundled third-party tool. `THIRD_PARTY.md` lists exact versions.

## Provenance

Every extraction and recovery record stores the exact tool path, version and
SHA-256 that produced it, so a report is self-describing about the toolchain.
