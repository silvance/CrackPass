/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 *
 * Shared discovery/probing for the OPTIONAL integration layer. It locates the
 * real external tools (hashcat and the John the Ripper Jumbo *2john utilities)
 * and the test corpus from environment variables or PATH, entirely offline.
 * When a dependency is absent the integration test and the diagnostic runner
 * report/skip cleanly -- they never require the tools to be present to build.
 *
 * Environment:
 *   CASEKEY_HASHCAT    - path to the hashcat executable (else looked up on PATH)
 *   CASEKEY_JOHN       - path to the John the Ripper executable (else PATH)
 *   CASEKEY_BKCRACK    - path to the bkcrack executable (else PATH)
 *   CASEKEY_TOOLS_DIR  - directory holding the *2john utilities (else PATH)
 *   CASEKEY_CORPUS     - directory holding fixtures + manifest.json
 */
#ifndef CASEKEY_INTEGRATIONENV_H
#define CASEKEY_INTEGRATIONENV_H

#include <QMap>
#include <QString>
#include <QStringList>

namespace forensic { namespace itest {

struct ToolInfo {
    QString id;
    bool available = false;
    QString program;       // resolved executable (interpreter, or the tool itself)
    QStringList prefixArgs;// e.g. {script.py} when run via an interpreter
    QString version;       // best-effort; may be empty
    QString interpreter;   // "python"/"perl"/"" (native)
};

class IntegrationEnv
{
public:
    static IntegrationEnv detect();

    ToolInfo hashcat;
    QString hashcatBackendInfo;             // `hashcat -I` (machine or plain)
    ToolInfo john;                          // John the Ripper cracking engine
    ToolInfo bkcrack;                       // bkcrack ZipCrypto known-plaintext engine
    QMap<QString, ToolInfo> extractors;     // keyed by tool id (office2john, ...)
    QString corpusDir;

    bool hashcatAvailable() const { return hashcat.available; }
    bool johnAvailable() const { return john.available; }
    bool bkcrackAvailable() const { return bkcrack.available; }
    bool corpusAvailable() const;
    // True when everything needed to run the full chain for `toolId` is present.
    bool canRun(const QString &extractorToolId) const;

    static QString runCapture(const QString &program, const QStringList &args,
                              int timeoutMs, bool *ok = nullptr);
};

}} // namespace forensic::itest

#endif // CASEKEY_INTEGRATIONENV_H
