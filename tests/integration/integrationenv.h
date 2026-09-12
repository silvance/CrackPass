/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 *
 * Shared discovery/probing for the OPTIONAL integration layer. It locates the
 * real external tools (hashcat and the John the Ripper Jumbo *2john utilities)
 * and the test corpus from environment variables or PATH, entirely offline.
 * When a dependency is absent the integration test and the diagnostic runner
 * report/skip cleanly -- they never require the tools to be present to build.
 *
 * Environment:
 *   CRACKPASS_HASHCAT    - path to the hashcat executable (else looked up on PATH)
 *   CRACKPASS_TOOLS_DIR  - directory holding the *2john utilities (else PATH)
 *   CRACKPASS_CORPUS     - directory holding fixtures + manifest.json
 */
#ifndef CRACKPASS_INTEGRATIONENV_H
#define CRACKPASS_INTEGRATIONENV_H

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
    QMap<QString, ToolInfo> extractors;     // keyed by tool id (office2john, ...)
    QString corpusDir;

    bool hashcatAvailable() const { return hashcat.available; }
    bool corpusAvailable() const;
    // True when everything needed to run the full chain for `toolId` is present.
    bool canRun(const QString &extractorToolId) const;

    static QString runCapture(const QString &program, const QStringList &args,
                              int timeoutMs, bool *ok = nullptr);
};

}} // namespace forensic::itest

#endif // CRACKPASS_INTEGRATIONENV_H
