/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#ifndef CRACKPASS_INTEGRATIONCHAIN_H
#define CRACKPASS_INTEGRATIONCHAIN_H

#include "integrationenv.h"
#include <QString>
#include <QVector>

namespace forensic { namespace itest {

// Result of driving one fixture through the entire real chain. `stage` names
// the exact point of failure so a lab operator can see where interop broke.
struct ChainResult {
    bool ok = false;
    QString stage;        // last stage attempted
    QString message;
    QString detectedType;
    QString extractedHash;
    quint32 modeUsed = 0;
    QString recovered;
    QString sha256Before;
    QString sha256After;
    bool reportWritten = false;
};

struct FixtureSpec {
    QString path;
    QString expectedType;     // manifest "type"
    bool encrypted = true;
    QString expectedPassword; // may be empty for non-encrypted/malformed
};

// Runs: detect -> encryption probe -> real extraction -> mode resolution ->
// real hashcat -> recovered password -> case association -> SHA unchanged ->
// report. `extractorToolId` selects which *2john tool to use.
ChainResult runChain(const IntegrationEnv &env, const QString &caseParentDir,
                     const FixtureSpec &fixture, const QString &extractorToolId,
                     int hashcatTimeoutMs = 120000);

// Maps an artifact type id to its extractor tool id.
QString extractorForType(const QString &typeId);

// Loads fixtures from <dir>/manifest.json (paths resolved against <dir>).
QVector<FixtureSpec> loadCorpus(const QString &dir);

}} // namespace forensic::itest

#endif // CRACKPASS_INTEGRATIONCHAIN_H
