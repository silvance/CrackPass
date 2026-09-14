/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef CASEKEY_INTEGRATIONCHAIN_H
#define CASEKEY_INTEGRATIONCHAIN_H

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

// A bkcrack (ZipCrypto known-plaintext) fixture: an encrypted ZIP, the entry to
// attack, and a known-plaintext file for that entry.
struct BkcrackFixtureSpec {
    QString zipPath;        // encrypted ZIP archive
    QString targetEntry;    // ZipCrypto entry to attack
    QString plainFile;      // known plaintext for that entry
    QString expectedContains; // optional: substring the recovered keys must contain
};

// Runs: detect -> encryption probe -> real extraction -> mode resolution ->
// real recovery -> recovered password -> case association -> SHA unchanged ->
// report. `extractorToolId` selects which *2john tool to use; `engineId`
// selects the cracking engine ("hashcat" or "john").
ChainResult runChain(const IntegrationEnv &env, const QString &caseParentDir,
                     const FixtureSpec &fixture, const QString &extractorToolId,
                     const QString &engineId = QStringLiteral("hashcat"),
                     int recoveryTimeoutMs = 120000);

// Runs the bkcrack ZipCrypto known-plaintext chain: intake -> real bkcrack ->
// recovered internal key -> case association -> SHA unchanged. Evidence is never
// modified.
ChainResult runBkcrackChain(const IntegrationEnv &env, const QString &caseParentDir,
                            const BkcrackFixtureSpec &fixture, int timeoutMs = 120000);

// Maps an artifact type id to its extractor tool id.
QString extractorForType(const QString &typeId);

// Loads password fixtures from <dir>/manifest.json (paths resolved against <dir>).
QVector<FixtureSpec> loadCorpus(const QString &dir);

// Loads bkcrack fixtures from the "bkcrack" array of <dir>/manifest.json.
QVector<BkcrackFixtureSpec> loadBkcrackCorpus(const QString &dir);

}} // namespace forensic::itest

#endif // CASEKEY_INTEGRATIONCHAIN_H
