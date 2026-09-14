/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef FORENSIC_RECOVERYREPORT_H
#define FORENSIC_RECOVERYREPORT_H

#include <QJsonObject>
#include <QString>
#include <QStringList>

namespace forensic {

/*
 * A per-recovery-attempt forensic report. It captures the full provenance of
 * one cracking job: case, artifact + integrity hash, detected type, extractor,
 * hashcat environment, exact attack parameters, timing, outcome, and any
 * recovered credential. Serializable to machine-readable JSON; a separate
 * renderer produces the human-readable HTML.
 */
struct RecoveryReport
{
    QString applicationVersion;
    QString generatedUtc;

    // Case
    QString caseId;
    QString caseName;
    QString examiner;

    // Artifact
    QString artifactFilename;
    QString artifactPath;
    qint64  artifactSize = 0;
    QString artifactSha256;
    QString artifactModifiedUtc;
    QString artifactCreatedUtc;
    QString detectedType;   // detected encryption/hash type

    // Extraction
    QString extractorId;
    QString extractorVersion;
    QString extractionStatus;

    // Recovery engine environment
    QString engineId;          // "hashcat" / "john" / "bkcrack"
    QString engineDisplayName; // human-readable engine name
    QString engineVersion;     // version / banner of the engine
    QString enginePath;        // resolved executable
    QString engineExeSha256;   // SHA-256 of the executable, if known
    QStringList devices;

    // Attack
    quint32 hashMode = 0;
    QString hashModeName;
    int attackMode = 0;
    QString attackStrategy;
    QStringList wordlists;
    QStringList rules;
    QString mask;
    QStringList engineArgs; // exact parameters passed to the engine

    // Timing / outcome
    QString startedUtc;
    QString endedUtc;
    qint64  runtimeMs = 0;
    QString finalStatus;

    // Recovered result (if any)
    bool recovered = false;
    QString recoveredKind;     // "password", "key material", ... (result kind noun)
    QString recoveredPlaintext; // the recovered value (password or key material)
    QString recoveredEncoding; // "utf-8" or "raw" (raw => value shown as $HEX[..])
    QString recoveredHash;     // the target (hash line, or bkcrack target label)
    QString recoveredUtc;

    QJsonObject toJson() const;
};

} // namespace forensic

#endif // FORENSIC_RECOVERYREPORT_H
