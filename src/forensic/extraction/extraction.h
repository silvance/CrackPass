/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#ifndef FORENSIC_EXTRACTION_H
#define FORENSIC_EXTRACTION_H

#include "forensic/hashextractor.h"
#include "hashcatmodes.h"
#include <QDateTime>
#include <QJsonObject>
#include <QString>
#include <QUuid>
#include <QVector>

namespace forensic {

/*
 * A persisted record of one extraction attempt against an evidence item. The
 * extracted hash lives in its own file (hashArtifactPath), separate from the
 * evidence. selectedMode is 0 until the examiner resolves an ambiguous mode.
 */
struct Extraction
{
    QUuid id;
    QString caseId;
    QUuid evidenceId;

    QString extractorId;
    QString extractorVersion;
    QString toolProgram;
    QStringList argv;

    QString status;                          // ExtractionStatus as string
    QString message;
    int exitCode = -1;

    QString hashArtifactPath;                // relative path to hash.txt
    QString stdoutPath;
    QString stderrPath;

    QVector<HashcatModeOption> candidateModes;
    quint32 selectedMode = 0;                // 0 = unresolved / ambiguous

    QDateTime startedUtc;
    QDateTime endedUtc;

    QJsonObject toJson() const;
    static Extraction fromJson(const QJsonObject &obj);

    static QString statusToString(ExtractionStatus s);
};

} // namespace forensic

#endif // FORENSIC_EXTRACTION_H
