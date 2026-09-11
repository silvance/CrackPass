/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#include "evidenceintake.h"
#include "hashingservice.h"

#include <QFileInfo>

namespace forensic {

EvidenceIntake::EvidenceIntake(const ArtifactAnalyzerRegistry &analyzers)
    : m_analyzers(analyzers)
{
}

IntakeResult EvidenceIntake::import(const QString &caseId, const QString &sourcePath) const
{
    IntakeResult result;

    QFileInfo fi(sourcePath);
    if (!fi.exists() || !fi.isFile()) {
        result.error = QStringLiteral("Source is not an existing file: %1").arg(sourcePath);
        return result;
    }
    if (!fi.isReadable()) {
        result.error = QStringLiteral("Source is not readable: %1").arg(sourcePath);
        return result;
    }

    QString hashError;
    const QString sha256 = HashingService::sha256File(fi.absoluteFilePath(), &hashError);
    if (sha256.isEmpty()) {
        result.error = hashError;
        return result;
    }

    EvidenceItem e;
    e.id = QUuid::createUuid();
    e.caseId = caseId;
    e.originalPath = fi.absoluteFilePath();
    e.filename = fi.fileName();
    e.size = fi.size();
    e.modifiedUtc = fi.lastModified().toUTC();
    e.createdUtc = fi.birthTime().toUTC();      // may be invalid on some filesystems
    e.accessedUtc = fi.lastRead().toUTC();
    e.sha256 = sha256;
    e.importedUtc = QDateTime::currentDateTimeUtc();
    e.type = m_analyzers.identify(fi.absoluteFilePath());

    result.ok = true;
    result.item = e;
    return result;
}

} // namespace forensic
