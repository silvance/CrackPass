/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#ifndef FORENSIC_EVIDENCEITEM_H
#define FORENSIC_EVIDENCEITEM_H

#include "artifacttype.h"
#include <QDateTime>
#include <QJsonObject>
#include <QString>
#include <QUuid>

namespace forensic {

// How the case holds the artifact bytes. The model supports both from the
// start; the workflow currently defaults to Referenced.
enum class EvidenceStorageMode {
    Referenced,  // original file left in place; read from originalPath
    WorkingCopy, // an immutable copy imported into the case; read from workingCopyPath
};

QString evidenceStorageModeToString(EvidenceStorageMode mode);
EvidenceStorageMode evidenceStorageModeFromString(const QString &s);

/*
 * A source artifact submitted to a case.
 *
 * The original file is referenced by path and is never copied or modified. Its
 * identity is pinned by a SHA-256 taken at intake. Filesystem metadata is
 * captured for the record. The extracted hash (when extraction is implemented)
 * is stored separately and is NOT part of this model.
 */
struct EvidenceItem
{
    QUuid id;
    QString caseId;

    QString originalPath;   // absolute path to the source, left in place
    QString filename;
    qint64 size = 0;

    QDateTime modifiedUtc;  // filesystem timestamps of the source
    QDateTime createdUtc;
    QDateTime accessedUtc;

    QString sha256;         // lowercase hex, computed read-only at intake

    EvidenceStorageMode storageMode = EvidenceStorageMode::Referenced;
    QString workingCopyPath; // relative-to-case path when storageMode == WorkingCopy
    QDateTime importedUtc;  // when it was added to the case

    ArtifactType type;      // detected artifact type
    QString notes;

    QJsonObject toJson() const;
    static EvidenceItem fromJson(const QJsonObject &obj);
};

} // namespace forensic

#endif // FORENSIC_EVIDENCEITEM_H
