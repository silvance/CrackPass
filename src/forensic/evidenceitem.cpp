/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#include "evidenceitem.h"
#include "jsonutil.h"

namespace forensic {

QJsonObject EvidenceItem::toJson() const
{
    QJsonObject typeObj;
    typeObj[QStringLiteral("id")] = type.id;
    typeObj[QStringLiteral("displayName")] = type.displayName;
    typeObj[QStringLiteral("confidence")] = type.confidence;

    QJsonObject obj;
    obj[QStringLiteral("id")] = id.toString(QUuid::WithoutBraces);
    obj[QStringLiteral("caseId")] = caseId;
    obj[QStringLiteral("originalPath")] = originalPath;
    obj[QStringLiteral("filename")] = filename;
    obj[QStringLiteral("size")] = static_cast<double>(size);
    obj[QStringLiteral("modifiedUtc")] = jsonutil::fromDateTime(modifiedUtc);
    obj[QStringLiteral("createdUtc")] = jsonutil::fromDateTime(createdUtc);
    obj[QStringLiteral("accessedUtc")] = jsonutil::fromDateTime(accessedUtc);
    obj[QStringLiteral("sha256")] = sha256;
    obj[QStringLiteral("importedUtc")] = jsonutil::fromDateTime(importedUtc);
    obj[QStringLiteral("type")] = typeObj;
    obj[QStringLiteral("notes")] = notes;
    return obj;
}

EvidenceItem EvidenceItem::fromJson(const QJsonObject &obj)
{
    EvidenceItem e;
    e.id = QUuid::fromString(obj.value(QStringLiteral("id")).toString());
    e.caseId = obj.value(QStringLiteral("caseId")).toString();
    e.originalPath = obj.value(QStringLiteral("originalPath")).toString();
    e.filename = obj.value(QStringLiteral("filename")).toString();
    e.size = static_cast<qint64>(obj.value(QStringLiteral("size")).toDouble());
    e.modifiedUtc = jsonutil::toDateTime(obj.value(QStringLiteral("modifiedUtc")).toString());
    e.createdUtc = jsonutil::toDateTime(obj.value(QStringLiteral("createdUtc")).toString());
    e.accessedUtc = jsonutil::toDateTime(obj.value(QStringLiteral("accessedUtc")).toString());
    e.sha256 = obj.value(QStringLiteral("sha256")).toString();
    e.importedUtc = jsonutil::toDateTime(obj.value(QStringLiteral("importedUtc")).toString());

    const QJsonObject typeObj = obj.value(QStringLiteral("type")).toObject();
    e.type.id = typeObj.value(QStringLiteral("id")).toString();
    e.type.displayName = typeObj.value(QStringLiteral("displayName")).toString();
    e.type.confidence = typeObj.value(QStringLiteral("confidence")).toDouble();

    e.notes = obj.value(QStringLiteral("notes")).toString();
    return e;
}

} // namespace forensic
