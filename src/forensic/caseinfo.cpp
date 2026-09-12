/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "caseinfo.h"
#include "jsonutil.h"

namespace forensic {

QJsonObject CaseInfo::toJson() const
{
    QJsonObject obj;
    obj[QStringLiteral("id")] = id;
    obj[QStringLiteral("name")] = name;
    obj[QStringLiteral("examiner")] = examiner;
    obj[QStringLiteral("createdUtc")] = jsonutil::fromDateTime(createdUtc);
    obj[QStringLiteral("notes")] = notes;
    obj[QStringLiteral("schemaVersion")] = schemaVersion;
    return obj;
}

CaseInfo CaseInfo::fromJson(const QJsonObject &obj)
{
    CaseInfo c;
    c.id = obj.value(QStringLiteral("id")).toString();
    c.name = obj.value(QStringLiteral("name")).toString();
    c.examiner = obj.value(QStringLiteral("examiner")).toString();
    c.createdUtc = jsonutil::toDateTime(obj.value(QStringLiteral("createdUtc")).toString());
    c.notes = obj.value(QStringLiteral("notes")).toString();
    c.schemaVersion = obj.value(QStringLiteral("schemaVersion")).toInt(1);
    return c;
}

} // namespace forensic
