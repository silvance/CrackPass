/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "recoveredcredential.h"
#include "jsonutil.h"

namespace forensic {

QJsonObject RecoveredCredential::toJson() const
{
    QJsonObject obj;
    obj[QStringLiteral("id")] = id.toString(QUuid::WithoutBraces);
    obj[QStringLiteral("caseId")] = caseId;
    obj[QStringLiteral("jobId")] = jobId.toString(QUuid::WithoutBraces);
    obj[QStringLiteral("evidenceId")] = evidenceId.toString(QUuid::WithoutBraces);
    obj[QStringLiteral("hash")] = hash;
    obj[QStringLiteral("plaintext")] = plaintext;
    obj[QStringLiteral("recoveredUtc")] = jsonutil::fromDateTime(recoveredUtc);
    return obj;
}

RecoveredCredential RecoveredCredential::fromJson(const QJsonObject &obj)
{
    RecoveredCredential c;
    c.id = QUuid::fromString(obj.value(QStringLiteral("id")).toString());
    c.caseId = obj.value(QStringLiteral("caseId")).toString();
    c.jobId = QUuid::fromString(obj.value(QStringLiteral("jobId")).toString());
    c.evidenceId = QUuid::fromString(obj.value(QStringLiteral("evidenceId")).toString());
    c.hash = obj.value(QStringLiteral("hash")).toString();
    c.plaintext = obj.value(QStringLiteral("plaintext")).toString();
    c.recoveredUtc = jsonutil::toDateTime(obj.value(QStringLiteral("recoveredUtc")).toString());
    return c;
}

} // namespace forensic
