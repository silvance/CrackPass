/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#include "extraction.h"
#include "forensic/jsonutil.h"

#include <QJsonArray>

namespace forensic {

QString Extraction::statusToString(ExtractionStatus s)
{
    switch (s) {
    case ExtractionStatus::Success:         return QStringLiteral("success");
    case ExtractionStatus::ToolUnavailable: return QStringLiteral("tool_unavailable");
    case ExtractionStatus::NotEncrypted:    return QStringLiteral("not_encrypted");
    case ExtractionStatus::NoHashProduced:  return QStringLiteral("no_hash_produced");
    case ExtractionStatus::Failed:          return QStringLiteral("failed");
    }
    return QStringLiteral("failed");
}

QJsonObject Extraction::toJson() const
{
    QJsonArray argvArr;
    for (const QString &a : argv)
        argvArr.append(a);

    QJsonArray modeArr;
    for (const HashcatModeOption &m : candidateModes)
        modeArr.append(m.toJson());

    QJsonObject obj;
    obj[QStringLiteral("id")] = id.toString(QUuid::WithoutBraces);
    obj[QStringLiteral("caseId")] = caseId;
    obj[QStringLiteral("evidenceId")] = evidenceId.toString(QUuid::WithoutBraces);
    obj[QStringLiteral("extractorId")] = extractorId;
    obj[QStringLiteral("toolProgram")] = toolProgram;
    obj[QStringLiteral("argv")] = argvArr;
    obj[QStringLiteral("status")] = status;
    obj[QStringLiteral("message")] = message;
    obj[QStringLiteral("exitCode")] = exitCode;
    obj[QStringLiteral("hashArtifactPath")] = hashArtifactPath;
    obj[QStringLiteral("stdoutPath")] = stdoutPath;
    obj[QStringLiteral("stderrPath")] = stderrPath;
    obj[QStringLiteral("candidateModes")] = modeArr;
    obj[QStringLiteral("selectedMode")] = static_cast<double>(selectedMode);
    obj[QStringLiteral("startedUtc")] = jsonutil::fromDateTime(startedUtc);
    obj[QStringLiteral("endedUtc")] = jsonutil::fromDateTime(endedUtc);
    return obj;
}

Extraction Extraction::fromJson(const QJsonObject &obj)
{
    Extraction e;
    e.id = QUuid::fromString(obj.value(QStringLiteral("id")).toString());
    e.caseId = obj.value(QStringLiteral("caseId")).toString();
    e.evidenceId = QUuid::fromString(obj.value(QStringLiteral("evidenceId")).toString());
    e.extractorId = obj.value(QStringLiteral("extractorId")).toString();
    e.toolProgram = obj.value(QStringLiteral("toolProgram")).toString();
    for (const QJsonValue &v : obj.value(QStringLiteral("argv")).toArray())
        e.argv.append(v.toString());
    e.status = obj.value(QStringLiteral("status")).toString();
    e.message = obj.value(QStringLiteral("message")).toString();
    e.exitCode = obj.value(QStringLiteral("exitCode")).toInt(-1);
    e.hashArtifactPath = obj.value(QStringLiteral("hashArtifactPath")).toString();
    e.stdoutPath = obj.value(QStringLiteral("stdoutPath")).toString();
    e.stderrPath = obj.value(QStringLiteral("stderrPath")).toString();
    for (const QJsonValue &v : obj.value(QStringLiteral("candidateModes")).toArray())
        e.candidateModes.append(HashcatModeOption::fromJson(v.toObject()));
    e.selectedMode = static_cast<quint32>(obj.value(QStringLiteral("selectedMode")).toDouble());
    e.startedUtc = jsonutil::toDateTime(obj.value(QStringLiteral("startedUtc")).toString());
    e.endedUtc = jsonutil::toDateTime(obj.value(QStringLiteral("endedUtc")).toString());
    return e;
}

} // namespace forensic
