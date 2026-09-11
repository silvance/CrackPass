/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#include "crackingjob.h"
#include "jsonutil.h"

#include <QJsonArray>

namespace forensic {

QString jobStateToString(JobState state)
{
    switch (state) {
    case JobState::Created:   return QStringLiteral("created");
    case JobState::Queued:    return QStringLiteral("queued");
    case JobState::Running:   return QStringLiteral("running");
    case JobState::Paused:    return QStringLiteral("paused");
    case JobState::Completed: return QStringLiteral("completed");
    case JobState::Failed:    return QStringLiteral("failed");
    case JobState::Cancelled: return QStringLiteral("cancelled");
    }
    return QStringLiteral("created");
}

JobState jobStateFromString(const QString &s)
{
    if (s == QStringLiteral("queued"))    return JobState::Queued;
    if (s == QStringLiteral("running"))   return JobState::Running;
    if (s == QStringLiteral("paused"))    return JobState::Paused;
    if (s == QStringLiteral("completed")) return JobState::Completed;
    if (s == QStringLiteral("failed"))    return JobState::Failed;
    if (s == QStringLiteral("cancelled")) return JobState::Cancelled;
    return JobState::Created;
}

QJsonObject ComputeDevice::toJson() const
{
    QJsonObject obj;
    obj[QStringLiteral("id")] = id;
    obj[QStringLiteral("name")] = name;
    obj[QStringLiteral("backend")] = backend;
    return obj;
}

ComputeDevice ComputeDevice::fromJson(const QJsonObject &obj)
{
    ComputeDevice d;
    d.id = obj.value(QStringLiteral("id")).toInt();
    d.name = obj.value(QStringLiteral("name")).toString();
    d.backend = obj.value(QStringLiteral("backend")).toString();
    return d;
}

qint64 CrackingJob::runtimeMs() const
{
    if (!startedUtc.isValid() || !endedUtc.isValid())
        return 0;
    return startedUtc.msecsTo(endedUtc);
}

QJsonObject CrackingJob::toJson() const
{
    QJsonArray devArray;
    for (const ComputeDevice &d : devices)
        devArray.append(d.toJson());

    QJsonArray argsArray;
    for (const QString &a : hashcatArgs)
        argsArray.append(a);

    QJsonObject obj;
    obj[QStringLiteral("id")] = id.toString(QUuid::WithoutBraces);
    obj[QStringLiteral("caseId")] = caseId;
    obj[QStringLiteral("evidenceId")] = evidenceId.toString(QUuid::WithoutBraces);
    obj[QStringLiteral("hashMode")] = static_cast<double>(hashMode);
    obj[QStringLiteral("attackMode")] = attackMode;
    obj[QStringLiteral("hashcatArgs")] = argsArray;
    obj[QStringLiteral("hashcatPath")] = hashcatPath;
    obj[QStringLiteral("hashcatVersion")] = hashcatVersion;
    obj[QStringLiteral("devices")] = devArray;
    obj[QStringLiteral("startedUtc")] = jsonutil::fromDateTime(startedUtc);
    obj[QStringLiteral("endedUtc")] = jsonutil::fromDateTime(endedUtc);
    obj[QStringLiteral("state")] = jobStateToString(state);
    obj[QStringLiteral("result")] = result;
    return obj;
}

CrackingJob CrackingJob::fromJson(const QJsonObject &obj)
{
    CrackingJob j;
    j.id = QUuid::fromString(obj.value(QStringLiteral("id")).toString());
    j.caseId = obj.value(QStringLiteral("caseId")).toString();
    j.evidenceId = QUuid::fromString(obj.value(QStringLiteral("evidenceId")).toString());
    j.hashMode = static_cast<quint32>(obj.value(QStringLiteral("hashMode")).toDouble());
    j.attackMode = obj.value(QStringLiteral("attackMode")).toInt();
    for (const QJsonValue &v : obj.value(QStringLiteral("hashcatArgs")).toArray())
        j.hashcatArgs.append(v.toString());
    j.hashcatPath = obj.value(QStringLiteral("hashcatPath")).toString();
    j.hashcatVersion = obj.value(QStringLiteral("hashcatVersion")).toString();
    for (const QJsonValue &v : obj.value(QStringLiteral("devices")).toArray())
        j.devices.append(ComputeDevice::fromJson(v.toObject()));
    j.startedUtc = jsonutil::toDateTime(obj.value(QStringLiteral("startedUtc")).toString());
    j.endedUtc = jsonutil::toDateTime(obj.value(QStringLiteral("endedUtc")).toString());
    j.state = jobStateFromString(obj.value(QStringLiteral("state")).toString());
    j.result = obj.value(QStringLiteral("result")).toString();
    return j;
}

} // namespace forensic
