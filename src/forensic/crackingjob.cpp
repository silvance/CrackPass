/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "crackingjob.h"
#include "jsonutil.h"

#include <QJsonArray>

namespace forensic {

QString jobStateToString(JobState state)
{
    switch (state) {
    case JobState::Pending:   return QStringLiteral("pending");
    case JobState::Preparing: return QStringLiteral("preparing");
    case JobState::Running:   return QStringLiteral("running");
    case JobState::Paused:    return QStringLiteral("paused");
    case JobState::Exhausted: return QStringLiteral("exhausted");
    case JobState::Recovered: return QStringLiteral("recovered");
    case JobState::Stopped:   return QStringLiteral("stopped");
    case JobState::Failed:    return QStringLiteral("failed");
    }
    return QStringLiteral("pending");
}

JobState jobStateFromString(const QString &s)
{
    if (s == QStringLiteral("preparing")) return JobState::Preparing;
    if (s == QStringLiteral("running"))   return JobState::Running;
    if (s == QStringLiteral("paused"))    return JobState::Paused;
    if (s == QStringLiteral("exhausted")) return JobState::Exhausted;
    if (s == QStringLiteral("recovered")) return JobState::Recovered;
    if (s == QStringLiteral("stopped"))   return JobState::Stopped;
    if (s == QStringLiteral("failed"))    return JobState::Failed;
    return JobState::Pending;
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
    for (const QString &a : engineArgs)
        argsArray.append(a);

    QJsonObject obj;
    obj[QStringLiteral("id")] = id.toString(QUuid::WithoutBraces);
    obj[QStringLiteral("caseId")] = caseId;
    obj[QStringLiteral("evidenceId")] = evidenceId.toString(QUuid::WithoutBraces);
    obj[QStringLiteral("hashMode")] = static_cast<double>(hashMode);
    obj[QStringLiteral("attackMode")] = attackMode;
    obj[QStringLiteral("engineId")] = engineId;
    obj[QStringLiteral("engineDisplayName")] = engineDisplayName;
    // Engine-neutral field names (records written before the migration used the
    // hashcat* names; fromJson still reads those).
    obj[QStringLiteral("engineArgs")] = argsArray;
    obj[QStringLiteral("enginePath")] = enginePath;
    obj[QStringLiteral("engineVersion")] = engineVersion;
    obj[QStringLiteral("engineExeSha256")] = engineExeSha256;
    obj[QStringLiteral("hashFile")] = hashFile;
    obj[QStringLiteral("mask")] = mask;
    { QJsonArray a; for (const QString &w : wordlists) a.append(w); obj[QStringLiteral("wordlists")] = a; }
    { QJsonArray a; for (const QString &r : rules) a.append(r); obj[QStringLiteral("rules")] = a; }
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
    // Records written before engines were pluggable are hashcat jobs.
    j.engineId = obj.value(QStringLiteral("engineId")).toString();
    if (j.engineId.isEmpty())
        j.engineId = QStringLiteral("hashcat");
    j.engineDisplayName = obj.value(QStringLiteral("engineDisplayName")).toString();
    // Engine-neutral names first; fall back to the legacy hashcat* names so
    // cases written before the migration still load with full provenance.
    const QJsonValue argsVal = obj.contains(QStringLiteral("engineArgs"))
        ? obj.value(QStringLiteral("engineArgs"))
        : obj.value(QStringLiteral("hashcatArgs"));
    for (const QJsonValue &v : argsVal.toArray())
        j.engineArgs.append(v.toString());
    j.enginePath = obj.contains(QStringLiteral("enginePath"))
        ? obj.value(QStringLiteral("enginePath")).toString()
        : obj.value(QStringLiteral("hashcatPath")).toString();
    j.engineVersion = obj.contains(QStringLiteral("engineVersion"))
        ? obj.value(QStringLiteral("engineVersion")).toString()
        : obj.value(QStringLiteral("hashcatVersion")).toString();
    j.engineExeSha256 = obj.value(QStringLiteral("engineExeSha256")).toString();
    j.hashFile = obj.value(QStringLiteral("hashFile")).toString();
    j.mask = obj.value(QStringLiteral("mask")).toString();
    for (const QJsonValue &v : obj.value(QStringLiteral("wordlists")).toArray()) j.wordlists.append(v.toString());
    for (const QJsonValue &v : obj.value(QStringLiteral("rules")).toArray()) j.rules.append(v.toString());
    for (const QJsonValue &v : obj.value(QStringLiteral("devices")).toArray())
        j.devices.append(ComputeDevice::fromJson(v.toObject()));
    j.startedUtc = jsonutil::toDateTime(obj.value(QStringLiteral("startedUtc")).toString());
    j.endedUtc = jsonutil::toDateTime(obj.value(QStringLiteral("endedUtc")).toString());
    j.state = jobStateFromString(obj.value(QStringLiteral("state")).toString());
    j.result = obj.value(QStringLiteral("result")).toString();
    return j;
}

} // namespace forensic
