/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#include "hashcatstatusparser.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

namespace forensic {

HashcatStatus HashcatStatusParser::parse(const QByteArray &jsonObject)
{
    HashcatStatus s;
    QJsonParseError err;
    const QJsonDocument doc = QJsonDocument::fromJson(jsonObject, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject())
        return s;

    const QJsonObject o = doc.object();
    // A status object always carries a numeric "status" and a "progress" array.
    if (!o.contains(QStringLiteral("status")) || !o.contains(QStringLiteral("progress")))
        return s;

    s.statusCode = o.value(QStringLiteral("status")).toInt();
    s.target = o.value(QStringLiteral("target")).toString();

    const QJsonArray progress = o.value(QStringLiteral("progress")).toArray();
    if (progress.size() >= 2) {
        s.progressDone = static_cast<qint64>(progress.at(0).toDouble());
        s.progressTotal = static_cast<qint64>(progress.at(1).toDouble());
    }

    const QJsonArray recovered = o.value(QStringLiteral("recovered_hashes")).toArray();
    if (recovered.size() >= 2) {
        s.recoveredHashes = recovered.at(0).toInt();
        s.totalHashes = recovered.at(1).toInt();
    }

    s.timeStartEpoch = static_cast<qint64>(o.value(QStringLiteral("time_start")).toDouble());
    s.estimatedStopEpoch = static_cast<qint64>(o.value(QStringLiteral("estimated_stop")).toDouble());

    const QJsonArray devices = o.value(QStringLiteral("devices")).toArray();
    for (const QJsonValue &dv : devices) {
        const QJsonObject d = dv.toObject();
        HashcatDeviceStatus dev;
        dev.id = d.value(QStringLiteral("device_id")).toInt();
        dev.name = d.value(QStringLiteral("device_name")).toString();
        dev.speed = static_cast<qint64>(d.value(QStringLiteral("speed")).toDouble());
        s.devices.append(dev);
        s.aggregateSpeed += dev.speed;
    }

    s.valid = true;
    return s;
}

HashcatStatus HashcatStatusParser::parseLatest(const QByteArray &stdoutChunk)
{
    HashcatStatus latest;
    const QList<QByteArray> lines = stdoutChunk.split('\n');
    for (const QByteArray &line : lines) {
        const QByteArray trimmed = line.trimmed();
        if (!trimmed.startsWith('{'))
            continue;
        const HashcatStatus s = parse(trimmed);
        if (s.valid)
            latest = s;
    }
    return latest;
}

} // namespace forensic
