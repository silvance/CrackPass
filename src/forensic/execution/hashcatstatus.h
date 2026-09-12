/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef FORENSIC_HASHCATSTATUS_H
#define FORENSIC_HASHCATSTATUS_H

#include <QString>
#include <QVector>

namespace forensic {

// hashcat status codes (from its --status-json "status" field).
namespace HashcatStatusCode {
constexpr int Running = 3;
constexpr int Paused = 4;
constexpr int Exhausted = 5;
constexpr int Cracked = 6;
constexpr int Aborted = 7;
constexpr int Quit = 8;
}

struct HashcatDeviceStatus
{
    int id = 0;
    QString name;
    qint64 speed = 0; // hashes/sec
};

/*
 * A parsed hashcat --status-json snapshot. Machine-readable throughout; no
 * human-readable terminal scraping.
 */
struct HashcatStatus
{
    bool valid = false;
    int statusCode = 0;
    QString target;

    qint64 progressDone = 0;   // candidates tested
    qint64 progressTotal = 0;  // keyspace
    qint64 aggregateSpeed = 0; // summed device speed (H/s)

    int recoveredHashes = 0;
    int totalHashes = 0;

    qint64 timeStartEpoch = 0;
    qint64 estimatedStopEpoch = 0;

    QVector<HashcatDeviceStatus> devices;

    double progressPercent() const
    {
        if (progressTotal <= 0)
            return -1.0;
        return (static_cast<double>(progressDone) / static_cast<double>(progressTotal)) * 100.0;
    }

    // Seconds remaining relative to a supplied "now" epoch (-1 if unknown).
    qint64 remainingSeconds(qint64 nowEpoch) const
    {
        if (estimatedStopEpoch <= 0 || nowEpoch <= 0)
            return -1;
        const qint64 r = estimatedStopEpoch - nowEpoch;
        return r > 0 ? r : 0;
    }
};

} // namespace forensic

#endif // FORENSIC_HASHCATSTATUS_H
