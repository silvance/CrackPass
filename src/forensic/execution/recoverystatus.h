/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 *
 * An engine-neutral progress snapshot shared by every recovery engine
 * (hashcat, John, bkcrack). It carries the information common to a running
 * recovery -- state, progress, speed, recovered count, ETA and any compute
 * devices -- so the queue and UI never depend on one engine's status format.
 *
 * Engine adapters populate only the fields they can supply: hashcat fills all
 * of them from its --status-json; John and bkcrack fill the state and whatever
 * progress/speed they can parse and leave the rest empty. The `state` is the
 * engine-neutral lifecycle signal; `nativeStatusCode` retains an engine's own
 * status code (e.g. hashcat's) for provenance and is 0 when not applicable --
 * John and bkcrack never invent a hashcat code.
 */
#ifndef FORENSIC_RECOVERYSTATUS_H
#define FORENSIC_RECOVERYSTATUS_H

#include <QString>
#include <QVector>

namespace forensic {

// Engine-neutral lifecycle state of a running recovery.
enum class RecoveryState {
    Unknown,
    Running,
    Paused,
    Exhausted, // finished the keyspace without recovering the target
    Recovered, // the target was recovered
    Aborted,   // stopped/aborted
    Quit,
};

struct RecoveryDeviceStatus
{
    int id = 0;
    QString name;
    qint64 speed = 0; // hashes/sec
};

struct RecoveryStatus
{
    bool valid = false;
    RecoveryState state = RecoveryState::Unknown;
    int nativeStatusCode = 0; // engine-native code (e.g. hashcat --status-json); 0 if N/A
    QString target;

    qint64 progressDone = 0;   // candidates tested
    qint64 progressTotal = 0;  // keyspace
    qint64 aggregateSpeed = 0; // summed device speed (H/s)

    int recoveredHashes = 0;
    int totalHashes = 0;

    qint64 timeStartEpoch = 0;
    qint64 estimatedStopEpoch = 0;

    QVector<RecoveryDeviceStatus> devices;

    // Percentage complete, or -1 when the keyspace/total is unknown (common for
    // John and bkcrack).
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

#endif // FORENSIC_RECOVERYSTATUS_H
