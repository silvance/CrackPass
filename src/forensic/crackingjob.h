/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#ifndef FORENSIC_CRACKINGJOB_H
#define FORENSIC_CRACKINGJOB_H

#include <QDateTime>
#include <QJsonObject>
#include <QString>
#include <QStringList>
#include <QUuid>
#include <QVector>

namespace forensic {

enum class JobState {
    Created,
    Queued,
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled,
};

QString jobStateToString(JobState state);
JobState jobStateFromString(const QString &s);

// Snapshot of a compute device recorded at job time (for reproducibility).
struct ComputeDevice
{
    int id = 0;
    QString name;
    QString backend; // e.g. "CUDA"
    QJsonObject toJson() const;
    static ComputeDevice fromJson(const QJsonObject &obj);
};

/*
 * A reproducible record of a hashcat run. In the foundation stage this is a
 * data model only: no execution takes place. It captures everything needed to
 * reproduce and audit a run: exact arguments, hashcat version, detected
 * devices, timing, attack type and result.
 */
struct CrackingJob
{
    QUuid id;
    QString caseId;
    QUuid evidenceId;

    quint32 hashMode = 0;
    int attackMode = 0;

    QStringList hashcatArgs;   // exact argv passed to hashcat
    QString hashcatPath;
    QString hashcatVersion;
    QVector<ComputeDevice> devices;

    QDateTime startedUtc;
    QDateTime endedUtc;
    JobState state = JobState::Created;
    QString result;            // human-readable outcome summary

    qint64 runtimeMs() const;

    QJsonObject toJson() const;
    static CrackingJob fromJson(const QJsonObject &obj);
};

} // namespace forensic

#endif // FORENSIC_CRACKINGJOB_H
