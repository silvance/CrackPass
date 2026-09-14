/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
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

// Lifecycle of a cracking job in the queue.
enum class JobState {
    Pending,    // queued, not yet started
    Preparing,  // process starting / building inputs
    Running,    // hashcat actively working
    Paused,     // paused by the examiner (resumable)
    Exhausted,  // keyspace finished without recovering the target
    Recovered,  // the target credential was recovered
    Stopped,    // stopped/aborted by the examiner
    Failed,     // error (tool missing, crash, bad args)
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

    // Which recovery engine ran (or will run) this job, e.g. "hashcat", "john"
    // or "bkcrack". Recorded for provenance and used to route the job to its
    // backend. `engineDisplayName` is the human-readable name for reports.
    QString engineId;
    QString engineDisplayName;

    // Engine-neutral provenance: the exact argv, resolved executable, version
    // banner and (best-effort) SHA-256 of the executable that ran this job.
    // These were named hashcat* when hashcat was the only engine; old case
    // records using those names still load (see fromJson).
    QStringList engineArgs;    // exact argv passed to the engine
    QString enginePath;        // resolved executable
    QString engineVersion;     // version / banner
    QString engineExeSha256;   // lowercase hex SHA-256 of the executable, if known

    QString hashFile;          // extracted-hash file being attacked
    QStringList wordlists;     // wordlists used (for reporting)
    QStringList rules;         // rule files used
    QString mask;              // mask used (a=3/6/7)
    QVector<ComputeDevice> devices;

    QDateTime startedUtc;
    QDateTime endedUtc;
    JobState state = JobState::Pending;
    QString result;            // human-readable outcome summary

    qint64 runtimeMs() const;

    QJsonObject toJson() const;
    static CrackingJob fromJson(const QJsonObject &obj);
};

} // namespace forensic

#endif // FORENSIC_CRACKINGJOB_H
