/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef FORENSIC_JOBQUEUE_H
#define FORENSIC_JOBQUEUE_H

#include "forensic/crackingjob.h"
#include "forensic/recoveredcredential.h"
#include "hashcatstatus.h"
#include "jobexecutionbackend.h"
#include <QHash>
#include <QList>
#include <QObject>
#include <QUuid>

namespace forensic {

/*
 * Serial job queue and state machine. It owns the ordered list of jobs, starts
 * them one at a time through a JobExecutionBackend, and maps backend events to
 * the forensic job states. It never auto-starts anything that was not
 * explicitly enqueued by the examiner.
 *
 * Persistence and case wiring live in the owner (which reacts to the signals);
 * the queue itself is pure state so it is unit-testable with a fake backend.
 */
class JobQueue : public QObject
{
    Q_OBJECT

public:
    // Paths the backend needs for a job; provided by the owner (case dirs).
    struct JobPaths {
        QString workingDir;
        QString sessionName;
        QString potfilePath;
        QString outfilePath;
        QString restorePath;
    };

    // `backend` is the default engine's backend (used for jobs whose engineId is
    // unregistered or empty, e.g. legacy hashcat jobs).
    explicit JobQueue(JobExecutionBackend *backend, QObject *parent = nullptr);

    // Register an additional engine's backend. A job is dispatched to the
    // backend registered under its engineId, falling back to the default.
    void registerBackend(const QString &engineId, JobExecutionBackend *backend);

    // Enqueue a job (state Pending) with the paths the backend should use.
    QUuid enqueue(const CrackingJob &job, const JobPaths &paths);

    // Register a job persisted in a prior session WITHOUT starting it, so it is
    // known to the queue (resume/stop/report can target it) after a case is
    // reopened. A job that was mid-run when the app closed (Running/Preparing/
    // Pending) is normalized to Paused so the examiner can explicitly resume it;
    // terminal states are kept as history. Never auto-starts.
    void restore(const CrackingJob &job, const JobPaths &paths);

    void pause(const QUuid &jobId);
    void resume(const QUuid &jobId);
    void stop(const QUuid &jobId);

    QList<CrackingJob> jobs() const { return m_jobs; }
    bool hasJob(const QUuid &id) const { return indexOf(id) >= 0; }
    CrackingJob jobById(const QUuid &id) const;
    HashcatStatus lastStatus(const QUuid &id) const { return m_status.value(id); }

signals:
    void jobChanged(const forensic::CrackingJob &job);
    void jobStatus(const QUuid &jobId, const forensic::HashcatStatus &status);
    void credentialRecovered(const forensic::RecoveredCredential &cred);

private slots:
    void onRunning(const QUuid &jobId);
    void onStatus(const QUuid &jobId, const forensic::HashcatStatus &status);
    void onCracked(const QUuid &jobId, const QString &hash, const QByteArray &rawPlaintext);
    void onPaused(const QUuid &jobId);
    void onStopped(const QUuid &jobId);
    void onFinished(const QUuid &jobId, int exitCode, int hashcatStatusCode);
    void onFailed(const QUuid &jobId, const QString &error);

private:
    int indexOf(const QUuid &id) const;
    void setState(const QUuid &id, JobState state);
    JobExecutionBackend::StartOptions optionsFor(const QUuid &id, bool restore) const;
    void connectBackend(JobExecutionBackend *backend);
    JobExecutionBackend *backendFor(const QUuid &id) const;
    void tryStartNext();
    void releaseAndAdvance(const QUuid &finishedId);

    JobExecutionBackend *m_backend; // default engine backend
    QHash<QString, JobExecutionBackend *> m_backends; // engineId -> backend
    QList<CrackingJob> m_jobs;
    QHash<QUuid, JobPaths> m_paths;
    QHash<QUuid, HashcatStatus> m_status;
    QHash<QUuid, bool> m_recoveredFlag; // a credential arrived for this job
    QUuid m_running;                    // currently executing job (null if idle)
};

} // namespace forensic

#endif // FORENSIC_JOBQUEUE_H
