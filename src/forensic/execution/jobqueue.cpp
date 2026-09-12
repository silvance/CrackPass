/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#include "jobqueue.h"

#include <QDateTime>

namespace forensic {

JobQueue::JobQueue(JobExecutionBackend *backend, QObject *parent)
    : QObject(parent)
    , m_backend(backend)
{
    connect(m_backend, &JobExecutionBackend::running, this, &JobQueue::onRunning);
    connect(m_backend, &JobExecutionBackend::statusUpdated, this, &JobQueue::onStatus);
    connect(m_backend, &JobExecutionBackend::cracked, this, &JobQueue::onCracked);
    connect(m_backend, &JobExecutionBackend::paused, this, &JobQueue::onPaused);
    connect(m_backend, &JobExecutionBackend::stopped, this, &JobQueue::onStopped);
    connect(m_backend, &JobExecutionBackend::finished, this, &JobQueue::onFinished);
    connect(m_backend, &JobExecutionBackend::failed, this, &JobQueue::onFailed);
}

int JobQueue::indexOf(const QUuid &id) const
{
    for (int i = 0; i < m_jobs.size(); ++i)
        if (m_jobs.at(i).id == id)
            return i;
    return -1;
}

CrackingJob JobQueue::jobById(const QUuid &id) const
{
    const int i = indexOf(id);
    return i >= 0 ? m_jobs.at(i) : CrackingJob{};
}

void JobQueue::setState(const QUuid &id, JobState state)
{
    const int i = indexOf(id);
    if (i < 0)
        return;
    m_jobs[i].state = state;
    emit jobChanged(m_jobs.at(i));
}

QUuid JobQueue::enqueue(const CrackingJob &job, const JobPaths &paths)
{
    CrackingJob j = job;
    if (j.id.isNull())
        j.id = QUuid::createUuid();
    j.state = JobState::Pending;
    m_jobs.append(j);
    m_paths.insert(j.id, paths);
    emit jobChanged(j);
    tryStartNext();
    return j.id;
}

void JobQueue::tryStartNext()
{
    if (!m_running.isNull())
        return; // serial: one running job at a time
    for (int i = 0; i < m_jobs.size(); ++i) {
        if (m_jobs.at(i).state == JobState::Pending) {
            const QUuid id = m_jobs.at(i).id;
            m_running = id;
            m_jobs[i].startedUtc = QDateTime::currentDateTimeUtc();
            setState(id, JobState::Preparing);

            const JobPaths p = m_paths.value(id);
            JobExecutionBackend::StartOptions opts;
            opts.workingDir = p.workingDir;
            opts.sessionName = p.sessionName;
            opts.potfilePath = p.potfilePath;
            opts.outfilePath = p.outfilePath;
            opts.restorePath = p.restorePath;
            opts.restore = false;
            m_backend->start(m_jobs.at(i), opts);
            return;
        }
    }
}

void JobQueue::releaseAndAdvance(const QUuid &finishedId)
{
    const int i = indexOf(finishedId);
    if (i >= 0)
        m_jobs[i].endedUtc = QDateTime::currentDateTimeUtc();
    if (m_running == finishedId)
        m_running = QUuid();
    tryStartNext();
}

void JobQueue::onRunning(const QUuid &jobId)
{
    setState(jobId, JobState::Running);
}

void JobQueue::onStatus(const QUuid &jobId, const HashcatStatus &status)
{
    m_status.insert(jobId, status);
    // First status is a good point to guarantee the Running state.
    const int i = indexOf(jobId);
    if (i >= 0 && m_jobs.at(i).state == JobState::Preparing)
        setState(jobId, JobState::Running);
    emit jobStatus(jobId, status);
}

void JobQueue::onCracked(const QUuid &jobId, const QString &hash, const QString &plaintext)
{
    const int i = indexOf(jobId);
    if (i < 0)
        return;
    m_recoveredFlag.insert(jobId, true);

    RecoveredCredential cred;
    cred.id = QUuid::createUuid();
    cred.caseId = m_jobs.at(i).caseId;
    cred.jobId = jobId;
    cred.evidenceId = m_jobs.at(i).evidenceId;
    cred.hash = hash;
    cred.plaintext = plaintext;
    cred.recoveredUtc = QDateTime::currentDateTimeUtc();
    emit credentialRecovered(cred);

    // Show recovery immediately, even before the process exits.
    setState(jobId, JobState::Recovered);
}

void JobQueue::onPaused(const QUuid &jobId)
{
    setState(jobId, JobState::Paused);
    releaseAndAdvance(jobId); // GPU is free; another job may run
}

void JobQueue::onStopped(const QUuid &jobId)
{
    setState(jobId, JobState::Stopped);
    releaseAndAdvance(jobId);
}

void JobQueue::onFinished(const QUuid &jobId, int exitCode, int hashcatStatusCode)
{
    const bool recovered = m_recoveredFlag.value(jobId, false);
    JobState state;
    if (recovered || hashcatStatusCode == HashcatStatusCode::Cracked) {
        state = JobState::Recovered;
    } else if (hashcatStatusCode == HashcatStatusCode::Exhausted || exitCode == 1) {
        state = JobState::Exhausted;
    } else if (hashcatStatusCode == HashcatStatusCode::Aborted
               || hashcatStatusCode == HashcatStatusCode::Quit || exitCode == 2) {
        state = JobState::Stopped;
    } else if (exitCode == 0) {
        state = recovered ? JobState::Recovered : JobState::Exhausted;
    } else {
        state = JobState::Failed;
    }
    setState(jobId, state);
    releaseAndAdvance(jobId);
}

void JobQueue::onFailed(const QUuid &jobId, const QString &error)
{
    const int i = indexOf(jobId);
    if (i >= 0)
        m_jobs[i].result = error;
    setState(jobId, JobState::Failed);
    releaseAndAdvance(jobId);
}

void JobQueue::pause(const QUuid &jobId)
{
    if (indexOf(jobId) >= 0 && m_running == jobId)
        m_backend->pause(jobId);
}

void JobQueue::resume(const QUuid &jobId)
{
    const int i = indexOf(jobId);
    if (i < 0 || m_jobs.at(i).state != JobState::Paused)
        return;
    if (!m_running.isNull())
        return; // wait until the queue is free
    m_running = jobId;
    setState(jobId, JobState::Preparing);
    const JobPaths p = m_paths.value(jobId);
    JobExecutionBackend::StartOptions opts;
    opts.workingDir = p.workingDir;
    opts.sessionName = p.sessionName;
    opts.potfilePath = p.potfilePath;
    opts.outfilePath = p.outfilePath;
    opts.restorePath = p.restorePath;
    opts.restore = true;
    m_backend->resume(jobId);
}

void JobQueue::stop(const QUuid &jobId)
{
    const int i = indexOf(jobId);
    if (i < 0)
        return;
    if (m_running == jobId) {
        m_backend->stop(jobId);
    } else if (m_jobs.at(i).state == JobState::Pending || m_jobs.at(i).state == JobState::Paused) {
        setState(jobId, JobState::Stopped);
    }
}

} // namespace forensic
