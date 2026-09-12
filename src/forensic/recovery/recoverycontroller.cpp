/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "recoverycontroller.h"

#include "forensic/caseworkspace.h"
#include "forensic/planner/attackcommandbuilder.h"

#include <QDir>

namespace forensic {

RecoveryController::RecoveryController(JobQueue *queue, QObject *parent)
    : QObject(parent)
    , m_queue(queue)
{
    // Persistence side of the recovery flow: every job-state transition and
    // recovered credential is written to the current case. Display is layered on
    // separately by whoever also connects to these signals.
    connect(m_queue, &JobQueue::jobChanged, this, [this](const CrackingJob &job) {
        if (m_workspace)
            m_workspace->saveJob(job);
    });
    connect(m_queue, &JobQueue::credentialRecovered, this, [this](const RecoveredCredential &cred) {
        if (m_workspace)
            m_workspace->addRecoveredCredential(cred);
    });
}

CrackingJob RecoveryController::buildJob(const AttackJobSpec &spec, const QString &caseId,
                                         const QUuid &evidenceId, const QString &hashcatPath,
                                         const QString &hashcatVersion)
{
    CrackingJob job;
    job.id = QUuid::createUuid();
    job.caseId = caseId;
    job.evidenceId = evidenceId;
    job.hashMode = spec.hashMode;
    job.attackMode = spec.attackMode;
    job.hashcatPath = hashcatPath;
    job.hashcatVersion = hashcatVersion;
    job.hashcatArgs = AttackCommandBuilder::buildArgs(spec);
    job.hashFile = spec.hashFile;
    job.wordlists = spec.wordlists;
    job.rules = spec.rules;
    job.mask = spec.mask;
    return job;
}

JobQueue::JobPaths RecoveryController::buildPaths(const QString &jobDir, const QUuid &jobId)
{
    JobQueue::JobPaths paths;
    paths.workingDir = jobDir;
    paths.sessionName = QStringLiteral("cp-") + jobId.toString(QUuid::WithoutBraces).left(8);
    paths.potfilePath = QDir(jobDir).filePath(QStringLiteral("job.potfile"));
    paths.outfilePath = QDir(jobDir).filePath(QStringLiteral("cracked.out"));
    paths.restorePath = QDir(jobDir).filePath(QStringLiteral("session.restore"));
    return paths;
}

QUuid RecoveryController::queueRecoveryJob(const AttackJobSpec &spec, const QUuid &evidenceId,
                                           const QString &hashcatPath, const QString &hashcatVersion)
{
    if (!m_workspace)
        return QUuid();

    const CrackingJob job = buildJob(spec, m_workspace->info().id, evidenceId,
                                     hashcatPath, hashcatVersion);
    const QString jobDir = m_workspace->jobDir(job.id);
    QDir().mkpath(jobDir);
    return m_queue->enqueue(job, buildPaths(jobDir, job.id));
}

void RecoveryController::restoreJobs()
{
    if (!m_workspace)
        return;
    for (const CrackingJob &job : m_workspace->jobs())
        m_queue->restore(job, buildPaths(m_workspace->jobDir(job.id), job.id));
}

} // namespace forensic
