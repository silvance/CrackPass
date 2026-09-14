/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "recoverycontroller.h"

#include "forensic/caseworkspace.h"
#include "forensic/bkcrack/bkcrackcommandbuilder.h"
#include "forensic/hashingservice.h"

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
        if (!m_workspace)
            return;
        // Runtime state persistence: a failure here must not corrupt the queue
        // (the job keeps running); it is surfaced separately for the examiner.
        QString err;
        if (!m_workspace->saveJob(job, &err))
            emit jobPersistenceFailed(job, err);
    });
    connect(m_queue, &JobQueue::credentialRecovered, this, [this](const RecoveredCredential &cred) {
        if (m_workspace)
            m_workspace->addRecoveredCredential(cred);
    });
}

CrackingJob RecoveryController::buildJob(const RecoveryEngine &engine, const AttackJobSpec &spec,
                                         const QString &caseId, const QUuid &evidenceId,
                                         const QString &toolPath, const QString &toolVersion)
{
    CrackingJob job;
    job.id = QUuid::createUuid();
    job.caseId = caseId;
    job.evidenceId = evidenceId;
    job.hashMode = spec.hashMode;
    job.attackMode = spec.attackMode;
    job.engineId = engine.id();
    job.engineDisplayName = engine.displayName();
    job.enginePath = toolPath;
    job.engineVersion = toolVersion;
    job.engineExeSha256 = HashingService::sha256File(toolPath); // best-effort (empty if unreadable)
    job.engineArgs = engine.buildArgs(spec);
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
                                           const QString &toolPath, const QString &toolVersion,
                                           const QString &engineId,
                                           const DictionaryProvenance &dictionary)
{
    if (!m_workspace) {
        emit recoveryRefused(tr("No case is open."));
        return QUuid();
    }
    const RecoveryEngine *engine = m_engines.find(engineId);
    if (!engine) {
        emit recoveryRefused(tr("Unknown recovery engine \"%1\".").arg(engineId));
        return QUuid(); // unknown engine: refuse rather than run the wrong tool
    }
    // Refuse an attack the engine cannot express exactly rather than run an
    // approximation that would not match what the examiner planned.
    const QString unsupported = engine->unsupportedReason(spec);
    if (!unsupported.isEmpty()) {
        emit recoveryRefused(tr("%1 cannot run this attack: %2")
                                 .arg(engine->displayName(), unsupported));
        return QUuid();
    }

    CrackingJob job = buildJob(*engine, spec, m_workspace->info().id, evidenceId,
                               toolPath, toolVersion);
    job.dictionary = dictionary; // provenance of the managed dictionary, if any
    return persistThenEnqueue(job);
}

QUuid RecoveryController::queueBkcrackJob(const BkcrackAttackSpec &spec, const QUuid &evidenceId,
                                          const QString &toolPath, const QString &toolVersion)
{
    if (!m_workspace) {
        emit recoveryRefused(tr("No case is open."));
        return QUuid();
    }
    const BkcrackBuildResult built = BkcrackCommandBuilder::build(spec);
    if (!built.valid) {
        emit recoveryRefused(tr("bkcrack cannot run this attack: %1").arg(built.error));
        return QUuid();
    }

    CrackingJob job;
    job.id = QUuid::createUuid();
    job.caseId = m_workspace->info().id;
    job.evidenceId = evidenceId;
    job.engineId = QStringLiteral("bkcrack");
    job.engineDisplayName = QStringLiteral("bkcrack");
    job.enginePath = toolPath;     // the resolved bkcrack binary
    job.engineVersion = toolVersion;
    job.engineExeSha256 = HashingService::sha256File(toolPath); // best-effort
    job.engineArgs = built.args;   // the bkcrack argv
    job.hashFile = spec.zipPath;   // the archive under attack, for reference/reporting

    return persistThenEnqueue(job);
}

bool RecoveryController::persistNewJob(const CrackingJob &job)
{
    if (!m_workspace)
        return false;
    return m_workspace->saveJob(job); // atomic write + job_created audit entry
}

QUuid RecoveryController::persistThenEnqueue(const CrackingJob &job)
{
    // Invariant: a new job must be persisted + audited BEFORE its engine starts,
    // so a persistence failure never leaves a running process without a case
    // record. Build -> persist/audit -> enqueue -> execute. On failure: no
    // launch, no phantom in-memory job, examiner told why.
    const QString jobDir = m_workspace->jobDir(job.id);
    QDir().mkpath(jobDir);
    if (!persistNewJob(job)) {
        emit recoveryRefused(tr("The job could not be saved to the case, so it was "
                                "not started."));
        return QUuid();
    }
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
