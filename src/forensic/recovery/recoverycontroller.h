/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 *
 * The one place that turns a planned attack into a running, persisted recovery
 * job. Building the reproducible CrackingJob, laying out its per-job session
 * files, enqueuing it, and writing job-state transitions and recovered
 * credentials back to the case were previously duplicated between the GUI and
 * the integration harness -- so they could drift. RecoveryController owns that
 * flow once; the UI and tests drive recovery through it and only add display on
 * top. It deliberately does not probe tools or spawn processes (that is the
 * backend's and ToolchainService's job); the hashcat path and version are
 * supplied by the caller so the recorded provenance is explicit.
 */
#ifndef FORENSIC_RECOVERYCONTROLLER_H
#define FORENSIC_RECOVERYCONTROLLER_H

#include "forensic/crackingjob.h"
#include "forensic/execution/jobqueue.h"
#include "forensic/planner/attackjobspec.h"
#include "forensic/bkcrack/bkcrackattackspec.h"
#include "recoveryengine.h"
#include "recoveryengineregistry.h"

#include <QObject>
#include <QString>
#include <QUuid>

namespace forensic {

class CaseWorkspace;

class RecoveryController : public QObject
{
    Q_OBJECT

public:
    // The workspace may be set later (the GUI opens a case after construction).
    explicit RecoveryController(JobQueue *queue, QObject *parent = nullptr);

    void setWorkspace(CaseWorkspace *workspace) { m_workspace = workspace; }
    CaseWorkspace *workspace() const { return m_workspace; }

    // Replace the set of known engines (defaults to the built-ins).
    void setEngines(RecoveryEngineRegistry engines) { m_engines = std::move(engines); }
    const RecoveryEngineRegistry &engines() const { return m_engines; }

    // Build the reproducible job from a planned spec, enqueue it, and return its
    // id. Returns a null id -- and emits recoveryRefused with the reason -- when
    // no workspace is set, the engineId is unknown, or the chosen engine cannot
    // express the attack exactly (it is refused rather than approximated).
    // `engineId` selects the recovery engine (default hashcat);
    // `toolPath`/`toolVersion` record the resolved binary for provenance. As the
    // queue runs the job, state transitions and any recovered credential are
    // written to the case.
    // `extractionId` binds the job to the exact Extraction whose hash it attacks
    // (null when the attack does not come from a *2john extraction).
    QUuid queueRecoveryJob(const AttackJobSpec &spec, const QUuid &evidenceId,
                           const QString &toolPath, const QString &toolVersion = QString(),
                           const QString &engineId = RecoveryEngineRegistry::defaultEngineId(),
                           const DictionaryProvenance &dictionary = DictionaryProvenance{},
                           const QUuid &extractionId = QUuid());

    // Build and enqueue a bkcrack (ZipCrypto known-plaintext) job from its own
    // spec, returning its id. bkcrack does not fit the hashcat-shaped
    // AttackJobSpec, so it has a dedicated path here. Returns a null id -- and
    // emits recoveryRefused with the reason -- when no workspace is set or the
    // spec cannot be turned into a bkcrack command (see BkcrackCommandBuilder).
    // `toolPath`/`toolVersion` record the resolved bkcrack binary for provenance.
    QUuid queueBkcrackJob(const BkcrackAttackSpec &spec, const QUuid &evidenceId,
                          const QString &toolPath, const QString &toolVersion = QString());

    // Re-register the current case's persisted jobs into the queue (with their
    // session paths reconstructed) so they survive a reopen: resume/stop/report
    // can target them and a resumable job can be continued. Never auto-starts.
    void restoreJobs();

    // Exposed for reuse/testing. The engine supplies the job's engineId and argv.
    static CrackingJob buildJob(const RecoveryEngine &engine, const AttackJobSpec &spec,
                                const QString &caseId, const QUuid &evidenceId,
                                const QString &toolPath, const QString &toolVersion,
                                const QUuid &extractionId = QUuid());
    static JobQueue::JobPaths buildPaths(const QString &jobDir, const QUuid &jobId);

signals:
    // Emitted when a queue request is declined (no case, unknown engine, an
    // engine that cannot express the attack, or the initial persistence failed
    // so nothing was started). The UI shows the reason to the examiner.
    void recoveryRefused(const QString &reason);

    // Emitted when persisting a RUNNING job's state transition failed. The job
    // keeps running (the queue is not corrupted); the examiner is warned that
    // the on-disk record may be stale.
    void jobPersistenceFailed(const forensic::CrackingJob &job, const QString &error);

    // Emitted when a credential was recovered by the engine but could NOT be
    // recorded to the case (the transactional write was refused). Recovery
    // genuinely succeeded and the in-memory result is still delivered for
    // display via JobQueue::credentialRecovered, so it is NOT discarded -- but
    // the case does NOT contain it, and the examiner must be told plainly so
    // they never assume it was saved. `error` is a filesystem-level reason and
    // never contains the recovered plaintext/key.
    void credentialPersistenceFailed(const forensic::RecoveredCredential &cred,
                                     const QString &error);

protected:
    // Persist a freshly built job (atomic write + job_created audit) before it is
    // enqueued. Virtual so tests can inject a persistence failure.
    virtual bool persistNewJob(const CrackingJob &job);

private:
    // Persist the job, then enqueue it (which starts it); refuse if persistence
    // fails. Shared by queueRecoveryJob and queueBkcrackJob.
    QUuid persistThenEnqueue(const CrackingJob &job);

    JobQueue *m_queue;
    CaseWorkspace *m_workspace = nullptr;
    RecoveryEngineRegistry m_engines = RecoveryEngineRegistry::withBuiltins();
};

} // namespace forensic

#endif // FORENSIC_RECOVERYCONTROLLER_H
