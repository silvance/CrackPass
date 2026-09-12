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
    // id (null if no workspace is set, or the engineId is unknown). `engineId`
    // selects the recovery engine (default hashcat); `toolPath`/`toolVersion`
    // record the resolved binary for provenance. As the queue runs the job,
    // state transitions and any recovered credential are written to the case.
    QUuid queueRecoveryJob(const AttackJobSpec &spec, const QUuid &evidenceId,
                           const QString &toolPath, const QString &toolVersion = QString(),
                           const QString &engineId = RecoveryEngineRegistry::defaultEngineId());

    // Re-register the current case's persisted jobs into the queue (with their
    // session paths reconstructed) so they survive a reopen: resume/stop/report
    // can target them and a resumable job can be continued. Never auto-starts.
    void restoreJobs();

    // Exposed for reuse/testing. The engine supplies the job's engineId and argv.
    static CrackingJob buildJob(const RecoveryEngine &engine, const AttackJobSpec &spec,
                                const QString &caseId, const QUuid &evidenceId,
                                const QString &toolPath, const QString &toolVersion);
    static JobQueue::JobPaths buildPaths(const QString &jobDir, const QUuid &jobId);

private:
    JobQueue *m_queue;
    CaseWorkspace *m_workspace = nullptr;
    RecoveryEngineRegistry m_engines = RecoveryEngineRegistry::withBuiltins();
};

} // namespace forensic

#endif // FORENSIC_RECOVERYCONTROLLER_H
