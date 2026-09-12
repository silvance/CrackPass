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

    // Build the reproducible job from a planned spec, enqueue it, and return its
    // id (null if no workspace is set). The initial record is persisted and, as
    // the queue runs it, state transitions and any recovered credential are
    // written to the case automatically.
    QUuid queueRecoveryJob(const AttackJobSpec &spec, const QUuid &evidenceId,
                           const QString &hashcatPath, const QString &hashcatVersion = QString());

    // Re-register the current case's persisted jobs into the queue (with their
    // session paths reconstructed) so they survive a reopen: resume/stop/report
    // can target them and a resumable job can be continued. Never auto-starts.
    void restoreJobs();

    // Exposed for reuse/testing.
    static CrackingJob buildJob(const AttackJobSpec &spec, const QString &caseId,
                                const QUuid &evidenceId, const QString &hashcatPath,
                                const QString &hashcatVersion);
    static JobQueue::JobPaths buildPaths(const QString &jobDir, const QUuid &jobId);

private:
    JobQueue *m_queue;
    CaseWorkspace *m_workspace = nullptr;
};

} // namespace forensic

#endif // FORENSIC_RECOVERYCONTROLLER_H
