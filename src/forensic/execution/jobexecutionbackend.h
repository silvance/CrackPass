/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef FORENSIC_JOBEXECUTIONBACKEND_H
#define FORENSIC_JOBEXECUTIONBACKEND_H

#include "forensic/crackingjob.h"
#include "hashcatstatus.h"
#include <QObject>
#include <QString>
#include <QUuid>

namespace forensic {

/*
 * Abstraction over actually running a hashcat job. The JobQueue drives the
 * lifecycle through this interface and reacts to its signals, so the queue's
 * state machine is testable with a fake backend (no hashcat, no GPU).
 *
 * Pause/resume/stop are modeled on hashcat's supported --session/--restore
 * mechanism: pause and stop end the process while preserving the restore file;
 * resume relaunches with --restore.
 */
class JobExecutionBackend : public QObject
{
    Q_OBJECT

public:
    struct StartOptions {
        QString workingDir;
        QString sessionName;
        QString potfilePath;
        QString outfilePath;
        QString restorePath;
        bool restore = false; // true => resume an existing session
    };

    explicit JobExecutionBackend(QObject *parent = nullptr) : QObject(parent) {}

    virtual void start(const CrackingJob &job, const StartOptions &opts) = 0;
    virtual void pause(const QUuid &jobId) = 0;
    virtual void resume(const QUuid &jobId) = 0;
    virtual void stop(const QUuid &jobId) = 0;

signals:
    void running(const QUuid &jobId);
    void statusUpdated(const QUuid &jobId, const forensic::HashcatStatus &status);
    void cracked(const QUuid &jobId, const QString &hash, const QString &plaintext);
    void paused(const QUuid &jobId);
    void stopped(const QUuid &jobId);
    // hashcatStatusCode is the last-seen status code (HashcatStatusCode::*), or -1.
    void finished(const QUuid &jobId, int exitCode, int hashcatStatusCode);
    void failed(const QUuid &jobId, const QString &error);
};

} // namespace forensic

#endif // FORENSIC_JOBEXECUTIONBACKEND_H
