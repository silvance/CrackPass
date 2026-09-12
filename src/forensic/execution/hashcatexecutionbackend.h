/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#ifndef FORENSIC_HASHCATEXECUTIONBACKEND_H
#define FORENSIC_HASHCATEXECUTIONBACKEND_H

#include "jobexecutionbackend.h"
#include <QHash>
#include <QString>

class QProcess;

namespace forensic {

/*
 * Real backend: runs hashcat as an attached child process with machine-readable
 * status (--status-json), and captures recovered plaintext from the outfile.
 * Pause/stop end the process while keeping the session's restore file; resume
 * relaunches hashcat with --restore. Reuses the configured hashcat binary path.
 */
class HashcatExecutionBackend : public JobExecutionBackend
{
    Q_OBJECT

public:
    explicit HashcatExecutionBackend(QString hashcatProgram, QObject *parent = nullptr);

    void start(const CrackingJob &job, const StartOptions &opts) override;
    void pause(const QUuid &jobId) override;
    void resume(const QUuid &jobId) override;
    void stop(const QUuid &jobId) override;

    // Exposed for testing: compose the argv passed to hashcat.
    static QStringList composeArgs(const CrackingJob &job, const StartOptions &opts);

private:
    enum class Pending { None, Pause, Stop };
    struct Context {
        QProcess *proc = nullptr;
        StartOptions opts;
        CrackingJob job;
        int lastStatusCode = -1;
        int emittedCredLines = 0;
        Pending pending = Pending::None;
    };

    void launch(const QUuid &jobId, bool restore);
    void drainStatus(const QUuid &jobId);
    void drainCredentials(const QUuid &jobId);

    QString m_program;
    QHash<QUuid, Context *> m_contexts;
};

} // namespace forensic

#endif // FORENSIC_HASHCATEXECUTIONBACKEND_H
