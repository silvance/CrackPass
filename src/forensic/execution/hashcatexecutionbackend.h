/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef FORENSIC_HASHCATEXECUTIONBACKEND_H
#define FORENSIC_HASHCATEXECUTIONBACKEND_H

#include "jobexecutionbackend.h"
#include "hashcatstatusstream.h"
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
    void resume(const CrackingJob &job, const StartOptions &opts) override;
    void stop(const QUuid &jobId) override;

    // Exposed for testing: compose the argv passed to hashcat.
    static QStringList composeArgs(const CrackingJob &job, const StartOptions &opts);

    // Exposed for testing: the binary that will be executed for `job`. Prefers
    // the path recorded on the job (so the executed binary matches the forensic
    // record) and falls back to `configured` only when the job records none.
    static QString programFor(const CrackingJob &job, const QString &configured);

private:
    enum class Pending { None, Pause, Stop };
    struct Context {
        QProcess *proc = nullptr;
        StartOptions opts;
        CrackingJob job;
        int lastStatusCode = -1;
        HashcatStatusStream statusStream;
        int emittedCredLines = 0;
        QString targetHash;
        Pending pending = Pending::None;
    };

    void launch(const QUuid &jobId, bool restore);
    void requestShutdown(const QUuid &jobId, Pending kind);
    static constexpr int kGraceMs = 10000; // grace before a forced kill
    void drainStatus(const QUuid &jobId);
    void drainCredentials(const QUuid &jobId);

    QString m_program;
    QHash<QUuid, Context *> m_contexts;
};

} // namespace forensic

#endif // FORENSIC_HASHCATEXECUTIONBACKEND_H
