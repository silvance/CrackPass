/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef FORENSIC_BKCRACKEXECUTIONBACKEND_H
#define FORENSIC_BKCRACKEXECUTIONBACKEND_H

#include "jobexecutionbackend.h"
#include <QHash>
#include <QString>

class QProcess;

namespace forensic {

/*
 * Execution backend for bkcrack (ZipCrypto known-plaintext attack). It runs
 * bkcrack as an attached child process, parses the recovered internal key triple
 * (X Y Z) and best-effort progress from bkcrack's stdout, and emits the keys as
 * the recovered result (bkcrack recovers keys, not a password -- see
 * docs/BKCRACK_DESIGN.md). Registered under engineId "bkcrack" in the JobQueue.
 *
 * bkcrack has no session/restore checkpoint, unlike hashcat/John: pause and stop
 * simply terminate the process, and resume restarts the attack from the
 * beginning. This is stated plainly rather than pretending a checkpoint exists.
 */
class BkcrackExecutionBackend : public JobExecutionBackend
{
    Q_OBJECT

public:
    explicit BkcrackExecutionBackend(QString bkcrackProgram, QObject *parent = nullptr);

    void start(const CrackingJob &job, const StartOptions &opts) override;
    void pause(const QUuid &jobId) override;
    void resume(const CrackingJob &job, const StartOptions &opts) override;
    void stop(const QUuid &jobId) override;

    // Exposed for testing: the argv passed to bkcrack (the builder already put
    // the full attack argv on the job; there is no session/pot plumbing to add).
    static QStringList composeArgs(const CrackingJob &job, const StartOptions &opts);

    // Exposed for testing: the binary that will run (prefers the job's recorded
    // path, falls back to `configured`).
    static QString programFor(const CrackingJob &job, const QString &configured);

    // Exposed for testing: the recovered key triple ("x y z", lowercased) from
    // one line of bkcrack output, or an empty string when the line has no keys.
    static QString parseKeysLine(const QString &line);

    // Exposed for testing: parse a bkcrack progress line ("50.0 % (a / b)") into
    // a HashcatStatus. Returns false when the line is not a progress line.
    static bool parseProgressLine(const QString &line, class HashcatStatus &out);

    // Exposed for testing: a human-readable target label ("<archive>!<entry>")
    // derived from the bkcrack argv (-C / -c), for the recovered record.
    static QString targetLabel(const CrackingJob &job);

private:
    enum class Pending { None, Pause, Stop };
    struct Context {
        QProcess *proc = nullptr;
        StartOptions opts;
        CrackingJob job;
        QByteArray outBuf;
        bool keysEmitted = false;
        Pending pending = Pending::None;
    };

    void launch(const QUuid &jobId);
    void requestShutdown(const QUuid &jobId, Pending kind);
    void drainOutput(const QUuid &jobId);

    static constexpr int kGraceMs = 10000;

    QString m_program;
    QHash<QUuid, Context *> m_contexts;
};

} // namespace forensic

#endif // FORENSIC_BKCRACKEXECUTIONBACKEND_H
