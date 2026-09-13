/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef FORENSIC_JOHNEXECUTIONBACKEND_H
#define FORENSIC_JOHNEXECUTIONBACKEND_H

#include "jobexecutionbackend.h"
#include <QHash>
#include <QString>

class QProcess;
class QTimer;

namespace forensic {

/*
 * Real backend for John the Ripper. It runs john as an attached child process,
 * reads recovered passwords from john's pot file (john writes cracked entries
 * there as it finds them), and derives a best-effort progress/speed status from
 * john's periodic stderr status lines (john has no machine-readable status like
 * hashcat's --status-json, so progress is advisory, not a forensic figure).
 *
 * Pause/stop terminate the process; john saves its session (.rec) on a graceful
 * signal, so resume relaunches with --restore=<session>. This mirrors the
 * hashcat backend's --session/--restore lifecycle through the same interface.
 */
class JohnExecutionBackend : public JobExecutionBackend
{
    Q_OBJECT

public:
    explicit JohnExecutionBackend(QString johnProgram, QObject *parent = nullptr);

    void start(const CrackingJob &job, const StartOptions &opts) override;
    void pause(const QUuid &jobId) override;
    void resume(const CrackingJob &job, const StartOptions &opts) override;
    void stop(const QUuid &jobId) override;

    // Exposed for testing: compose the argv passed to john.
    static QStringList composeArgs(const CrackingJob &job, const StartOptions &opts);

    // Exposed for testing: the binary that will be executed for `job` (prefers
    // the path recorded on the job, falling back to `configured`).
    static QString programFor(const CrackingJob &job, const QString &configured);

    // Exposed for testing: extract the recovered-plaintext token from one john
    // pot-file line. john pot lines are "<ciphertext>:<plaintext>", and the
    // ciphertext itself can contain colons; when `knownHash` matches the line's
    // prefix we split there exactly, otherwise we fall back to the first colon.
    // Returns an empty string when the line is not a valid pot entry. The token
    // may still be $HEX[..]-wrapped (decode with decodeHashcatPlain).
    static QString potPlaintextToken(const QString &potLine, const QString &knownHash);

    // Exposed for testing: parse one john status line into a HashcatStatus
    // (speed + guesses). Returns false when the line is not a status line.
    static bool parseProgressLine(const QString &line, class HashcatStatus &out);

private:
    enum class Pending { None, Pause, Stop };
    struct Context {
        QProcess *proc = nullptr;
        QTimer *potTimer = nullptr;
        StartOptions opts;
        CrackingJob job;
        int emittedCredLines = 0;
        QString targetHash;
        QByteArray stderrBuf;
        Pending pending = Pending::None;
    };

    void launch(const QUuid &jobId, bool restore);
    void requestShutdown(const QUuid &jobId, Pending kind);
    void drainStderr(const QUuid &jobId);
    void drainCredentials(const QUuid &jobId);
    void ensureTargetHash(Context *ctx);

    static constexpr int kGraceMs = 10000; // grace before a forced kill
    static constexpr int kPotPollMs = 2000; // how often to scan the pot for cracks

    QString m_program;
    QHash<QUuid, Context *> m_contexts;
};

} // namespace forensic

#endif // FORENSIC_JOHNEXECUTIONBACKEND_H
