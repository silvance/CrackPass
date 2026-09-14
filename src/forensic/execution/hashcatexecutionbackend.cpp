/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "hashcatexecutionbackend.h"

#include "hashcatstatusparser.h"
#include "crackedplain.h"
#include "processcontrol.h"

#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QTimer>
#include <QTextStream>

namespace forensic {

HashcatExecutionBackend::HashcatExecutionBackend(QString hashcatProgram, QObject *parent)
    : JobExecutionBackend(parent)
    , m_program(std::move(hashcatProgram))
{
}

QStringList HashcatExecutionBackend::composeArgs(const CrackingJob &job, const StartOptions &opts)
{
    QStringList args;
    if (opts.restore) {
        // Resume an existing session; hashcat reloads the attack from the
        // restore file, so we only re-supply session + status plumbing.
        args << QStringLiteral("--session") << opts.sessionName
             << QStringLiteral("--restore");
        if (!opts.restorePath.isEmpty())
            args << QStringLiteral("--restore-file-path") << opts.restorePath;
    } else {
        args << job.engineArgs;
        args << QStringLiteral("--session") << opts.sessionName;
        if (!opts.restorePath.isEmpty())
            args << QStringLiteral("--restore-file-path") << opts.restorePath;
        if (!opts.potfilePath.isEmpty())
            args << QStringLiteral("--potfile-path") << opts.potfilePath;
        if (!opts.outfilePath.isEmpty())
            args << QStringLiteral("--outfile") << opts.outfilePath
                 << QStringLiteral("--outfile-format") << QStringLiteral("2"); // 2 = plaintext only
    }
    // Machine-readable status on a timer instead of scraping the terminal.
    args << QStringLiteral("--status") << QStringLiteral("--status-json")
         << QStringLiteral("--status-timer") << QStringLiteral("2");
    return args;
}

QString HashcatExecutionBackend::programFor(const CrackingJob &job, const QString &configured)
{
    return job.enginePath.isEmpty() ? configured : job.enginePath;
}

void HashcatExecutionBackend::launch(const QUuid &jobId, bool restore)
{
    Context *ctx = m_contexts.value(jobId);
    if (!ctx)
        return;
    ctx->opts.restore = restore;
    ctx->pending = Pending::None;

    auto *proc = new QProcess(this);
    ctx->proc = proc;
    configureForGracefulStop(proc); // Windows: own process group for CTRL_BREAK
    if (!ctx->opts.workingDir.isEmpty())
        proc->setWorkingDirectory(ctx->opts.workingDir);
    // Execute the binary recorded on the job so the process we run is exactly the
    // one the forensic record attributes the work to. m_program is only a
    // fallback for jobs created without a recorded path.
    proc->setProgram(programFor(ctx->job, m_program));
    proc->setArguments(composeArgs(ctx->job, ctx->opts));

    connect(proc, &QProcess::readyReadStandardOutput, this, [this, jobId] { drainStatus(jobId); });
    // Report Running only when the process HAS started -- not optimistically
    // after start() -- so a FailedToStart never transiently appears as Running.
    connect(proc, &QProcess::started, this, [this, jobId] { emit running(jobId); });
    connect(proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this,
            [this, jobId](int exitCode, QProcess::ExitStatus) {
                Context *c = m_contexts.value(jobId);
                if (!c)
                    return;
                drainCredentials(jobId); // capture any last-moment cracks
                const Pending pending = c->pending;
                const int statusCode = c->lastStatusCode;
                if (pending == Pending::Pause) {
                    // Resumable: keep the context, just release the process.
                    c->proc->deleteLater();
                    c->proc = nullptr;
                    emit paused(jobId);
                } else if (pending == Pending::Stop) {
                    emit stopped(jobId);
                    disposeContext(jobId); // terminal: no resume state to keep
                } else {
                    emit finished(jobId, exitCode, statusCode);
                    disposeContext(jobId); // terminal
                }
            });
    connect(proc, &QProcess::errorOccurred, this, [this, jobId](QProcess::ProcessError e) {
        if (e == QProcess::FailedToStart) {
            // One clean failure transition; started() never fired, so no Running
            // was emitted. Tear the context down so nothing leaks.
            emit failed(jobId, QStringLiteral("Failed to start hashcat."));
            disposeContext(jobId);
        }
    });

    proc->start(QIODevice::ReadOnly);
}

void HashcatExecutionBackend::disposeContext(const QUuid &jobId)
{
    Context *c = m_contexts.take(jobId);
    if (!c)
        return;
    if (c->proc) {
        c->proc->deleteLater();
        c->proc = nullptr;
    }
    delete c;
}

void HashcatExecutionBackend::start(const CrackingJob &job, const StartOptions &opts)
{
    auto *ctx = new Context;
    ctx->opts = opts;
    ctx->job = job;
    m_contexts.insert(job.id, ctx);
    launch(job.id, false);
}

void HashcatExecutionBackend::drainStatus(const QUuid &jobId)
{
    Context *ctx = m_contexts.value(jobId);
    if (!ctx || !ctx->proc)
        return;
    const QByteArray chunk = ctx->proc->readAllStandardOutput();
    // Reassemble across reads: a JSON status line may be split between chunks.
    const QVector<RecoveryStatus> statuses = ctx->statusStream.append(chunk);
    if (!statuses.isEmpty()) {
        const RecoveryStatus &status = statuses.last();
        ctx->lastStatusCode = status.nativeStatusCode;
        emit statusUpdated(jobId, status);
    }
    drainCredentials(jobId);
}

void HashcatExecutionBackend::drainCredentials(const QUuid &jobId)
{
    Context *ctx = m_contexts.value(jobId);
    if (!ctx || ctx->opts.outfilePath.isEmpty())
        return;
    QFile f(ctx->opts.outfilePath);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
        return;
    // Read the target hash once so recovered credentials carry their hash even
    // though the outfile contains only plaintext.
    if (ctx->targetHash.isEmpty() && !ctx->job.hashFile.isEmpty()) {
        QFile hf(ctx->job.hashFile);
        if (hf.open(QIODevice::ReadOnly | QIODevice::Text)) {
            QTextStream hin(&hf);
            while (!hin.atEnd()) {
                const QString l = hin.readLine().trimmed();
                if (!l.isEmpty()) { ctx->targetHash = l; break; }
            }
        }
    }

    QTextStream in(&f);
    in.setEncoding(QStringConverter::Utf8);
    int line = 0;
    while (!in.atEnd()) {
        const QString text = in.readLine();
        if (line++ < ctx->emittedCredLines)
            continue;
        if (text.isEmpty())
            continue;
        // Outfile is plaintext-only (format 2); decode hashcat's $HEX[] wrapping
        // to the exact password bytes so passwords with colons, spaces, Unicode
        // or non-UTF-8 bytes survive intact.
        emit cracked(jobId, ctx->targetHash, decodeHashcatPlain(text).raw);
    }
    ctx->emittedCredLines = line;
}

void HashcatExecutionBackend::requestShutdown(const QUuid &jobId, Pending kind)
{
    Context *ctx = m_contexts.value(jobId);
    if (!ctx || !ctx->proc)
        return;
    ctx->pending = kind;
    // Graceful first (SIGTERM on POSIX, console CTRL_BREAK on Windows) lets
    // hashcat write its restore/session file so the job can be resumed. If it
    // does not exit within the grace period we force a kill so a hung process
    // cannot wedge the queue (no restore is guaranteed in that forced case).
    requestGracefulStop(ctx->proc);
    QProcess *proc = ctx->proc;
    QTimer::singleShot(kGraceMs, proc, [proc]() {
        if (proc->state() != QProcess::NotRunning)
            proc->kill();
    });
}

void HashcatExecutionBackend::pause(const QUuid &jobId)
{
    requestShutdown(jobId, Pending::Pause);
}

void HashcatExecutionBackend::stop(const QUuid &jobId)
{
    requestShutdown(jobId, Pending::Stop);
}

void HashcatExecutionBackend::resume(const CrackingJob &job, const StartOptions &opts)
{
    // Reconstruct the run context if we do not have one -- this is the case when
    // resuming a job that was persisted (Paused/interrupted) before the app was
    // restarted, so it was never started in this process. hashcat reloads the
    // attack from the restore file, so we only need the session/restore plumbing.
    Context *ctx = m_contexts.value(job.id);
    if (!ctx) {
        ctx = new Context;
        ctx->job = job;
        m_contexts.insert(job.id, ctx);
    }
    ctx->opts = opts;
    launch(job.id, true);
}

} // namespace forensic
