/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "hashcatexecutionbackend.h"

#include "hashcatstatusparser.h"
#include "crackedplain.h"

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
        args << job.hashcatArgs;
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

void HashcatExecutionBackend::launch(const QUuid &jobId, bool restore)
{
    Context *ctx = m_contexts.value(jobId);
    if (!ctx)
        return;
    ctx->opts.restore = restore;
    ctx->pending = Pending::None;

    auto *proc = new QProcess(this);
    ctx->proc = proc;
    if (!ctx->opts.workingDir.isEmpty())
        proc->setWorkingDirectory(ctx->opts.workingDir);
    proc->setProgram(m_program);
    proc->setArguments(composeArgs(ctx->job, ctx->opts));

    connect(proc, &QProcess::readyReadStandardOutput, this, [this, jobId] { drainStatus(jobId); });
    connect(proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this,
            [this, jobId](int exitCode, QProcess::ExitStatus) {
                Context *c = m_contexts.value(jobId);
                if (!c)
                    return;
                drainCredentials(jobId); // capture any last-moment cracks
                const Pending pending = c->pending;
                const int statusCode = c->lastStatusCode;
                c->proc->deleteLater();
                c->proc = nullptr;
                if (pending == Pending::Pause) {
                    emit paused(jobId);
                } else if (pending == Pending::Stop) {
                    emit stopped(jobId);
                } else {
                    emit finished(jobId, exitCode, statusCode);
                }
            });
    connect(proc, &QProcess::errorOccurred, this, [this, jobId](QProcess::ProcessError e) {
        if (e == QProcess::FailedToStart)
            emit failed(jobId, QStringLiteral("Failed to start hashcat."));
    });

    proc->start(QIODevice::ReadOnly);
    emit running(jobId);
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
    const QVector<HashcatStatus> statuses = ctx->statusStream.append(chunk);
    if (!statuses.isEmpty()) {
        const HashcatStatus &status = statuses.last();
        ctx->lastStatusCode = status.statusCode;
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
        // so passwords with colons, spaces or Unicode survive intact.
        const QString plain = decodeHashcatPlain(text);
        emit cracked(jobId, ctx->targetHash, plain);
    }
    ctx->emittedCredLines = line;
}

void HashcatExecutionBackend::requestShutdown(const QUuid &jobId, Pending kind)
{
    Context *ctx = m_contexts.value(jobId);
    if (!ctx || !ctx->proc)
        return;
    ctx->pending = kind;
    // Graceful first: SIGTERM lets hashcat write its restore/session file so the
    // job can be resumed. If it does not exit within the grace period we force
    // a kill so a hung process cannot wedge the queue (no restore is guaranteed
    // in that forced case).
    ctx->proc->terminate();
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

void HashcatExecutionBackend::resume(const QUuid &jobId)
{
    if (m_contexts.contains(jobId))
        launch(jobId, true);
}

} // namespace forensic
