/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#include "hashcatexecutionbackend.h"

#include "hashcatstatusparser.h"

#include <QFile>
#include <QFileInfo>
#include <QProcess>
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
            args << QStringLiteral("--outfile") << opts.outfilePath;
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
    const HashcatStatus status = HashcatStatusParser::parseLatest(chunk);
    if (status.valid) {
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
    QTextStream in(&f);
    int line = 0;
    while (!in.atEnd()) {
        const QString text = in.readLine();
        if (line++ < ctx->emittedCredLines)
            continue;
        if (text.trimmed().isEmpty())
            continue;
        // Default outfile is "<hash>:<plain>"; extracted hashes use '*' as their
        // internal separator, so the last ':' splits hash from plaintext.
        const int colon = text.lastIndexOf(QLatin1Char(':'));
        const QString hash = colon > 0 ? text.left(colon) : QString();
        const QString plain = colon >= 0 ? text.mid(colon + 1) : text;
        emit cracked(jobId, hash, plain);
    }
    ctx->emittedCredLines = line;
}

void HashcatExecutionBackend::pause(const QUuid &jobId)
{
    Context *ctx = m_contexts.value(jobId);
    if (ctx && ctx->proc) {
        ctx->pending = Pending::Pause;
        ctx->proc->terminate();
    }
}

void HashcatExecutionBackend::stop(const QUuid &jobId)
{
    Context *ctx = m_contexts.value(jobId);
    if (ctx && ctx->proc) {
        ctx->pending = Pending::Stop;
        ctx->proc->terminate();
    }
}

void HashcatExecutionBackend::resume(const QUuid &jobId)
{
    if (m_contexts.contains(jobId))
        launch(jobId, true);
}

} // namespace forensic
