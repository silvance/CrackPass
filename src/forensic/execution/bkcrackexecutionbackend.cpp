/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "bkcrackexecutionbackend.h"

#include "hashcatstatus.h"

#include <QProcess>
#include <QRegularExpression>
#include <QTimer>

namespace forensic {

BkcrackExecutionBackend::BkcrackExecutionBackend(QString bkcrackProgram, QObject *parent)
    : JobExecutionBackend(parent)
    , m_program(std::move(bkcrackProgram))
{
}

QStringList BkcrackExecutionBackend::composeArgs(const CrackingJob &job, const StartOptions &)
{
    // The full bkcrack attack argv was produced by BkcrackCommandBuilder and
    // stored on the job. bkcrack has no session/pot/status plumbing to add.
    return job.hashcatArgs;
}

QString BkcrackExecutionBackend::programFor(const CrackingJob &job, const QString &configured)
{
    return job.hashcatPath.isEmpty() ? configured : job.hashcatPath;
}

QString BkcrackExecutionBackend::parseKeysLine(const QString &line)
{
    // bkcrack prints the recovered keys as three 8-hex-digit words, optionally
    // after a "Keys:" label. Progress lines contain '%', never keys.
    if (line.contains(QLatin1Char('%')))
        return QString();
    static const QRegularExpression re(
        QStringLiteral("\\b([0-9a-fA-F]{8})\\s+([0-9a-fA-F]{8})\\s+([0-9a-fA-F]{8})\\b"));
    const QRegularExpressionMatch m = re.match(line);
    if (!m.hasMatch())
        return QString();
    return (m.captured(1) + QLatin1Char(' ') + m.captured(2) + QLatin1Char(' ') + m.captured(3))
        .toLower();
}

bool BkcrackExecutionBackend::parseProgressLine(const QString &line, HashcatStatus &out)
{
    // e.g. "50.0 % (8388608 / 16777216)".
    static const QRegularExpression re(QStringLiteral("\\((\\d+)\\s*/\\s*(\\d+)\\)"));
    const QRegularExpressionMatch m = re.match(line);
    if (!m.hasMatch() || !line.contains(QLatin1Char('%')))
        return false;
    HashcatStatus st;
    st.valid = true;
    st.statusCode = HashcatStatusCode::Running;
    st.progressDone = m.captured(1).toLongLong();
    st.progressTotal = m.captured(2).toLongLong();
    out = st;
    return true;
}

QString BkcrackExecutionBackend::targetLabel(const CrackingJob &job)
{
    QString archive, entry;
    const QStringList &a = job.hashcatArgs;
    for (int i = 0; i + 1 < a.size(); ++i) {
        if (a.at(i) == QStringLiteral("-C"))
            archive = a.at(i + 1);
        else if (a.at(i) == QStringLiteral("-c"))
            entry = a.at(i + 1);
    }
    if (!archive.isEmpty() && !entry.isEmpty())
        return archive + QLatin1Char('!') + entry;
    if (!entry.isEmpty())
        return entry;
    return archive; // may be empty; the recovered record still carries the keys
}

void BkcrackExecutionBackend::launch(const QUuid &jobId)
{
    Context *ctx = m_contexts.value(jobId);
    if (!ctx)
        return;
    ctx->pending = Pending::None;
    ctx->outBuf.clear();
    ctx->keysEmitted = false;

    auto *proc = new QProcess(this);
    ctx->proc = proc;
    if (!ctx->opts.workingDir.isEmpty())
        proc->setWorkingDirectory(ctx->opts.workingDir);
    proc->setProgram(programFor(ctx->job, m_program));
    proc->setArguments(composeArgs(ctx->job, ctx->opts));
    // bkcrack writes progress and the keys to stdout; merge so a build that logs
    // either to stderr is still parsed.
    proc->setProcessChannelMode(QProcess::MergedChannels);

    connect(proc, &QProcess::readyReadStandardOutput, this, [this, jobId] { drainOutput(jobId); });
    connect(proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this,
            [this, jobId](int exitCode, QProcess::ExitStatus) {
                Context *c = m_contexts.value(jobId);
                if (!c)
                    return;
                drainOutput(jobId); // capture any final keys line
                const Pending pending = c->pending;
                const bool keys = c->keysEmitted;
                c->proc->deleteLater();
                c->proc = nullptr;
                if (pending == Pending::Pause) {
                    emit paused(jobId);
                } else if (pending == Pending::Stop) {
                    emit stopped(jobId);
                } else if (keys) {
                    // Keys recovered: report Cracked so the queue records Recovered.
                    emit finished(jobId, exitCode, HashcatStatusCode::Cracked);
                } else {
                    // No keys: bkcrack exits non-zero; present as Exhausted.
                    emit finished(jobId, exitCode, HashcatStatusCode::Exhausted);
                }
            });
    connect(proc, &QProcess::errorOccurred, this, [this, jobId](QProcess::ProcessError e) {
        if (e == QProcess::FailedToStart)
            emit failed(jobId, QStringLiteral("Failed to start bkcrack."));
    });

    proc->start(QIODevice::ReadOnly);
    emit running(jobId);
}

void BkcrackExecutionBackend::start(const CrackingJob &job, const StartOptions &opts)
{
    auto *ctx = new Context;
    ctx->opts = opts;
    ctx->job = job;
    m_contexts.insert(job.id, ctx);
    launch(job.id);
}

void BkcrackExecutionBackend::drainOutput(const QUuid &jobId)
{
    Context *ctx = m_contexts.value(jobId);
    if (!ctx || !ctx->proc)
        return;
    ctx->outBuf += ctx->proc->readAllStandardOutput();
    int nl;
    while ((nl = ctx->outBuf.indexOf('\n')) >= 0) {
        const QString line = QString::fromUtf8(ctx->outBuf.left(nl));
        ctx->outBuf.remove(0, nl + 1);

        HashcatStatus st;
        if (parseProgressLine(line, st)) {
            emit statusUpdated(jobId, st);
            continue;
        }
        if (!ctx->keysEmitted) {
            const QString keys = parseKeysLine(line);
            if (!keys.isEmpty()) {
                ctx->keysEmitted = true;
                // Emit the recovered keys via the standard credential path. The
                // "hash" is the target label; the "plaintext" is the key triple.
                emit cracked(jobId, targetLabel(ctx->job), keys.toUtf8());
            }
        }
    }
}

void BkcrackExecutionBackend::requestShutdown(const QUuid &jobId, Pending kind)
{
    Context *ctx = m_contexts.value(jobId);
    if (!ctx || !ctx->proc)
        return;
    ctx->pending = kind;
    // bkcrack has no restore file to preserve, so a plain terminate (then a
    // forced kill if it does not exit) is all that is needed.
    ctx->proc->terminate();
    QProcess *proc = ctx->proc;
    QTimer::singleShot(kGraceMs, proc, [proc]() {
        if (proc->state() != QProcess::NotRunning)
            proc->kill();
    });
}

void BkcrackExecutionBackend::pause(const QUuid &jobId)
{
    // No checkpoint: pausing ends the run; resume will restart it from scratch.
    requestShutdown(jobId, Pending::Pause);
}

void BkcrackExecutionBackend::stop(const QUuid &jobId)
{
    requestShutdown(jobId, Pending::Stop);
}

void BkcrackExecutionBackend::resume(const CrackingJob &job, const StartOptions &opts)
{
    // bkcrack cannot resume from a checkpoint; restart the attack from the
    // beginning (deterministic, so it simply redoes the work).
    Context *ctx = m_contexts.value(job.id);
    if (!ctx) {
        ctx = new Context;
        ctx->job = job;
        m_contexts.insert(job.id, ctx);
    }
    ctx->opts = opts;
    launch(job.id);
}

} // namespace forensic
