/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "johnexecutionbackend.h"

#include "crackedplain.h"
#include "hashcatstatus.h"

#include <QFile>
#include <QProcess>
#include <QRegularExpression>
#include <QTextStream>
#include <QTimer>

namespace forensic {

JohnExecutionBackend::JohnExecutionBackend(QString johnProgram, QObject *parent)
    : JobExecutionBackend(parent)
    , m_program(std::move(johnProgram))
{
}

QStringList JohnExecutionBackend::composeArgs(const CrackingJob &job, const StartOptions &opts)
{
    QStringList args;
    if (opts.restore) {
        // Resume: john reloads the attack, wordlist position and options from the
        // session (.rec) file, so we only name the session to restore.
        args << (QStringLiteral("--restore=") + opts.sessionName);
        return args;
    }

    args << job.hashcatArgs; // the john attack argv (built by JohnCommandBuilder)
    if (!opts.sessionName.isEmpty())
        args << (QStringLiteral("--session=") + opts.sessionName);
    if (!opts.potfilePath.isEmpty())
        args << (QStringLiteral("--pot=") + opts.potfilePath);
    // Periodic status to stderr so we can surface a best-effort live speed.
    args << QStringLiteral("--progress-every=5");
    return args;
}

QString JohnExecutionBackend::programFor(const CrackingJob &job, const QString &configured)
{
    return job.hashcatPath.isEmpty() ? configured : job.hashcatPath;
}

QString JohnExecutionBackend::potPlaintextToken(const QString &potLine, const QString &knownHash)
{
    const QString line = potLine.trimmed();
    if (line.isEmpty())
        return QString();

    // Exact split: when we know the target ciphertext and the line begins with
    // it, the plaintext is everything after that ciphertext's trailing colon --
    // correct even when the ciphertext contains colons of its own.
    if (!knownHash.isEmpty() && line.size() > knownHash.size()
        && line.startsWith(knownHash) && line.at(knownHash.size()) == QLatin1Char(':')) {
        return line.mid(knownHash.size() + 1);
    }

    // Fallback: split on the first colon.
    const int colon = line.indexOf(QLatin1Char(':'));
    if (colon < 0)
        return QString(); // not a "ciphertext:plaintext" line
    return line.mid(colon + 1);
}

namespace {

// Parse a john speed token like "1234c/s", "12.3Mp/s" into hashes/sec.
qint64 parseScaledRate(const QString &numberWithSuffix)
{
    QRegularExpression re(QStringLiteral("^([0-9]+(?:\\.[0-9]+)?)([kKmMgGtT]?)$"));
    const QRegularExpressionMatch m = re.match(numberWithSuffix);
    if (!m.hasMatch())
        return 0;
    double value = m.captured(1).toDouble();
    const QString suffix = m.captured(2).toLower();
    if (suffix == QLatin1String("k")) value *= 1e3;
    else if (suffix == QLatin1String("m")) value *= 1e6;
    else if (suffix == QLatin1String("g")) value *= 1e9;
    else if (suffix == QLatin1String("t")) value *= 1e12;
    return static_cast<qint64>(value);
}

} // namespace

bool JohnExecutionBackend::parseProgressLine(const QString &line, HashcatStatus &out)
{
    // A john status line looks like:
    //   0g 0:00:00:05 12.34% (ETA: ...) 4567p/s 4567c/s 4567C/s foo..bar
    // We extract the recovered-guess count and the crypts/sec speed. The line is
    // human-readable, so this is advisory: absence of a token is not an error.
    const QString s = line.trimmed();
    if (s.isEmpty())
        return false;

    bool recognized = false;
    HashcatStatus st;
    st.statusCode = HashcatStatusCode::Running;

    // Guesses so far: a leading "<N>g" token.
    QRegularExpression guessRe(QStringLiteral("(?:^|\\s)(\\d+)g(?:\\s|$)"));
    const QRegularExpressionMatch gm = guessRe.match(s);
    if (gm.hasMatch()) {
        st.recoveredHashes = gm.captured(1).toInt();
        recognized = true;
    }

    // Speed: prefer c/s (crypts, i.e. hashes computed per second); fall back to
    // p/s (candidates per second) when c/s is absent.
    QRegularExpression csRe(QStringLiteral("([0-9.]+[kKmMgGtT]?)c/s"));
    QRegularExpression psRe(QStringLiteral("([0-9.]+[kKmMgGtT]?)p/s"));
    QRegularExpressionMatch sm = csRe.match(s);
    if (!sm.hasMatch())
        sm = psRe.match(s);
    if (sm.hasMatch()) {
        st.aggregateSpeed = parseScaledRate(sm.captured(1));
        recognized = true;
    }

    if (!recognized)
        return false;
    st.valid = true;
    out = st;
    return true;
}

void JohnExecutionBackend::ensureTargetHash(Context *ctx)
{
    if (!ctx->targetHash.isEmpty() || ctx->job.hashFile.isEmpty())
        return;
    QFile hf(ctx->job.hashFile);
    if (!hf.open(QIODevice::ReadOnly | QIODevice::Text))
        return;
    QTextStream hin(&hf);
    while (!hin.atEnd()) {
        const QString l = hin.readLine().trimmed();
        if (!l.isEmpty()) { ctx->targetHash = l; break; }
    }
}

void JohnExecutionBackend::launch(const QUuid &jobId, bool restore)
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
    // Run the binary recorded on the job so the executed process matches the
    // forensic record; m_program is only a fallback for jobs without a path.
    proc->setProgram(programFor(ctx->job, m_program));
    proc->setArguments(composeArgs(ctx->job, ctx->opts));

    connect(proc, &QProcess::readyReadStandardError, this, [this, jobId] { drainStderr(jobId); });
    connect(proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this,
            [this, jobId](int exitCode, QProcess::ExitStatus) {
                Context *c = m_contexts.value(jobId);
                if (!c)
                    return;
                drainCredentials(jobId); // capture any last-moment cracks
                if (c->potTimer)
                    c->potTimer->stop();
                const Pending pending = c->pending;
                c->proc->deleteLater();
                c->proc = nullptr;
                if (pending == Pending::Pause) {
                    emit paused(jobId);
                } else if (pending == Pending::Stop) {
                    emit stopped(jobId);
                } else {
                    // john has no status code; the queue decides Recovered vs
                    // Exhausted from whether a credential arrived and the exit code.
                    emit finished(jobId, exitCode, -1);
                }
            });
    connect(proc, &QProcess::errorOccurred, this, [this, jobId](QProcess::ProcessError e) {
        if (e == QProcess::FailedToStart)
            emit failed(jobId, QStringLiteral("Failed to start John the Ripper."));
    });

    // Poll the pot file for recovered passwords; john appends to it as it cracks,
    // independently of its stderr status cadence.
    if (!ctx->potTimer) {
        ctx->potTimer = new QTimer(this);
        ctx->potTimer->setInterval(kPotPollMs);
        connect(ctx->potTimer, &QTimer::timeout, this, [this, jobId] { drainCredentials(jobId); });
    }
    ctx->potTimer->start();

    proc->start(QIODevice::ReadOnly);
    emit running(jobId);
}

void JohnExecutionBackend::start(const CrackingJob &job, const StartOptions &opts)
{
    auto *ctx = new Context;
    ctx->opts = opts;
    ctx->job = job;
    m_contexts.insert(job.id, ctx);
    launch(job.id, false);
}

void JohnExecutionBackend::drainStderr(const QUuid &jobId)
{
    Context *ctx = m_contexts.value(jobId);
    if (!ctx || !ctx->proc)
        return;
    ctx->stderrBuf += ctx->proc->readAllStandardError();
    // Process complete lines; keep any trailing partial line buffered.
    int nl;
    while ((nl = ctx->stderrBuf.indexOf('\n')) >= 0) {
        const QString line = QString::fromUtf8(ctx->stderrBuf.left(nl));
        ctx->stderrBuf.remove(0, nl + 1);
        HashcatStatus st;
        if (parseProgressLine(line, st))
            emit statusUpdated(jobId, st);
    }
    // A crack may have landed in the pot around the same time as a status print.
    drainCredentials(jobId);
}

void JohnExecutionBackend::drainCredentials(const QUuid &jobId)
{
    Context *ctx = m_contexts.value(jobId);
    if (!ctx || ctx->opts.potfilePath.isEmpty())
        return;
    QFile f(ctx->opts.potfilePath);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
        return;
    ensureTargetHash(ctx);

    QTextStream in(&f);
    in.setEncoding(QStringConverter::Utf8);
    int line = 0;
    while (!in.atEnd()) {
        const QString text = in.readLine();
        if (line++ < ctx->emittedCredLines)
            continue;
        const QString token = potPlaintextToken(text, ctx->targetHash);
        if (token.isEmpty())
            continue;
        // john $HEX[..]-wraps awkward plaintexts just like hashcat; decode to the
        // exact recovered bytes so colons/Unicode/non-UTF-8 survive intact.
        emit cracked(jobId, ctx->targetHash, decodeHashcatPlain(token).raw);
    }
    ctx->emittedCredLines = line;
}

void JohnExecutionBackend::requestShutdown(const QUuid &jobId, Pending kind)
{
    Context *ctx = m_contexts.value(jobId);
    if (!ctx || !ctx->proc)
        return;
    ctx->pending = kind;
    // Graceful first: john saves its session (.rec) on a terminate signal so the
    // job can be resumed. Force-kill only if it does not exit within the grace
    // period (no session save is guaranteed in that forced case).
    ctx->proc->terminate();
    QProcess *proc = ctx->proc;
    QTimer::singleShot(kGraceMs, proc, [proc]() {
        if (proc->state() != QProcess::NotRunning)
            proc->kill();
    });
}

void JohnExecutionBackend::pause(const QUuid &jobId)
{
    requestShutdown(jobId, Pending::Pause);
}

void JohnExecutionBackend::stop(const QUuid &jobId)
{
    requestShutdown(jobId, Pending::Stop);
}

void JohnExecutionBackend::resume(const CrackingJob &job, const StartOptions &opts)
{
    // Reconstruct the context when resuming a job persisted before the app
    // restarted (never started in this process). john reloads the attack from
    // the .rec session file, so only session/restore plumbing is needed.
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
