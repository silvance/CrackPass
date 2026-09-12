/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "integrationchain.h"

#include "forensic/caseworkspace.h"
#include "forensic/extraction/processrunner.h"
#include "forensic/extraction/toolresolver.h"
#include "forensic/execution/hashcatexecutionbackend.h"
#include "forensic/execution/jobqueue.h"
#include "forensic/planner/attackcommandbuilder.h"
#include "forensic/planner/attackjobspec.h"
#include "forensic/report/reportbuilder.h"
#include "forensic/report/reportrenderer.h"

#include <QDir>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QEventLoop>
#include <QFile>
#include <QTextStream>
#include <QTimer>

namespace forensic { namespace itest {

QString extractorForType(const QString &t)
{
    if (t == QStringLiteral("ms-office"))    return QStringLiteral("office2john");
    if (t == QStringLiteral("pdf"))          return QStringLiteral("pdf2john");
    if (t == QStringLiteral("zip"))          return QStringLiteral("zip2john");
    if (t == QStringLiteral("rar"))          return QStringLiteral("rar2john");
    if (t == QStringLiteral("7z"))           return QStringLiteral("7z2john");
    if (t == QStringLiteral("keepass-kdbx")) return QStringLiteral("keepass2john");
    return QString();
}

namespace {

// Drives the real JobQueue + hashcat backend for one mode, returning the
// recovered plaintext (empty if not recovered within the timeout).
QString crackOnce(const IntegrationEnv &env, CaseWorkspace &ws, const EvidenceItem &item,
                  const QString &hashFile, quint32 mode, const QString &wordlist, int timeoutMs)
{
    HashcatExecutionBackend backend(env.hashcat.program);
    JobQueue queue(&backend);

    AttackJobSpec spec;
    spec.hashMode = mode;
    spec.attackMode = AttackModeNum::Straight;
    spec.hashFile = hashFile;
    spec.wordlists = {wordlist};

    CrackingJob job;
    job.id = QUuid::createUuid();
    job.caseId = ws.info().id;
    job.evidenceId = item.id;
    job.hashMode = mode;
    job.attackMode = spec.attackMode;
    job.hashFile = hashFile;
    job.wordlists = spec.wordlists;
    job.hashcatPath = env.hashcat.program;
    job.hashcatArgs = AttackCommandBuilder::buildArgs(spec);

    const QString jobDir = ws.jobDir(job.id);
    QDir().mkpath(jobDir);
    JobQueue::JobPaths paths;
    paths.workingDir = jobDir;
    paths.sessionName = QStringLiteral("itest-") + job.id.toString(QUuid::WithoutBraces).left(8);
    paths.potfilePath = QDir(jobDir).filePath(QStringLiteral("job.potfile"));
    paths.outfilePath = QDir(jobDir).filePath(QStringLiteral("cracked.out"));
    paths.restorePath = QDir(jobDir).filePath(QStringLiteral("session.restore"));

    QString recovered;
    CrackingJob finalJob = job;
    QEventLoop loop;
    QObject::connect(&queue, &JobQueue::credentialRecovered, &loop,
                     [&](const RecoveredCredential &c) { recovered = c.plaintext; loop.quit(); });
    QObject::connect(&queue, &JobQueue::jobChanged, &loop, [&](const CrackingJob &j) {
        if (j.id != job.id)
            return;
        finalJob = j; // keep the latest state/timing/devices the queue recorded
        if (j.state == JobState::Exhausted || j.state == JobState::Failed
            || j.state == JobState::Stopped || j.state == JobState::Recovered)
            loop.quit();
    });
    QTimer::singleShot(timeoutMs, &loop, [&] { loop.quit(); });

    queue.enqueue(job, paths);
    loop.exec();

    // Persist the job so it is part of the case state (reporting reads
    // ws.jobs()) and case association is real.
    ws.saveJob(finalJob);
    if (!recovered.isEmpty()) {
        RecoveredCredential c;
        c.caseId = ws.info().id;
        c.jobId = job.id;
        c.evidenceId = item.id;
        c.plaintext = recovered;
        ws.addRecoveredCredential(c);
    }
    return recovered;
}

} // namespace

ChainResult runChain(const IntegrationEnv &env, const QString &caseParentDir,
                     const FixtureSpec &fixture, const QString &extractorToolId, int hashcatTimeoutMs)
{
    ChainResult r;

    r.stage = QStringLiteral("case-open");
    QString err;
    auto ws = CaseWorkspace::create(caseParentDir, CaseInfo{}, &err);
    if (!ws) { r.message = err; return r; }

    r.stage = QStringLiteral("intake");
    auto intake = ws->addEvidence(fixture.path);
    if (!intake.ok) { r.message = intake.error; return r; }
    const EvidenceItem item = intake.item;
    r.sha256Before = item.sha256;

    r.stage = QStringLiteral("content-detection");
    r.detectedType = item.type.id;
    if (!fixture.expectedType.isEmpty() && fixture.expectedType != QStringLiteral("unknown")
        && item.type.id != fixture.expectedType) {
        r.message = QStringLiteral("detected '%1', expected '%2'").arg(item.type.id, fixture.expectedType);
        return r;
    }

    // Non-encrypted / malformed fixtures: success means extraction does NOT
    // falsely produce a crackable hash.
    if (!fixture.encrypted) {
        r.stage = QStringLiteral("negative-extraction");
        forensic::ToolResolver tools;
        const ToolInfo ti = env.extractors.value(extractorToolId);
        if (ti.available)
            tools.setTool(extractorToolId, forensic::ResolvedTool{true, ti.program, ti.prefixArgs, ti.version});
        forensic::QtProcessRunner runner;
        forensic::ExtractionContext ctx; ctx.runner = &runner; ctx.tools = &tools;
        auto outcome = ws->extractHash(item.id, ctx);
        // Either no extractor, or it correctly produced no usable hash.
        r.ok = !outcome.ok || outcome.result.status != forensic::ExtractionStatus::Success
               || outcome.result.hash.isEmpty();
        r.message = r.ok ? QStringLiteral("no false hash produced") : QStringLiteral("unexpected hash from non-encrypted artifact");
        r.sha256After = ws->verifyEvidenceIntegrity(item.id).currentSha256;
        return r;
    }

    r.stage = QStringLiteral("extraction");
    forensic::ToolResolver tools;
    const ToolInfo ti = env.extractors.value(extractorToolId);
    if (!ti.available) { r.message = QStringLiteral("extractor %1 unavailable").arg(extractorToolId); return r; }
    tools.setTool(extractorToolId, forensic::ResolvedTool{true, ti.program, ti.prefixArgs, ti.version});
    forensic::QtProcessRunner runner;
    forensic::ExtractionContext ctx; ctx.runner = &runner; ctx.tools = &tools;
    auto outcome = ws->extractHash(item.id, ctx);
    if (!outcome.ok || outcome.result.status != forensic::ExtractionStatus::Success) {
        r.message = outcome.ok ? outcome.result.message : outcome.error;
        return r;
    }
    r.extractedHash = outcome.result.hash;

    r.stage = QStringLiteral("mode-resolution");
    QVector<quint32> modes;
    for (const auto &m : outcome.result.candidateModes)
        modes << m.mode;
    if (modes.isEmpty()) { r.message = QStringLiteral("no candidate hashcat mode"); return r; }

    // Tiny wordlist containing the known password + decoys.
    const QString wl = QDir(ws->rootPath()).filePath(QStringLiteral("itest_wordlist.txt"));
    { QFile f(wl); f.open(QIODevice::WriteOnly | QIODevice::Text);
      QTextStream ts(&f); ts.setEncoding(QStringConverter::Utf8);
      ts << "decoy1\n" << fixture.expectedPassword << "\n" << "decoy2\n"; }

    const QString hashFile = QDir(ws->extractionsDir())
        .filePath(outcome.record.id.toString(QUuid::WithoutBraces) + "/hash.txt");

    r.stage = QStringLiteral("hashcat-recovery");
    // Try each candidate mode until one recovers (handles ambiguous families).
    for (quint32 mode : modes) {
        const QString rec = crackOnce(env, *ws, item, hashFile, mode, wl, hashcatTimeoutMs / modes.size());
        if (!rec.isEmpty()) { r.recovered = rec; r.modeUsed = mode; break; }
    }
    if (r.recovered.isEmpty()) { r.message = QStringLiteral("hashcat did not recover the password"); return r; }
    if (r.recovered != fixture.expectedPassword) {
        r.message = QStringLiteral("recovered '%1' != expected '%2'").arg(r.recovered, fixture.expectedPassword);
        return r;
    }

    r.stage = QStringLiteral("case-association");
    bool associated = false;
    for (const auto &c : ws->recoveredCredentials())
        if (c.evidenceId == item.id && c.plaintext == fixture.expectedPassword) associated = true;
    if (!associated) { r.message = QStringLiteral("credential not associated to evidence/case"); return r; }

    r.stage = QStringLiteral("integrity");
    const auto integ = ws->verifyEvidenceIntegrity(item.id);
    r.sha256After = integ.currentSha256;
    if (!integ.ok) { r.message = QStringLiteral("evidence SHA-256 changed during processing"); return r; }

    r.stage = QStringLiteral("report");
    if (ws->jobs().isEmpty()) { r.message = QStringLiteral("no job persisted for reporting"); return r; }
    const auto rep = forensic::ReportBuilder::build(*ws, ws->jobs().last(), QStringLiteral("itest"));
    const QString html = forensic::ReportRenderer::toHtml(rep);
    r.reportWritten = html.contains(item.sha256) && !forensic::ReportRenderer::toJson(rep).isEmpty();
    if (!r.reportWritten) { r.message = QStringLiteral("report missing expected content"); return r; }

    r.ok = true;
    r.stage = QStringLiteral("complete");
    r.message = QStringLiteral("recovered '%1' with -m %2").arg(r.recovered).arg(r.modeUsed);
    return r;
}


QVector<FixtureSpec> loadCorpus(const QString &dir)
{
    QVector<FixtureSpec> out;
    QFile f(QDir(dir).filePath(QStringLiteral("manifest.json")));
    if (!f.open(QIODevice::ReadOnly))
        return out;
    const QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
    for (const QJsonValue &v : doc.object().value(QStringLiteral("fixtures")).toArray()) {
        const QJsonObject o = v.toObject();
        FixtureSpec fx;
        fx.path = QDir(dir).filePath(o.value(QStringLiteral("file")).toString());
        fx.expectedType = o.value(QStringLiteral("type")).toString();
        fx.encrypted = o.value(QStringLiteral("encrypted")).toBool();
        fx.expectedPassword = o.value(QStringLiteral("password")).toString();
        out.append(fx);
    }
    return out;
}

}} // namespace forensic::itest
