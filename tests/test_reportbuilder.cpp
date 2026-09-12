/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#include "forensic/caseworkspace.h"
#include "forensic/report/reportbuilder.h"
#include "forensic/report/reportrenderer.h"
#include "forensic/extraction/toolresolver.h"
#include "fakeprocessrunner.h"

#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryDir>
#include <QtTest>

using namespace forensic;

class TestReportBuilder : public QObject
{
    Q_OBJECT
private:
    static QString writeFile(QTemporaryDir &d, const QString &n, const QByteArray &b)
    {
        const QString p = d.filePath(n);
        QFile f(p); f.open(QIODevice::WriteOnly); f.write(b); f.close();
        return p;
    }

private slots:
    void buildsFullReportWithRecovery();
    void jsonAndHtmlContainKeyFields();
};

// Builds a case with an artifact, an extraction, a job, and a recovered
// credential, then reports on it.
static void seedCase(CaseWorkspace *ws, QTemporaryDir &src, QUuid &jobIdOut)
{
    const QString pdf = TestReportBuilder{}.metaObject() ? QString() : QString();
    Q_UNUSED(pdf);
    auto intake = ws->addEvidence([&] {
        const QString p = src.filePath("secret.pdf");
        QFile f(p); f.open(QIODevice::WriteOnly); f.write("%PDF-1.6\n/Encrypt"); f.close();
        return p;
    }());

    FakeProcessRunner runner;
    runner.nextResult = FakeProcessRunner::ok("secret.pdf:$pdf$2*3*128*abc\n");
    ToolResolver tools;
    tools.setTool("pdf2john", ResolvedTool{true, "pdf2john", {}, "jumbo-1.9"});
    ExtractionContext ctx; ctx.runner = &runner; ctx.tools = &tools;
    ws->extractHash(intake.item.id, ctx);

    CrackingJob job;
    job.id = QUuid::createUuid();
    job.caseId = ws->info().id;
    job.evidenceId = intake.item.id;
    job.hashMode = 10500;
    job.attackMode = 0;
    job.hashcatVersion = "v7.1.2";
    job.wordlists = {"rockyou.txt"};
    job.rules = {"best64.rule"};
    job.hashcatArgs = {"-m", "10500", "-a", "0", "hash.txt", "rockyou.txt", "-r", "best64.rule"};
    job.startedUtc = QDateTime::currentDateTimeUtc();
    job.endedUtc = job.startedUtc.addSecs(42);
    job.state = JobState::Recovered;
    ws->saveJob(job);

    RecoveredCredential c;
    c.jobId = job.id;
    c.evidenceId = intake.item.id;
    c.hash = "$pdf$2*3*128*abc";
    c.plaintext = "letmein";
    c.recoveredUtc = QDateTime::currentDateTimeUtc();
    ws->addRecoveredCredential(c);

    jobIdOut = job.id;
}

void TestReportBuilder::buildsFullReportWithRecovery()
{
    QTemporaryDir caseDir, src;
    auto ws = CaseWorkspace::create(caseDir.path(), CaseInfo{});
    QVERIFY(ws);
    QUuid jobId;
    seedCase(ws.get(), src, jobId);

    const RecoveryReport r = ReportBuilder::build(*ws, ws->jobs().first(), "0.7.1");
    QCOMPARE(r.applicationVersion, QStringLiteral("0.7.1"));
    QCOMPARE(r.artifactFilename, QStringLiteral("secret.pdf"));
    QCOMPARE(r.artifactSha256.size(), 64);
    QCOMPARE(r.detectedType, QStringLiteral("PDF document"));
    QCOMPARE(r.extractorId, QStringLiteral("pdf2john"));
    QCOMPARE(r.extractorVersion, QStringLiteral("jumbo-1.9"));
    QCOMPARE(r.hashMode, 10500u);
    QCOMPARE(r.hashModeName, QStringLiteral("PDF 1.4-1.6 (Acrobat 5-8)"));
    QCOMPARE(r.attackStrategy, QStringLiteral("Straight (dictionary)"));
    QCOMPARE(r.wordlists, QStringList{"rockyou.txt"});
    QCOMPARE(r.hashcatVersion, QStringLiteral("v7.1.2"));
    QVERIFY(r.runtimeMs >= 42000);
    QCOMPARE(r.finalStatus, QStringLiteral("recovered"));
    QVERIFY(r.recovered);
    QCOMPARE(r.recoveredPlaintext, QStringLiteral("letmein"));
}

void TestReportBuilder::jsonAndHtmlContainKeyFields()
{
    QTemporaryDir caseDir, src;
    auto ws = CaseWorkspace::create(caseDir.path(), CaseInfo{});
    QUuid jobId;
    seedCase(ws.get(), src, jobId);
    const RecoveryReport r = ReportBuilder::build(*ws, ws->jobs().first(), "0.7.1");

    const QByteArray json = ReportRenderer::toJson(r);
    const QJsonObject o = QJsonDocument::fromJson(json).object();
    QVERIFY(o.contains("artifact"));
    QCOMPARE(o.value("artifact").toObject().value("sha256").toString(), r.artifactSha256);
    QCOMPARE(o.value("credential").toObject().value("plaintext").toString(), QStringLiteral("letmein"));

    const QString html = ReportRenderer::toHtml(r);
    QVERIFY(html.contains("Password Recovery Report"));
    QVERIFY(html.contains(r.artifactSha256));
    QVERIFY(html.contains("letmein"));
    QVERIFY(html.contains("-m 10500"));
}

QTEST_GUILESS_MAIN(TestReportBuilder)
#include "test_reportbuilder.moc"
