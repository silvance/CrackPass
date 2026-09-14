/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
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
    void reportCarriesDictionaryProvenance();
    void redactionHidesPlaintext();
    void reportPrefersJobExtractionId();
    void legacyJobFallsBackToNewestExtraction();

private:
    // Add one artifact and two successful extractions (older then newer) for it,
    // returning the evidence id and each extraction's id. `newer` is created
    // strictly after `older`.
    static QUuid seedTwoExtractions(CaseWorkspace *ws, QTemporaryDir &src,
                                    QUuid &olderOut, QUuid &newerOut)
    {
        auto intake = ws->addEvidence([&] {
            const QString p = src.filePath("multi.pdf");
            QFile f(p); f.open(QIODevice::WriteOnly); f.write("%PDF-1.6\n/Encrypt"); f.close();
            return p;
        }());
        auto extractWith = [&](const QString &version) -> QUuid {
            FakeProcessRunner runner;
            runner.nextResult = FakeProcessRunner::ok("multi.pdf:$pdf$2*3*128*abc\n");
            ToolResolver tools;
            tools.setTool("pdf2john", ResolvedTool{true, "pdf2john", {}, version});
            ExtractionContext ctx; ctx.runner = &runner; ctx.tools = &tools;
            auto outcome = ws->extractHash(intake.item.id, ctx);
            return outcome.record.id;
        };
        olderOut = extractWith(QStringLiteral("vA"));
        QTest::qSleep(15); // guarantee a strictly newer endedUtc for the second
        newerOut = extractWith(QStringLiteral("vB"));
        return intake.item.id;
    }
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
    job.engineVersion = "v7.1.2";
    job.wordlists = {"rockyou.txt"};
    job.rules = {"best64.rule"};
    job.engineArgs = {"-m", "10500", "-a", "0", "hash.txt", "rockyou.txt", "-r", "best64.rule"};
    job.dictionary.id = "casekey-common";
    job.dictionary.displayName = "CaseKey Common";
    job.dictionary.path = "/dicts/casekey-common.txt";
    job.dictionary.sha256 = QString(64, QLatin1Char('d'));
    job.dictionary.candidateCount = 12345;
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
    QCOMPARE(r.engineVersion, QStringLiteral("v7.1.2"));
    QCOMPARE(r.engineArgs, (QStringList{"-m", "10500", "-a", "0", "hash.txt", "rockyou.txt", "-r", "best64.rule"}));
    QVERIFY(r.runtimeMs >= 42000);
    QCOMPARE(r.finalStatus, QStringLiteral("recovered"));
    QVERIFY(r.recovered);
    QCOMPARE(r.recoveredPlaintext, QStringLiteral("letmein"));
    QCOMPARE(r.recoveredKind, QStringLiteral("password")); // a password, labelled as such
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
    const QJsonObject cred = o.value("credential").toObject();
    QCOMPARE(cred.value("value").toString(), QStringLiteral("letmein"));
    QCOMPARE(cred.value("kind").toString(), QStringLiteral("password"));

    const QString html = ReportRenderer::toHtml(r);
    QVERIFY(html.contains("Recovery Report"));
    QVERIFY(html.contains(r.artifactSha256));
    QVERIFY(html.contains("letmein"));
    QVERIFY(html.contains("-m 10500"));
    QVERIFY(html.contains("Recovery engine")); // engine-neutral section, not "Hashcat environment"
}


void TestReportBuilder::reportCarriesDictionaryProvenance()
{
    QTemporaryDir caseDir, src;
    auto ws = CaseWorkspace::create(caseDir.path(), CaseInfo{});
    QVERIFY(ws);
    QUuid jobId;
    seedCase(ws.get(), src, jobId);
    const RecoveryReport r = ReportBuilder::build(*ws, ws->jobs().first(), "0.7.1");

    QCOMPARE(r.dictionaryId, QStringLiteral("casekey-common"));
    QCOMPARE(r.dictionaryName, QStringLiteral("CaseKey Common"));
    QCOMPARE(r.dictionaryCandidateCount, qint64(12345));

    const QJsonObject o = QJsonDocument::fromJson(ReportRenderer::toJson(r)).object();
    const QJsonObject dict = o.value("attack").toObject().value("dictionary").toObject();
    QCOMPARE(dict.value("id").toString(), QStringLiteral("casekey-common"));
    QCOMPARE(dict.value("sha256").toString().size(), 64);

    const QString html = ReportRenderer::toHtml(r);
    QVERIFY(html.contains("CaseKey Common"));
    QVERIFY(html.contains("Dictionary SHA-256"));
}

void TestReportBuilder::redactionHidesPlaintext()
{
    QTemporaryDir caseDir, src;
    auto ws = CaseWorkspace::create(caseDir.path(), CaseInfo{});
    QUuid jobId;
    seedCase(ws.get(), src, jobId);

    const RecoveryReport r = ReportBuilder::build(*ws, ws->jobs().first(), "0.7.1",
                                                  /*includePlaintext=*/false);
    QVERIFY(r.recovered);                                  // recovery still recorded
    QCOMPARE(r.recoveredPlaintext, QStringLiteral("[REDACTED]"));
    const QString html = ReportRenderer::toHtml(r);
    QVERIFY(!html.contains("letmein"));                    // plaintext not leaked
    QVERIFY(html.contains("[REDACTED]"));
    const QByteArray json = ReportRenderer::toJson(r);
    QVERIFY(!json.contains("letmein"));
}

// An artifact with several extractions: the report must name the EXACT one the
// job was bound to, even when it is not the newest. Reopen the case first.
void TestReportBuilder::reportPrefersJobExtractionId()
{
    QTemporaryDir caseDir, src;
    QString root;
    QUuid jobId, olderId, newerId, evId;
    {
        auto ws = CaseWorkspace::create(caseDir.path(), CaseInfo{});
        QVERIFY(ws);
        root = ws->rootPath();
        evId = seedTwoExtractions(ws.get(), src, olderId, newerId);

        CrackingJob job;
        job.id = QUuid::createUuid();
        job.caseId = ws->info().id;
        job.evidenceId = evId;
        job.extractionId = olderId; // bound to the OLDER extraction on purpose
        job.hashMode = 10500;
        job.state = JobState::Recovered;
        job.startedUtc = QDateTime::currentDateTimeUtc();
        job.endedUtc = job.startedUtc.addSecs(1);
        QVERIFY(ws->saveJob(job));
        jobId = job.id;
    }

    auto ws = CaseWorkspace::open(root);
    QVERIFY(ws);
    CrackingJob job;
    for (const CrackingJob &j : ws->jobs())
        if (j.id == jobId) job = j;
    QCOMPARE(job.extractionId, olderId); // survived serialization + reopen

    const RecoveryReport r = ReportBuilder::build(*ws, job, "x");
    QCOMPARE(r.extractionId, olderId.toString(QUuid::WithoutBraces));
    QCOMPARE(r.extractorVersion, QStringLiteral("vA")); // the bound one, not newest ("vB")
}

// A legacy job carries no extractionId: the report deterministically uses the
// NEWEST successful extraction for the artifact, not list/registration order.
void TestReportBuilder::legacyJobFallsBackToNewestExtraction()
{
    QTemporaryDir caseDir, src;
    QString root;
    QUuid jobId, olderId, newerId, evId;
    {
        auto ws = CaseWorkspace::create(caseDir.path(), CaseInfo{});
        QVERIFY(ws);
        root = ws->rootPath();
        evId = seedTwoExtractions(ws.get(), src, olderId, newerId);

        CrackingJob job;
        job.id = QUuid::createUuid();
        job.caseId = ws->info().id;
        job.evidenceId = evId; // extractionId left null (legacy record)
        job.hashMode = 10500;
        job.state = JobState::Recovered;
        QVERIFY(ws->saveJob(job));
        jobId = job.id;
    }

    auto ws = CaseWorkspace::open(root);
    QVERIFY(ws);
    CrackingJob job;
    for (const CrackingJob &j : ws->jobs())
        if (j.id == jobId) job = j;
    QVERIFY(job.extractionId.isNull());

    const RecoveryReport r = ReportBuilder::build(*ws, job, "x");
    QCOMPARE(r.extractionId, newerId.toString(QUuid::WithoutBraces));
    QCOMPARE(r.extractorVersion, QStringLiteral("vB")); // newest successful
}

QTEST_GUILESS_MAIN(TestReportBuilder)
#include "test_reportbuilder.moc"
