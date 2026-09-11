/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#include "forensic/caseworkspace.h"
#include "forensic/extraction/toolresolver.h"
#include "fakeprocessrunner.h"

#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <QtTest>

using namespace forensic;

class TestExtractionService : public QObject
{
    Q_OBJECT

private:
    static QString writeFile(QTemporaryDir &d, const QString &name, const QByteArray &b)
    {
        const QString p = d.filePath(name);
        QFile f(p); f.open(QIODevice::WriteOnly); f.write(b); f.close();
        return p;
    }

    static ExtractionContext ctx(FakeProcessRunner &r, ToolResolver &t)
    {
        ExtractionContext c; c.runner = &r; c.tools = &t; return c;
    }

private slots:
    void unambiguousExtractionPersistsAndAudits();
    void doesNotModifyEvidence();
    void ambiguousRequiresManualSelection();
    void reopenLoadsExtractions();
};

void TestExtractionService::unambiguousExtractionPersistsAndAudits()
{
    QTemporaryDir caseDir, src;
    auto ws = CaseWorkspace::create(caseDir.path(), CaseInfo{});
    QVERIFY(ws);
    const QString pdf = writeFile(src, "e.pdf", "%PDF-1.6\n/Encrypt ...");
    auto intake = ws->addEvidence(pdf);
    QVERIFY(intake.ok);

    FakeProcessRunner runner;
    runner.nextResult = FakeProcessRunner::ok("e.pdf:$pdf$2*3*128*deadbeef\n");
    ToolResolver tools;
    tools.setTool("pdf2john", ResolvedTool{true, "pdf2john", {}, ""});

    auto outcome = ws->extractHash(intake.item.id, ctx(runner, tools));
    QVERIFY2(outcome.ok, qPrintable(outcome.error));
    QCOMPARE(outcome.record.status, QStringLiteral("success"));
    QCOMPARE(outcome.record.selectedMode, 10500u);

    // hash.txt written separately from evidence, containing the extracted hash.
    const QString hashPath = QDir(ws->extractionsDir())
        .filePath(outcome.record.id.toString(QUuid::WithoutBraces) + "/hash.txt");
    QVERIFY(QFile::exists(hashPath));
    QFile hf(hashPath); hf.open(QIODevice::ReadOnly);
    QCOMPARE(QString::fromUtf8(hf.readAll()), QStringLiteral("$pdf$2*3*128*deadbeef"));

    // Audit chain includes the extraction and still verifies.
    bool sawExtract = false;
    for (const auto &ev : ws->audit().events())
        if (ev.action == QStringLiteral("hash_extracted")) sawExtract = true;
    QVERIFY(sawExtract);
    QVERIFY(ws->audit().verify());
}

void TestExtractionService::doesNotModifyEvidence()
{
    QTemporaryDir caseDir, src;
    auto ws = CaseWorkspace::create(caseDir.path(), CaseInfo{});
    const QString pdf = writeFile(src, "e.pdf", "%PDF-1.6\n/Encrypt secret bytes");
    auto intake = ws->addEvidence(pdf);
    const QByteArray before = [&]{ QFile f(pdf); f.open(QIODevice::ReadOnly); return f.readAll(); }();

    FakeProcessRunner runner;
    runner.nextResult = FakeProcessRunner::ok("e.pdf:$pdf$2*3*1*a");
    ToolResolver tools;
    tools.setTool("pdf2john", ResolvedTool{true, "pdf2john", {}, ""});
    ws->extractHash(intake.item.id, ctx(runner, tools));

    const QByteArray after = [&]{ QFile f(pdf); f.open(QIODevice::ReadOnly); return f.readAll(); }();
    QCOMPARE(after, before);
}

void TestExtractionService::ambiguousRequiresManualSelection()
{
    QTemporaryDir caseDir, src;
    auto ws = CaseWorkspace::create(caseDir.path(), CaseInfo{});
    // A ZIP with the encrypted-entry flag set so the analyzer tags it "zip".
    QByteArray zip("\x50\x4b\x03\x04\x14\x00\x01\x00", 8);
    zip.append(QByteArray(16, '\0'));
    auto intake = ws->addEvidence(writeFile(src, "a.zip", zip));
    QCOMPARE(intake.item.type.id, QStringLiteral("zip"));

    FakeProcessRunner runner;
    runner.nextResult = FakeProcessRunner::ok("a.zip:$pkzip2$1*1*2*0*ab*cd*ef");
    ToolResolver tools;
    tools.setTool("zip2john", ResolvedTool{true, "zip2john", {}, ""});

    auto outcome = ws->extractHash(intake.item.id, ctx(runner, tools));
    QVERIFY(outcome.ok);
    QVERIFY(outcome.result.modeAmbiguous());
    QCOMPARE(outcome.record.selectedMode, 0u); // never auto-guessed

    // Selecting a non-candidate mode is rejected; a candidate is accepted.
    QString err;
    QVERIFY(!ws->selectExtractionMode(outcome.record.id, 99999, &err));
    QVERIFY(ws->selectExtractionMode(outcome.record.id, 17210, &err));
    QCOMPARE(ws->extractions().first().selectedMode, 17210u);
}

void TestExtractionService::reopenLoadsExtractions()
{
    QTemporaryDir caseDir, src;
    QString root;
    QUuid extractionId;
    {
        auto ws = CaseWorkspace::create(caseDir.path(), CaseInfo{});
        root = ws->rootPath();
        auto intake = ws->addEvidence(writeFile(src, "e.pdf", "%PDF-1.6\n/Encrypt"));
        FakeProcessRunner runner;
        runner.nextResult = FakeProcessRunner::ok("e.pdf:$pdf$2*3*1*a");
        ToolResolver tools;
        tools.setTool("pdf2john", ResolvedTool{true, "pdf2john", {}, ""});
        auto outcome = ws->extractHash(intake.item.id, ctx(runner, tools));
        extractionId = outcome.record.id;
    }
    auto reopened = CaseWorkspace::open(root);
    QVERIFY(reopened);
    QCOMPARE(reopened->extractions().size(), 1);
    QCOMPARE(reopened->extractions().first().id, extractionId);
    QCOMPARE(reopened->extractions().first().selectedMode, 10500u);
}

QTEST_GUILESS_MAIN(TestExtractionService)
#include "test_extractionservice.moc"
