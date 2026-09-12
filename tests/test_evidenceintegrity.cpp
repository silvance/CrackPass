/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#include "forensic/caseworkspace.h"
#include "forensic/extraction/toolresolver.h"
#include "fakeprocessrunner.h"

#include <QFile>
#include <QTemporaryDir>
#include <QtTest>

using namespace forensic;

class TestEvidenceIntegrity : public QObject
{
    Q_OBJECT
private:
    static QString writePdf(const QString &path, const QByteArray &body)
    {
        QFile f(path); f.open(QIODevice::WriteOnly); f.write(QByteArray("%PDF-1.6\n") + body); f.close();
        return path;
    }
    static ExtractionContext ctx(FakeProcessRunner &r, ToolResolver &t)
    { ExtractionContext c; c.runner=&r; c.tools=&t; return c; }

private slots:
    void matchesAtIntake();
    void detectsModifiedReferencedEvidence();
    void extractionRefusesOnMismatch();
    void unreadableEvidenceFailsLoudly();
    void workingCopyImportIsReadInsteadOfOriginal();
};

void TestEvidenceIntegrity::matchesAtIntake()
{
    QTemporaryDir caseDir, src;
    auto ws = CaseWorkspace::create(caseDir.path(), CaseInfo{});
    auto r = ws->addEvidence(writePdf(src.filePath("a.pdf"), "orig"));
    QVERIFY(r.ok);
    const auto ir = ws->verifyEvidenceIntegrity(r.item.id);
    QVERIFY(ir.checked);
    QVERIFY(ir.ok);
    QCOMPARE(ir.currentSha256, ir.recordedSha256);
}

void TestEvidenceIntegrity::detectsModifiedReferencedEvidence()
{
    QTemporaryDir caseDir, src;
    auto ws = CaseWorkspace::create(caseDir.path(), CaseInfo{});
    const QString path = writePdf(src.filePath("a.pdf"), "orig");
    auto r = ws->addEvidence(path);
    QVERIFY(r.ok);
    // Tamper with the referenced original after intake.
    { QFile f(path); f.open(QIODevice::WriteOnly | QIODevice::Append); f.write("tampered"); f.close(); }

    const auto ir = ws->verifyEvidenceIntegrity(r.item.id);
    QVERIFY(ir.checked);
    QVERIFY(!ir.ok);                       // mismatch detected
    QVERIFY(ir.currentSha256 != ir.recordedSha256);
    // The mismatch is recorded in the (still-valid) audit chain.
    bool audited = false;
    for (const auto &e : ws->audit().events())
        if (e.action == QStringLiteral("integrity_mismatch")) audited = true;
    QVERIFY(audited);
    QVERIFY(ws->audit().verify());
}

void TestEvidenceIntegrity::extractionRefusesOnMismatch()
{
    QTemporaryDir caseDir, src;
    auto ws = CaseWorkspace::create(caseDir.path(), CaseInfo{});
    const QString path = writePdf(src.filePath("a.pdf"), "/Encrypt orig");
    auto r = ws->addEvidence(path);
    { QFile f(path); f.open(QIODevice::WriteOnly | QIODevice::Append); f.write("x"); f.close(); }

    FakeProcessRunner runner;
    runner.nextResult = FakeProcessRunner::ok("a.pdf:$pdf$2*3*1*a");
    ToolResolver tools; tools.setTool("pdf2john", ResolvedTool{true, "pdf2john", {}, ""});

    auto outcome = ws->extractHash(r.item.id, ctx(runner, tools));
    QVERIFY(!outcome.ok);                   // extraction refused
    QVERIFY(outcome.error.contains("integrity", Qt::CaseInsensitive));
    QCOMPARE(runner.calls, 0);              // extractor never ran on altered data
}

void TestEvidenceIntegrity::unreadableEvidenceFailsLoudly()
{
    QTemporaryDir caseDir, src;
    auto ws = CaseWorkspace::create(caseDir.path(), CaseInfo{});
    const QString path = writePdf(src.filePath("a.pdf"), "orig");
    auto r = ws->addEvidence(path);
    QFile::remove(path);                    // evidence no longer present

    const auto ir = ws->verifyEvidenceIntegrity(r.item.id);
    QVERIFY(!ir.checked);                    // could not read
    QVERIFY(!ir.ok);
    QVERIFY(!ir.error.isEmpty());
}

void TestEvidenceIntegrity::workingCopyImportIsReadInsteadOfOriginal()
{
    QTemporaryDir caseDir, src;
    auto ws = CaseWorkspace::create(caseDir.path(), CaseInfo{});
    const QString path = writePdf(src.filePath("a.pdf"), "orig");
    auto r = ws->addEvidence(path, EvidenceStorageMode::WorkingCopy);
    QVERIFY2(r.ok, qPrintable(r.error));
    QVERIFY(!r.item.workingCopyPath.isEmpty());

    // Deleting the ORIGINAL must not affect integrity: reads use the copy.
    QFile::remove(path);
    const auto ir = ws->verifyEvidenceIntegrity(r.item.id);
    QVERIFY(ir.ok);
    QVERIFY(ws->evidenceReadPath(r.item).contains("source.bin"));
}

QTEST_GUILESS_MAIN(TestEvidenceIntegrity)
#include "test_evidenceintegrity.moc"
