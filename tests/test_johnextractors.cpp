/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "forensic/extraction/johnextractors.h"
#include "forensic/extraction/toolresolver.h"
#include "fakeprocessrunner.h"

#include <QtTest>

using namespace forensic;

class TestJohnExtractors : public QObject
{
    Q_OBJECT

private:
    static EvidenceItem pdfItem()
    {
        EvidenceItem e;
        e.id = QUuid::createUuid();
        e.originalPath = QStringLiteral("/evidence/secret.pdf");
        e.type = ArtifactType{"pdf", "PDF", 0.95};
        return e;
    }

    static ExtractionContext ctxWith(FakeProcessRunner &runner, ToolResolver &tools)
    {
        ExtractionContext ctx;
        ctx.runner = &runner;
        ctx.tools = &tools;
        return ctx;
    }

private slots:
    void normalizeStripsFilenamePrefix();
    void successProducesHashAndMode();
    void toolUnavailable();
    void noHashProduced();
    void launchFailure();
    void argvUsesOriginalPathReadOnly();
    void bitlockerUsesInputFlagAndResolvesMode();
};

void TestJohnExtractors::normalizeStripsFilenamePrefix()
{
    QCOMPARE(John2HashExtractor::normalizeHashLine("secret.pdf:$pdf$2*3*128*x"),
             QStringLiteral("$pdf$2*3*128*x"));
    // Windows-style path with a drive colon must not confuse the split.
    QCOMPARE(John2HashExtractor::normalizeHashLine("C:\\ev\\a.7z:$7z$0$aaa"),
             QStringLiteral("$7z$0$aaa"));
    QVERIFY(John2HashExtractor::normalizeHashLine("no hash here").isEmpty());
}

void TestJohnExtractors::successProducesHashAndMode()
{
    FakeProcessRunner runner;
    runner.nextResult = FakeProcessRunner::ok("secret.pdf:$pdf$2*3*128*abc\n");
    ToolResolver tools;
    tools.setTool("pdf2john", ResolvedTool{true, "pdf2john", {}, "jumbo"});

    PdfHashExtractor ex;
    const ExtractionResult r = ex.extract(pdfItem(), ctxWith(runner, tools));
    QCOMPARE(r.status, ExtractionStatus::Success);
    QCOMPARE(r.hash, QStringLiteral("$pdf$2*3*128*abc"));
    QCOMPARE(r.candidateModes.size(), 1);
    QCOMPARE(r.candidateModes.first().mode, 10500u);
    QVERIFY(!r.modeAmbiguous());
}

void TestJohnExtractors::toolUnavailable()
{
    FakeProcessRunner runner;
    ToolResolver tools; // pdf2john not registered
    PdfHashExtractor ex;
    const ExtractionResult r = ex.extract(pdfItem(), ctxWith(runner, tools));
    QCOMPARE(r.status, ExtractionStatus::ToolUnavailable);
    QCOMPARE(runner.calls, 0); // never attempted to run
}

void TestJohnExtractors::noHashProduced()
{
    FakeProcessRunner runner;
    runner.nextResult = FakeProcessRunner::ok(""); // ran, but no hash
    ToolResolver tools;
    tools.setTool("pdf2john", ResolvedTool{true, "pdf2john", {}, ""});
    PdfHashExtractor ex;
    const ExtractionResult r = ex.extract(pdfItem(), ctxWith(runner, tools));
    QCOMPARE(r.status, ExtractionStatus::NoHashProduced);
}

void TestJohnExtractors::launchFailure()
{
    FakeProcessRunner runner;
    ProcessRunner::Result fail;
    fail.started = false;
    fail.error = "boom";
    runner.nextResult = fail;
    ToolResolver tools;
    tools.setTool("pdf2john", ResolvedTool{true, "pdf2john", {}, ""});
    PdfHashExtractor ex;
    const ExtractionResult r = ex.extract(pdfItem(), ctxWith(runner, tools));
    QCOMPARE(r.status, ExtractionStatus::Failed);
}

void TestJohnExtractors::argvUsesOriginalPathReadOnly()
{
    FakeProcessRunner runner;
    runner.nextResult = FakeProcessRunner::ok("x:$pdf$2*3*1*a");
    ToolResolver tools;
    tools.setTool("pdf2john", ResolvedTool{true, "python", {"pdf2john.py"}, ""});
    PdfHashExtractor ex;
    ex.extract(pdfItem(), ctxWith(runner, tools));
    QCOMPARE(runner.lastProgram, QStringLiteral("python"));
    QCOMPARE(runner.lastArgs, (QStringList{"pdf2john.py", "/evidence/secret.pdf"}));
}

void TestJohnExtractors::bitlockerUsesInputFlagAndResolvesMode()
{
    EvidenceItem e;
    e.id = QUuid::createUuid();
    e.originalPath = QStringLiteral("/evidence/disk.raw");
    e.type = ArtifactType{"bitlocker", "BitLocker volume", 0.97};

    FakeProcessRunner runner;
    runner.nextResult = FakeProcessRunner::ok("disk.raw:$bitlocker$0$16$aaaa$...\n");
    ToolResolver tools;
    tools.setTool("bitlocker2john", ResolvedTool{true, "bitlocker2john", {}, ""});

    BitLockerHashExtractor ex;
    const ExtractionResult r = ex.extract(e, ctxWith(runner, tools));
    QCOMPARE(r.status, ExtractionStatus::Success);
    QCOMPARE(r.hash, QStringLiteral("$bitlocker$0$16$aaaa$..."));
    QCOMPARE(r.candidateModes.size(), 1);
    QCOMPARE(r.candidateModes.first().mode, 22100u);
    // bitlocker2john takes its input via -i, not positionally.
    QCOMPARE(runner.lastArgs, (QStringList{"-i", "/evidence/disk.raw"}));
}

QTEST_GUILESS_MAIN(TestJohnExtractors)
#include "test_johnextractors.moc"
