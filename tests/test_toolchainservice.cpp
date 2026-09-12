/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "forensic/deps/toolchainservice.h"
#include "fakeprocessrunner.h"

#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <QtTest>

using namespace forensic;

class TestToolchainService : public QObject
{
    Q_OBJECT
private:
    static void touchExe(const QString &path)
    {
        QDir().mkpath(QFileInfo(path).absolutePath());
        QFile f(path); f.open(QIODevice::WriteOnly); f.write("#!/bin/sh\n"); f.close();
        QFile::setPermissions(path, QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner);
    }

private slots:
    void extractionResolverMatchesReport();
    void extractionResolverHonoursSettingsOverride();
    void unresolvedExtractorIsNotFound();
};

// The whole point of the service: what the Doctor reports for an extractor must
// be exactly what extraction would run. Resolve every extractor two ways and
// compare.
void TestToolchainService::extractionResolverMatchesReport()
{
    QTemporaryDir dir;
    const QString appDir = dir.filePath("app");
    // A portable native extractor and a script extractor (must gain a python prefix).
    touchExe(QDir(appDir).filePath("tools/john/run/zip2john"));
    touchExe(QDir(appDir).filePath("tools/john/run/office2john.py"));

    auto settings = [](const QString &) { return QString(); };
    ToolchainService svc(nullptr, appDir, settings);

    const ToolResolver resolver = svc.extractionResolver();
    const DependencyReport rep = svc.report();

    for (const ToolStatus &s : rep.extractors) {
        const ResolvedTool r = resolver.resolve(s.id);
        QCOMPARE(r.found, s.found);
        QCOMPARE(r.program, s.program);
        QCOMPARE(r.prefixArgs, s.prefixArgs);
    }

    // The script extractor resolves through an interpreter: the script itself is
    // recorded as a prefix arg (whether or not the interpreter is installed on
    // this machine), which the old settings-only resolver never did.
    const ResolvedTool office = resolver.resolve(QStringLiteral("office2john"));
    QVERIFY(!office.prefixArgs.isEmpty());
    QVERIFY(office.prefixArgs.first().endsWith(QStringLiteral("office2john.py")));

    // A native tool is found and needs no interpreter prefix (deterministic,
    // independent of any installed interpreter).
    const ResolvedTool zip = resolver.resolve(QStringLiteral("zip2john"));
    QVERIFY(zip.found);
    QVERIFY(zip.prefixArgs.isEmpty());
}

void TestToolchainService::extractionResolverHonoursSettingsOverride()
{
    QTemporaryDir dir;
    const QString appDir = dir.filePath("app");
    const QString custom = dir.filePath("custom/pdf2john"); // native, no interpreter
    touchExe(custom);

    auto settings = [&](const QString &k) {
        return k == QStringLiteral("tools/pdf2john") ? custom : QString();
    };
    ToolchainService svc(nullptr, appDir, settings);

    const ResolvedTool r = svc.resolveExtractor(QStringLiteral("pdf2john"));
    QVERIFY(r.found);
    QCOMPARE(r.program, QFileInfo(custom).absoluteFilePath());
    QVERIFY(svc.extractionResolver().has(QStringLiteral("pdf2john")));
}

void TestToolchainService::unresolvedExtractorIsNotFound()
{
    QTemporaryDir dir;
    auto settings = [](const QString &) { return QString(); };
    ToolchainService svc(nullptr, dir.filePath("app"), settings);
    QVERIFY(!svc.extractionResolver().has(QStringLiteral("keepass2john")));
}

QTEST_GUILESS_MAIN(TestToolchainService)
#include "test_toolchainservice.moc"
