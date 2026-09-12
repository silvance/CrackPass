/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#include "forensic/deps/dependencyprobe.h"
#include "fakeprocessrunner.h"

#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <QtTest>

using namespace forensic;

class TestDependencyProbe : public QObject
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
    void settingsOverrideWins();
    void portableLayoutDiscovered();
    void missingToolReported();
    void hashcatSelfTestParsesVersion();
    void hashcatSelfTestFailureReported();
    void resourcesReported();
};

void TestDependencyProbe::settingsOverrideWins()
{
    QTemporaryDir dir;
    const QString custom = dir.filePath("bin/hashcat");
    touchExe(custom);
    // Also create a portable copy that must be ignored in favor of the override.
    touchExe(dir.filePath("app/tools/hashcat/hashcat"));

    auto settings = [&](const QString &k) { return k == "hashcatPath" ? custom : QString(); };
    DependencyProbe probe(nullptr, dir.filePath("app"), settings);
    const ToolStatus t = probe.resolveTool("hashcat", "hashcatPath");
    QVERIFY(t.found);
    QCOMPARE(t.source, QStringLiteral("settings"));
    QCOMPARE(t.program, QFileInfo(custom).absoluteFilePath());
}

void TestDependencyProbe::portableLayoutDiscovered()
{
    QTemporaryDir dir;
    const QString appDir = dir.filePath("app");
    touchExe(QDir(appDir).filePath("tools/hashcat/hashcat"));
    auto settings = [](const QString &) { return QString(); };
    DependencyProbe probe(nullptr, appDir, settings);
    const ToolStatus t = probe.resolveTool("hashcat", "hashcatPath");
    QVERIFY(t.found);
    QCOMPARE(t.source, QStringLiteral("portable"));
}

void TestDependencyProbe::missingToolReported()
{
    QTemporaryDir dir;
    auto settings = [](const QString &) { return QString(); };
    DependencyProbe probe(nullptr, dir.filePath("app"), settings);
    const ToolStatus t = probe.resolveTool("keepass2john", "tools/keepass2john");
    QVERIFY(!t.found);
    QVERIFY(!t.detail.isEmpty());
}

void TestDependencyProbe::hashcatSelfTestParsesVersion()
{
    QTemporaryDir dir;
    const QString hc = dir.filePath("app/tools/hashcat/hashcat");
    touchExe(hc);
    FakeProcessRunner runner;
    runner.nextResult = FakeProcessRunner::ok("v7.1.2\n");
    auto settings = [](const QString &) { return QString(); };
    DependencyProbe probe(&runner, dir.filePath("app"), settings);
    const DependencyReport rep = probe.run();
    QVERIFY(rep.hashcat.found);
    QVERIFY(rep.hashcat.selfTestRun);
    QVERIFY(rep.hashcat.selfTestOk);
    QCOMPARE(rep.hashcat.version, QStringLiteral("v7.1.2"));
}

void TestDependencyProbe::hashcatSelfTestFailureReported()
{
    QTemporaryDir dir;
    touchExe(dir.filePath("app/tools/hashcat/hashcat"));
    FakeProcessRunner runner;
    ProcessRunner::Result bad; bad.started = true; bad.exitCode = 1; bad.stdErr = "boom";
    runner.nextResult = bad;
    auto settings = [](const QString &) { return QString(); };
    DependencyProbe probe(&runner, dir.filePath("app"), settings);
    const DependencyReport rep = probe.run();
    QVERIFY(rep.hashcat.found);
    QVERIFY(rep.hashcat.selfTestRun);
    QVERIFY(!rep.hashcat.selfTestOk);
}

void TestDependencyProbe::resourcesReported()
{
    QTemporaryDir dir;
    const QString appDir = dir.filePath("app");
    // rules under portable default
    const QString rules = QDir(appDir).filePath("tools/rules");
    QDir().mkpath(rules);
    { QFile f(QDir(rules).filePath("best64.rule")); f.open(QIODevice::WriteOnly); f.write(":\n"); }
    const QString wl = dir.filePath("words.txt");
    { QFile f(wl); f.open(QIODevice::WriteOnly); f.write("password\n"); }
    const QString caseRoot = dir.filePath("cases");
    QDir().mkpath(caseRoot);

    auto settings = [&](const QString &k) -> QString {
        if (k == "commonWordlist") return wl;
        if (k == "caseRoot") return caseRoot;
        return QString();
    };
    DependencyProbe probe(nullptr, appDir, settings);
    const DependencyReport rep = probe.run();
    QVERIFY(rep.resources.commonWordlistOk);
    QVERIFY(rep.resources.rules.contains("best64.rule"));
    QVERIFY(rep.resources.caseRootWritable);
    QVERIFY(rep.resources.freeBytes >= 0);
}

QTEST_GUILESS_MAIN(TestDependencyProbe)
#include "test_dependencyprobe.moc"
