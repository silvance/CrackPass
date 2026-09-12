/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "forensic/caseworkspace.h"

#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <QtTest>

using forensic::CaseInfo;
using forensic::CaseWorkspace;

class TestCaseWorkspace : public QObject
{
    Q_OBJECT

private:
    static QString makePdf(QTemporaryDir &dir)
    {
        const QString path = dir.filePath("evidence.pdf");
        QFile f(path);
        f.open(QIODevice::WriteOnly);
        f.write("%PDF-1.6\nsome encrypted content");
        f.close();
        return path;
    }

private slots:
    void createScaffoldsDirsAndManifest();
    void addEvidenceCapturesMetadataAndType();
    void addEvidenceDoesNotModifySource();
    void reopenPersistsEvidenceAndAudit();
    void auditChainRecordsActions();
    void probeEncryptionUsesWorkingCopyWhenOriginalGone();
};

void TestCaseWorkspace::createScaffoldsDirsAndManifest()
{
    QTemporaryDir dir;
    CaseInfo info; info.name = "Op Test"; info.examiner = "Alice";
    QString error;
    auto ws = CaseWorkspace::create(dir.path(), info, &error);
    QVERIFY2(ws != nullptr, qPrintable(error));
    QVERIFY(QFile::exists(QDir(ws->rootPath()).filePath("case.json")));
    QVERIFY(QDir(ws->evidenceDir()).exists());
    QVERIFY(QDir(ws->jobsDir()).exists());
    QVERIFY(QDir(ws->logsDir()).exists());
    QVERIFY(!ws->info().id.isEmpty());
}

void TestCaseWorkspace::addEvidenceCapturesMetadataAndType()
{
    QTemporaryDir dir, src;
    CaseInfo info; info.name = "C";
    auto ws = CaseWorkspace::create(dir.path(), info);
    QVERIFY(ws);
    const QString pdf = makePdf(src);
    auto result = ws->addEvidence(pdf);
    QVERIFY2(result.ok, qPrintable(result.error));
    QCOMPARE(ws->evidence().size(), 1);
    const auto &e = ws->evidence().first();
    QCOMPARE(e.filename, QStringLiteral("evidence.pdf"));
    QCOMPARE(e.type.id, QStringLiteral("pdf"));
    QCOMPARE(e.sha256.size(), 64);
    QVERIFY(e.size > 0);
    QVERIFY(e.importedUtc.isValid());
    QVERIFY(ws->extractors().hasExtractorFor(e.type));
}

void TestCaseWorkspace::addEvidenceDoesNotModifySource()
{
    QTemporaryDir dir, src;
    auto ws = CaseWorkspace::create(dir.path(), CaseInfo{});
    QVERIFY(ws);
    const QString pdf = makePdf(src);
    const QByteArray before = [&] { QFile r(pdf); r.open(QIODevice::ReadOnly); return r.readAll(); }();
    ws->addEvidence(pdf);
    const QByteArray after = [&] { QFile r(pdf); r.open(QIODevice::ReadOnly); return r.readAll(); }();
    QCOMPARE(after, before);
}

void TestCaseWorkspace::reopenPersistsEvidenceAndAudit()
{
    QTemporaryDir dir, src;
    QString root;
    QString sha;
    {
        auto ws = CaseWorkspace::create(dir.path(), CaseInfo{});
        QVERIFY(ws);
        root = ws->rootPath();
        auto r = ws->addEvidence(makePdf(src));
        QVERIFY(r.ok);
        sha = r.item.sha256;
    }
    QString error;
    auto reopened = CaseWorkspace::open(root, &error);
    QVERIFY2(reopened != nullptr, qPrintable(error));
    QCOMPARE(reopened->evidence().size(), 1);
    QCOMPARE(reopened->evidence().first().sha256, sha);
    QVERIFY(reopened->audit().verify());
}

void TestCaseWorkspace::auditChainRecordsActions()
{
    QTemporaryDir dir, src;
    auto ws = CaseWorkspace::create(dir.path(), CaseInfo{});
    QVERIFY(ws);
    ws->addEvidence(makePdf(src));
    const auto events = ws->audit().events();
    QCOMPARE(events.size(), 2);
    QCOMPARE(events.at(0).action, QStringLiteral("case_created"));
    QCOMPARE(events.at(1).action, QStringLiteral("evidence_added"));
    QVERIFY(ws->audit().verify());
}

void TestCaseWorkspace::probeEncryptionUsesWorkingCopyWhenOriginalGone()
{
    // With a working-copy import the case must analyze its own immutable copy,
    // not the original path. Deleting the source proves the probe reads the
    // working copy rather than depending on originalPath.
    QTemporaryDir dir, src;
    auto ws = CaseWorkspace::create(dir.path(), CaseInfo{});
    QVERIFY(ws);

    const QString pdf = src.filePath("enc.pdf");
    { QFile f(pdf); f.open(QIODevice::WriteOnly);
      f.write("%PDF-1.6\n... /Encrypt 12 0 R ... trailer"); f.close(); }

    auto r = ws->addEvidence(pdf, forensic::EvidenceStorageMode::WorkingCopy);
    QVERIFY2(r.ok, qPrintable(r.error));

    // Remove the original source; only the working copy remains.
    QVERIFY(QFile::remove(pdf));

    QCOMPARE(ws->probeEncryption(r.item.id), forensic::EncryptionState::Encrypted);
}

QTEST_GUILESS_MAIN(TestCaseWorkspace)
#include "test_caseworkspace.moc"
