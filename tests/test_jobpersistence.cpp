/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "forensic/caseworkspace.h"

#include <QTemporaryDir>
#include <QtTest>

using namespace forensic;

class TestJobPersistence : public QObject
{
    Q_OBJECT
private slots:
    void saveJobAndReopen();
    void recoveredCredentialAssociationAndAudit();
};

void TestJobPersistence::saveJobAndReopen()
{
    QTemporaryDir dir;
    QString root;
    QUuid jobId = QUuid::createUuid();
    {
        auto ws = CaseWorkspace::create(dir.path(), CaseInfo{});
        QVERIFY(ws);
        root = ws->rootPath();
        CrackingJob j;
        j.id = jobId;
        j.caseId = ws->info().id;
        j.hashMode = 13400;
        j.engineArgs = {"-m", "13400", "-a", "0", "hash.txt", "wl.txt"};
        j.state = JobState::Exhausted;
        QString err;
        QVERIFY2(ws->saveJob(j, &err), qPrintable(err));
        QCOMPARE(ws->jobs().size(), 1);
    }
    auto reopened = CaseWorkspace::open(root);
    QVERIFY(reopened);
    QCOMPARE(reopened->jobs().size(), 1);
    QCOMPARE(reopened->jobs().first().id, jobId);
    QCOMPARE(reopened->jobs().first().state, JobState::Exhausted);
}

void TestJobPersistence::recoveredCredentialAssociationAndAudit()
{
    QTemporaryDir dir;
    QString root;
    QUuid evId = QUuid::createUuid();
    QUuid jobId = QUuid::createUuid();
    {
        auto ws = CaseWorkspace::create(dir.path(), CaseInfo{});
        root = ws->rootPath();
        RecoveredCredential c;
        c.jobId = jobId;
        c.evidenceId = evId;
        c.hash = "$keepass$*x";
        c.plaintext = "s3cret";
        c.recoveredUtc = QDateTime::currentDateTimeUtc();
        QVERIFY(ws->addRecoveredCredential(c));
        QCOMPARE(ws->recoveredCredentials().size(), 1);
        // caseId is filled in from the workspace.
        QCOMPARE(ws->recoveredCredentials().first().caseId, ws->info().id);
        bool audited = false;
        for (const auto &e : ws->audit().events())
            if (e.action == QStringLiteral("credential_recovered")) audited = true;
        QVERIFY(audited);
        QVERIFY(ws->audit().verify());
    }
    auto reopened = CaseWorkspace::open(root);
    QVERIFY(reopened);
    QCOMPARE(reopened->recoveredCredentials().size(), 1);
    const auto &c = reopened->recoveredCredentials().first();
    QCOMPARE(c.evidenceId, evId);
    QCOMPARE(c.jobId, jobId);
    QCOMPARE(c.plaintext, QStringLiteral("s3cret")); // readable, no gating
}

QTEST_GUILESS_MAIN(TestJobPersistence)
#include "test_jobpersistence.moc"
