/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "forensic/recovery/recoverycontroller.h"
#include "forensic/caseworkspace.h"
#include "forensic/execution/jobexecutionbackend.h"
#include "forensic/execution/jobqueue.h"
#include "forensic/planner/attackjobspec.h"

#include <QTemporaryDir>
#include <QtTest>

using namespace forensic;

// Minimal backend: records what it was asked to start and lets the test emit a
// recovered credential, without running any process.
class FakeBackend : public JobExecutionBackend
{
    Q_OBJECT
public:
    void start(const CrackingJob &job, const StartOptions &) override
    {
        started << job.id;
        emit running(job.id); // drive the queue into Running so state persists
    }
    void pause(const QUuid &) override {}
    void resume(const QUuid &) override {}
    void stop(const QUuid &) override {}
    void fireCracked(const QUuid &id, const QString &h, const QByteArray &p) { emit cracked(id, h, p); }

    QList<QUuid> started;
};

class TestRecoveryController : public QObject
{
    Q_OBJECT
private slots:
    void queuesBuildsAndPersistsJob();
    void recoveredCredentialIsPersisted();
    void noWorkspaceIsANoOp();
};

static AttackJobSpec straightSpec()
{
    AttackJobSpec spec;
    spec.hashMode = 13400;
    spec.attackMode = AttackModeNum::Straight;
    spec.hashFile = QStringLiteral("hash.txt");
    spec.wordlists = {QStringLiteral("wl.txt")};
    return spec;
}

void TestRecoveryController::queuesBuildsAndPersistsJob()
{
    QTemporaryDir dir;
    auto ws = CaseWorkspace::create(dir.path(), CaseInfo{});
    QVERIFY(ws);

    FakeBackend backend;
    JobQueue queue(&backend);
    RecoveryController controller(&queue);
    controller.setWorkspace(ws.get());

    const QUuid evidenceId = QUuid::createUuid();
    const QUuid jobId = controller.queueRecoveryJob(straightSpec(), evidenceId,
                                                    QStringLiteral("/tools/hashcat"), QStringLiteral("v7.1"));
    QVERIFY(!jobId.isNull());
    QCOMPARE(backend.started.size(), 1);       // the queue started it

    // The reproducible record is persisted with the fields the controller built.
    QCOMPARE(ws->jobs().size(), 1);
    const CrackingJob &j = ws->jobs().first();
    QCOMPARE(j.id, jobId);
    QCOMPARE(j.evidenceId, evidenceId);
    QCOMPARE(j.hashcatPath, QStringLiteral("/tools/hashcat"));
    QCOMPARE(j.hashcatVersion, QStringLiteral("v7.1"));
    QCOMPARE(j.hashMode, 13400u);
    QVERIFY(!j.hashcatArgs.isEmpty());         // built via AttackCommandBuilder
}

void TestRecoveryController::recoveredCredentialIsPersisted()
{
    QTemporaryDir dir;
    auto ws = CaseWorkspace::create(dir.path(), CaseInfo{});
    QVERIFY(ws);

    FakeBackend backend;
    JobQueue queue(&backend);
    RecoveryController controller(&queue);
    controller.setWorkspace(ws.get());

    const QUuid evidenceId = QUuid::createUuid();
    const QUuid jobId = controller.queueRecoveryJob(straightSpec(), evidenceId,
                                                    QStringLiteral("/tools/hashcat"));
    backend.fireCracked(jobId, QStringLiteral("$keepass$*hash"), QByteArray("hunter2"));

    QCOMPARE(ws->recoveredCredentials().size(), 1);
    const RecoveredCredential &c = ws->recoveredCredentials().first();
    QCOMPARE(c.jobId, jobId);
    QCOMPARE(c.evidenceId, evidenceId);
    QCOMPARE(c.plaintext, QStringLiteral("hunter2"));
    QCOMPARE(c.rawPlaintext, QByteArray("hunter2"));
}

void TestRecoveryController::noWorkspaceIsANoOp()
{
    FakeBackend backend;
    JobQueue queue(&backend);
    RecoveryController controller(&queue); // no workspace set
    const QUuid jobId = controller.queueRecoveryJob(straightSpec(), QUuid::createUuid(),
                                                    QStringLiteral("/tools/hashcat"));
    QVERIFY(jobId.isNull());
    QVERIFY(backend.started.isEmpty());
}

QTEST_GUILESS_MAIN(TestRecoveryController)
#include "test_recoverycontroller.moc"
