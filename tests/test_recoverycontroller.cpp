/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "forensic/recovery/recoverycontroller.h"
#include "forensic/bkcrack/bkcrackattackspec.h"
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
    void resume(const CrackingJob &job, const StartOptions &opts) override
    {
        resumed << job.id;
        resumeRestore = opts.restore;
    }
    void stop(const QUuid &) override {}
    void fireCracked(const QUuid &id, const QString &h, const QByteArray &p) { emit cracked(id, h, p); }

    QList<QUuid> started;
    QList<QUuid> resumed;
    bool resumeRestore = false;
};

// A controller whose initial job persistence always fails, to prove that a
// persistence failure prevents the engine from ever starting.
class FailingPersistController : public RecoveryController
{
public:
    using RecoveryController::RecoveryController;
protected:
    bool persistNewJob(const CrackingJob &) override { return false; }
};

class TestRecoveryController : public QObject
{
    Q_OBJECT
private slots:
    void queuesBuildsAndPersistsJob();
    void recoveredCredentialIsPersisted();
    void noWorkspaceIsANoOp();
    void restoreJobsRehydratesPersistedJobsForResume();
    void refusesUnknownEngine();
    void persistenceFailurePreventsStart();
    void queuesBkcrackJob();
    void refusesIncompleteBkcrackJob();
    void queuesJohnWordlistJob();
    void refusesJohnInexpressibleAttack();
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
    const CrackingJob j = ws->jobs().first(); // by value: jobs() returns a temporary
    QCOMPARE(j.id, jobId);
    QCOMPARE(j.evidenceId, evidenceId);
    QCOMPARE(j.enginePath, QStringLiteral("/tools/hashcat"));
    QCOMPARE(j.engineVersion, QStringLiteral("v7.1"));
    QCOMPARE(j.hashMode, 13400u);
    QCOMPARE(j.engineId, QStringLiteral("hashcat")); // default engine recorded
    QVERIFY(!j.engineArgs.isEmpty());         // built via the engine
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
    const RecoveredCredential c = ws->recoveredCredentials().first(); // by value: temporary
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

void TestRecoveryController::restoreJobsRehydratesPersistedJobsForResume()
{
    // Simulate a case with a Paused job persisted in a prior session.
    QTemporaryDir dir;
    QString root;
    QUuid jobId;
    {
        auto ws = CaseWorkspace::create(dir.path(), CaseInfo{});
        QVERIFY(ws);
        root = ws->rootPath();
        const RecoveryEngineRegistry engines = RecoveryEngineRegistry::withBuiltins();
        const RecoveryEngine *hc = engines.find("hashcat");
        QVERIFY(hc);
        CrackingJob j = RecoveryController::buildJob(*hc, straightSpec(), ws->info().id,
                                                     QUuid::createUuid(), QStringLiteral("/tools/hashcat"),
                                                     QStringLiteral("v7"));
        jobId = j.id;
        j.state = JobState::Paused;
        QVERIFY(ws->saveJob(j));
    }

    // Reopen and rehydrate the queue through a fresh controller.
    QString err;
    auto ws = CaseWorkspace::open(root, &err);
    QVERIFY2(ws != nullptr, qPrintable(err));

    FakeBackend backend;
    JobQueue queue(&backend);
    RecoveryController controller(&queue);
    controller.setWorkspace(ws.get());
    controller.restoreJobs();

    // The persisted job is known to the queue and resumable, without starting.
    QVERIFY(queue.hasJob(jobId));
    QCOMPARE(queue.jobById(jobId).state, JobState::Paused);
    QVERIFY(backend.started.isEmpty());

    // And it can actually be resumed (backend asked to resume with restore).
    queue.resume(jobId);
    QCOMPARE(backend.resumed, (QList<QUuid>{jobId}));
    QVERIFY(backend.resumeRestore);
}

void TestRecoveryController::refusesUnknownEngine()
{
    QTemporaryDir dir;
    auto ws = CaseWorkspace::create(dir.path(), CaseInfo{});
    QVERIFY(ws);

    FakeBackend backend;
    JobQueue queue(&backend);
    RecoveryController controller(&queue);
    controller.setWorkspace(ws.get());

    QSignalSpy refused(&controller, &RecoveryController::recoveryRefused);
    const QUuid jobId = controller.queueRecoveryJob(straightSpec(), QUuid::createUuid(),
                                                    QStringLiteral("/tools/x"), QString(),
                                                    QStringLiteral("nope"));
    QVERIFY(jobId.isNull());
    QCOMPARE(refused.size(), 1);
    QVERIFY(backend.started.isEmpty());
    QVERIFY(ws->jobs().isEmpty());
}

void TestRecoveryController::persistenceFailurePreventsStart()
{
    QTemporaryDir dir;
    auto ws = CaseWorkspace::create(dir.path(), CaseInfo{});
    QVERIFY(ws);

    FakeBackend backend;
    JobQueue queue(&backend);
    FailingPersistController controller(&queue); // persistNewJob() always fails
    controller.setWorkspace(ws.get());

    QSignalSpy refused(&controller, &RecoveryController::recoveryRefused);
    const QUuid jobId = controller.queueRecoveryJob(straightSpec(), QUuid::createUuid(),
                                                    QStringLiteral("/tools/hashcat"));
    // A job that could not be persisted must not start, must not linger in the
    // queue, and the examiner must be told.
    QVERIFY(jobId.isNull());
    QCOMPARE(refused.size(), 1);
    QVERIFY(backend.started.isEmpty());
    QVERIFY(queue.jobs().isEmpty());
}

void TestRecoveryController::queuesBkcrackJob()
{
    QTemporaryDir dir;
    auto ws = CaseWorkspace::create(dir.path(), CaseInfo{});
    QVERIFY(ws);

    FakeBackend backend;
    JobQueue queue(&backend);
    RecoveryController controller(&queue);
    controller.setWorkspace(ws.get());

    BkcrackAttackSpec spec;
    spec.zipPath = QStringLiteral("/case/e.zip");
    spec.targetEntry = QStringLiteral("secret.doc");
    spec.plainFile = QStringLiteral("/case/known.bin");

    const QUuid jobId = controller.queueBkcrackJob(spec, QUuid::createUuid(),
                                                   QStringLiteral("/tools/bkcrack"),
                                                   QStringLiteral("bkcrack 1.7.0"));
    QVERIFY(!jobId.isNull());
    QCOMPARE(ws->jobs().size(), 1);
    const CrackingJob j = ws->jobs().first();
    QCOMPARE(j.engineId, QStringLiteral("bkcrack"));
    QVERIFY(j.engineArgs.contains(QStringLiteral("-C")));
    QVERIFY(j.engineArgs.contains(QStringLiteral("secret.doc")));
}

void TestRecoveryController::refusesIncompleteBkcrackJob()
{
    QTemporaryDir dir;
    auto ws = CaseWorkspace::create(dir.path(), CaseInfo{});
    QVERIFY(ws);

    FakeBackend backend;
    JobQueue queue(&backend);
    RecoveryController controller(&queue);
    controller.setWorkspace(ws.get());

    BkcrackAttackSpec spec; // no archive/entry/plaintext
    QSignalSpy refused(&controller, &RecoveryController::recoveryRefused);
    const QUuid jobId = controller.queueBkcrackJob(spec, QUuid::createUuid(),
                                                   QStringLiteral("/tools/bkcrack"));
    QVERIFY(jobId.isNull());
    QCOMPARE(refused.size(), 1);
    QVERIFY(ws->jobs().isEmpty());
}

void TestRecoveryController::queuesJohnWordlistJob()
{
    QTemporaryDir dir;
    auto ws = CaseWorkspace::create(dir.path(), CaseInfo{});
    QVERIFY(ws);

    FakeBackend backend;
    JobQueue queue(&backend);
    RecoveryController controller(&queue);
    controller.setWorkspace(ws.get());

    // A clean wordlist attack is expressible by John and is queued as a "john" job.
    const QUuid jobId = controller.queueRecoveryJob(straightSpec(), QUuid::createUuid(),
                                                    QStringLiteral("/tools/john"),
                                                    QStringLiteral("1.9.0-jumbo"),
                                                    QStringLiteral("john"));
    QVERIFY(!jobId.isNull());
    QCOMPARE(ws->jobs().size(), 1);
    const CrackingJob j = ws->jobs().first(); // by value: jobs() returns a temporary
    QCOMPARE(j.engineId, QStringLiteral("john"));
    QVERIFY(j.engineArgs.contains(QStringLiteral("--wordlist=wl.txt")));
}

void TestRecoveryController::refusesJohnInexpressibleAttack()
{
    QTemporaryDir dir;
    auto ws = CaseWorkspace::create(dir.path(), CaseInfo{});
    QVERIFY(ws);

    FakeBackend backend;
    JobQueue queue(&backend);
    RecoveryController controller(&queue);
    controller.setWorkspace(ws.get());

    // A rule-file attack cannot be expressed by John: refuse, do not approximate.
    AttackJobSpec spec = straightSpec();
    spec.rules = {QStringLiteral("best64.rule")};

    QSignalSpy refused(&controller, &RecoveryController::recoveryRefused);
    const QUuid jobId = controller.queueRecoveryJob(spec, QUuid::createUuid(),
                                                    QStringLiteral("/tools/john"), QString(),
                                                    QStringLiteral("john"));
    QVERIFY(jobId.isNull());
    QCOMPARE(refused.size(), 1);
    QVERIFY(backend.started.isEmpty());
    QVERIFY(ws->jobs().isEmpty());
    // The same attack IS accepted by hashcat (the default engine).
    const QUuid hc = controller.queueRecoveryJob(spec, QUuid::createUuid(),
                                                 QStringLiteral("/tools/hashcat"));
    QVERIFY(!hc.isNull());
}

QTEST_GUILESS_MAIN(TestRecoveryController)
#include "test_recoverycontroller.moc"
