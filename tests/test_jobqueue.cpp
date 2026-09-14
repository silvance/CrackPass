/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "forensic/execution/jobqueue.h"
#include "forensic/execution/jobexecutionbackend.h"

#include <QSignalSpy>
#include <QtTest>

using namespace forensic;

// Test backend: records calls and lets the test drive the lifecycle by
// re-emitting the base class signals.
class FakeBackend : public JobExecutionBackend
{
    Q_OBJECT
public:
    QList<QUuid> started, resumed, pausedCalls, stoppedCalls;
    bool resumeRestoreFlag = false;
    void start(const CrackingJob &job, const StartOptions &) override { started << job.id; }
    void pause(const QUuid &id) override { pausedCalls << id; }
    void resume(const CrackingJob &job, const StartOptions &opts) override
    {
        resumed << job.id;
        resumeRestoreFlag = opts.restore;
    }
    void stop(const QUuid &id) override { stoppedCalls << id; }

    void fireRunning(const QUuid &id) { emit running(id); }
    void fireStatus(const QUuid &id, const HashcatStatus &s) { emit statusUpdated(id, s); }
    void fireCracked(const QUuid &id, const QString &h, const QByteArray &p) { emit cracked(id, h, p); }
    void firePaused(const QUuid &id) { emit paused(id); }
    void fireStopped(const QUuid &id) { emit stopped(id); }
    void fireFinished(const QUuid &id, int ec, int sc) { emit finished(id, ec, sc); }
};

class TestJobQueue : public QObject
{
    Q_OBJECT
private:
    static CrackingJob job()
    {
        CrackingJob j;
        j.caseId = "case-1";
        j.evidenceId = QUuid::createUuid();
        j.hashMode = 13400;
        j.hashcatArgs = {"-m", "13400", "-a", "0", "hash.txt", "wl.txt"};
        return j;
    }

private slots:
    void statusMovesToRunning();
    void crackedRecordsCredentialImmediately();
    void exhaustedThenAdvances();
    void stopRunningJob();
    void pauseFreesQueueAndResumeRestores();
    void restoreRegistersJobWithoutStarting();
    void restoreNormalizesInterruptedRunningToPaused();
    void restoredPausedJobResumesWithRestoreFlag();
    void routesJobToItsEngineBackend();
    void legacyNoEngineRoutesToDefault();
    void hashcatEngineRoutesToDefault();
    void unknownEngineRefusesAndDoesNotLaunch();
};

void TestJobQueue::statusMovesToRunning()
{
    FakeBackend backend;
    JobQueue q(&backend);
    const QUuid id = q.enqueue(job(), {});
    QCOMPARE(backend.started.size(), 1);
    QCOMPARE(q.jobById(id).state, JobState::Preparing);

    HashcatStatus s;
    s.valid = true;
    s.statusCode = HashcatStatusCode::Running;
    s.progressDone = 1;
    s.progressTotal = 10;
    backend.fireStatus(id, s);
    QCOMPARE(q.jobById(id).state, JobState::Running);
    QCOMPARE(q.lastStatus(id).progressTotal, qint64(10));
}

void TestJobQueue::crackedRecordsCredentialImmediately()
{
    FakeBackend backend;
    JobQueue q(&backend);
    int credCount = 0;
    forensic::RecoveredCredential cred;
    QObject::connect(&q, &JobQueue::credentialRecovered, &q,
                     [&](const forensic::RecoveredCredential &c) { ++credCount; cred = c; });
    const QUuid id = q.enqueue(job(), {});
    backend.fireCracked(id, "$keepass$*hash", "hunter2");
    QCOMPARE(credCount, 1);
    QCOMPARE(q.jobById(id).state, JobState::Recovered);
    // The recovered credential carries the exact bytes, a display form and its
    // encoding.
    QCOMPARE(cred.rawPlaintext, QByteArray("hunter2"));
    QCOMPARE(cred.plaintext, QStringLiteral("hunter2"));
    QCOMPARE(cred.encoding, QStringLiteral("utf-8"));
}

void TestJobQueue::exhaustedThenAdvances()
{
    FakeBackend backend;
    JobQueue q(&backend);
    const QUuid a = q.enqueue(job(), {});
    const QUuid b = q.enqueue(job(), {});
    QCOMPARE(backend.started.size(), 1);              // serial: only first runs
    QCOMPARE(q.jobById(b).state, JobState::Pending);
    backend.fireFinished(a, 1, HashcatStatusCode::Exhausted);
    QCOMPARE(q.jobById(a).state, JobState::Exhausted);
    QCOMPARE(backend.started.size(), 2);              // second advanced
}

void TestJobQueue::stopRunningJob()
{
    FakeBackend backend;
    JobQueue q(&backend);
    const QUuid id = q.enqueue(job(), {});
    q.stop(id);
    QCOMPARE(backend.stoppedCalls, (QList<QUuid>{id}));
    backend.fireStopped(id);
    QCOMPARE(q.jobById(id).state, JobState::Stopped);
}

void TestJobQueue::pauseFreesQueueAndResumeRestores()
{
    FakeBackend backend;
    JobQueue q(&backend);
    const QUuid a = q.enqueue(job(), {});
    q.enqueue(job(), {}); // second job: starts once the queue frees
    q.pause(a);
    QCOMPARE(backend.pausedCalls, (QList<QUuid>{a}));
    backend.firePaused(a);
    QCOMPARE(q.jobById(a).state, JobState::Paused);
    QCOMPARE(backend.started.size(), 2);              // b starts once queue frees
}

void TestJobQueue::restoreRegistersJobWithoutStarting()
{
    FakeBackend backend;
    JobQueue q(&backend);
    CrackingJob j = job();
    j.id = QUuid::createUuid();
    j.state = JobState::Paused;
    q.restore(j, {});
    QVERIFY(q.hasJob(j.id));
    QCOMPARE(q.jobById(j.id).state, JobState::Paused);
    QVERIFY(backend.started.isEmpty()); // restore must never auto-start
}

void TestJobQueue::restoreNormalizesInterruptedRunningToPaused()
{
    FakeBackend backend;
    JobQueue q(&backend);
    CrackingJob j = job();
    j.id = QUuid::createUuid();
    j.state = JobState::Running; // was mid-run when the app closed
    q.restore(j, {});
    // No longer running: presented as resumable.
    QCOMPARE(q.jobById(j.id).state, JobState::Paused);
    QVERIFY(backend.started.isEmpty());
}

void TestJobQueue::restoredPausedJobResumesWithRestoreFlag()
{
    FakeBackend backend;
    JobQueue q(&backend);
    CrackingJob j = job();
    j.id = QUuid::createUuid();
    j.state = JobState::Paused;
    JobQueue::JobPaths paths;
    paths.sessionName = QStringLiteral("cp-restore");
    q.restore(j, paths);

    q.resume(j.id);
    // The backend is asked to resume this job with the restore flag set, even
    // though it never started it in this session.
    QCOMPARE(backend.resumed, (QList<QUuid>{j.id}));
    QVERIFY(backend.resumeRestoreFlag);
    QCOMPARE(q.jobById(j.id).state, JobState::Preparing);
}

void TestJobQueue::routesJobToItsEngineBackend()
{
    FakeBackend hashcat; // default
    FakeBackend john;
    JobQueue q(&hashcat);
    q.registerBackend(QStringLiteral("john"), &john);

    CrackingJob j = job();
    j.engineId = QStringLiteral("john");
    const QUuid id = q.enqueue(j, {});

    // The job was dispatched to the engine's backend, not the default.
    QCOMPARE(john.started, (QList<QUuid>{id}));
    QVERIFY(hashcat.started.isEmpty());

    // Control/lifecycle also routes to the same backend.
    q.stop(id);
    QCOMPARE(john.stoppedCalls, (QList<QUuid>{id}));
    QVERIFY(hashcat.stoppedCalls.isEmpty());
}

void TestJobQueue::legacyNoEngineRoutesToDefault()
{
    // A legacy job carries no engineId; it must run on the default backend.
    FakeBackend hashcat;
    FakeBackend john;
    JobQueue q(&hashcat);
    q.registerBackend(QStringLiteral("john"), &john);

    CrackingJob j = job(); // engineId left empty
    const QUuid id = q.enqueue(j, {});
    QCOMPARE(hashcat.started, (QList<QUuid>{id}));
    QVERIFY(john.started.isEmpty());
}

void TestJobQueue::hashcatEngineRoutesToDefault()
{
    // "hashcat" is served by the default backend (it is never registered).
    FakeBackend hashcat;
    JobQueue q(&hashcat);
    CrackingJob j = job();
    j.engineId = QStringLiteral("hashcat");
    const QUuid id = q.enqueue(j, {});
    QCOMPARE(hashcat.started, (QList<QUuid>{id}));
}

void TestJobQueue::unknownEngineRefusesAndDoesNotLaunch()
{
    // An unknown engineId must NOT fall back to hashcat: the job fails and no
    // backend is launched.
    FakeBackend hashcat;
    FakeBackend john;
    JobQueue q(&hashcat);
    q.registerBackend(QStringLiteral("john"), &john);

    CrackingJob j = job();
    j.engineId = QStringLiteral("nonsense");
    const QUuid id = q.enqueue(j, {});

    QCOMPARE(q.jobById(id).state, JobState::Failed);
    QVERIFY(hashcat.started.isEmpty());
    QVERIFY(john.started.isEmpty());
    QVERIFY(q.jobById(id).result.contains(QStringLiteral("Unknown recovery engine")));
}

QTEST_GUILESS_MAIN(TestJobQueue)
#include "test_jobqueue.moc"
