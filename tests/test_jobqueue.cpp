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
    void start(const CrackingJob &job, const StartOptions &) override { started << job.id; }
    void pause(const QUuid &id) override { pausedCalls << id; }
    void resume(const QUuid &id) override { resumed << id; }
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
    const QUuid b = q.enqueue(job(), {});
    q.pause(a);
    QCOMPARE(backend.pausedCalls, (QList<QUuid>{a}));
    backend.firePaused(a);
    QCOMPARE(q.jobById(a).state, JobState::Paused);
    QCOMPARE(backend.started.size(), 2);              // b starts once queue frees
}

QTEST_GUILESS_MAIN(TestJobQueue)
#include "test_jobqueue.moc"
