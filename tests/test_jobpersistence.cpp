/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "forensic/caseworkspace.h"
#include "forensic/execution/jobqueue.h"
#include "forensic/execution/jobexecutionbackend.h"

#include <functional>

#include <QTemporaryDir>
#include <QtTest>

using namespace forensic;

// Minimal backend that lets the test drive the job lifecycle by re-emitting the
// base-class signals (the same technique test_jobqueue.cpp uses).
class FakeBackend : public JobExecutionBackend
{
    Q_OBJECT
public:
    void start(const CrackingJob &, const StartOptions &) override {}
    void pause(const QUuid &id) override { emit paused(id); }
    void resume(const CrackingJob &, const StartOptions &) override {}
    void stop(const QUuid &id) override { emit stopped(id); }

    void fireRunning(const QUuid &id) { emit running(id); }
    void fireCracked(const QUuid &id, const QString &h, const QByteArray &p) { emit cracked(id, h, p); }
    void firePaused(const QUuid &id) { emit paused(id); }
    void fireStopped(const QUuid &id) { emit stopped(id); }
    void fireFinished(const QUuid &id, int ec, int sc) { emit finished(id, ec, sc); }
    void fireFailed(const QUuid &id, const QString &e) { emit failed(id, e); }
};

class TestJobPersistence : public QObject
{
    Q_OBJECT
private:
    // Create a case, wire the queue's jobChanged to saveJob exactly as
    // RecoveryController does, enqueue one job, let `drive` push it through the
    // lifecycle, then REOPEN the case from disk and return the persisted job.
    static CrackingJob persistThenReopen(
        const std::function<void(FakeBackend &, JobQueue &, const QUuid &)> &drive)
    {
        QTemporaryDir dir;
        QString root;
        QUuid id;
        {
            auto ws = CaseWorkspace::create(dir.path(), CaseInfo{});
            root = ws->rootPath();
            FakeBackend backend;
            JobQueue q(&backend);
            QObject::connect(&q, &JobQueue::jobChanged, &q,
                             [wsp = ws.get()](const CrackingJob &j) { wsp->saveJob(j); });
            CrackingJob j;
            j.caseId = ws->info().id;
            j.hashMode = 13400;
            j.engineArgs = {"-m", "13400", "-a", "0", "hash.txt", "wl.txt"};
            id = q.enqueue(j, {});
            backend.fireRunning(id);
            drive(backend, q, id);
        }
        auto reopened = CaseWorkspace::open(root);
        for (const CrackingJob &j : reopened->jobs())
            if (j.id == id)
                return j;
        return CrackingJob{};
    }

private slots:
    void saveJobAndReopen();
    void recoveredCredentialAssociationAndAudit();
    void completionPersistsEndedUtc();
    void recoveryPersistsEndedUtc();
    void failurePersistsEndedUtc();
    void stopPersistsEndedUtc();
    void pauseDoesNotPersistEndedUtc();
    void pauseResumeCompletionPersistsFinalEndedUtc();
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

// Terminal transitions must persist a valid endedUtc and a sane runtime.
void TestJobPersistence::completionPersistsEndedUtc()
{
    const CrackingJob j = persistThenReopen([](FakeBackend &b, JobQueue &, const QUuid &id) {
        b.fireFinished(id, 1, HashcatStatusCode::Exhausted);
    });
    QCOMPARE(j.state, JobState::Exhausted);
    QVERIFY(j.startedUtc.isValid());
    QVERIFY2(j.endedUtc.isValid(), "endedUtc must be persisted on completion");
    QVERIFY(j.endedUtc >= j.startedUtc);
    QVERIFY(j.runtimeMs() >= 0);
}

void TestJobPersistence::recoveryPersistsEndedUtc()
{
    const CrackingJob j = persistThenReopen([](FakeBackend &b, JobQueue &, const QUuid &id) {
        b.fireCracked(id, "$office$*hash", "Password1"); // immediate Recovered
        b.fireFinished(id, 0, HashcatStatusCode::Cracked); // process exits -> final endedUtc
    });
    QCOMPARE(j.state, JobState::Recovered);
    QVERIFY2(j.endedUtc.isValid(), "endedUtc must be persisted on recovery completion");
    QVERIFY(j.endedUtc >= j.startedUtc);
}

void TestJobPersistence::failurePersistsEndedUtc()
{
    const CrackingJob j = persistThenReopen([](FakeBackend &b, JobQueue &, const QUuid &id) {
        b.fireFailed(id, QStringLiteral("tool crashed"));
    });
    QCOMPARE(j.state, JobState::Failed);
    QVERIFY2(j.endedUtc.isValid(), "endedUtc must be persisted on failure");
    QCOMPARE(j.result, QStringLiteral("tool crashed"));
}

void TestJobPersistence::stopPersistsEndedUtc()
{
    const CrackingJob j = persistThenReopen([](FakeBackend &b, JobQueue &, const QUuid &id) {
        b.fireStopped(id);
    });
    QCOMPARE(j.state, JobState::Stopped);
    QVERIFY2(j.endedUtc.isValid(), "endedUtc must be persisted on stop");
}

// Pause is NOT terminal: the persisted paused record must have a start time but
// NO endedUtc, so a resumed job's runtime is not poisoned by a bogus end time.
void TestJobPersistence::pauseDoesNotPersistEndedUtc()
{
    const CrackingJob j = persistThenReopen([](FakeBackend &b, JobQueue &, const QUuid &id) {
        b.firePaused(id);
    });
    QCOMPARE(j.state, JobState::Paused);
    QVERIFY(j.startedUtc.isValid());
    QVERIFY2(!j.endedUtc.isValid(), "a paused job must not carry a completion time");
}

// Pause -> resume -> completion: the persisted final record reflects actual
// final completion (a valid endedUtc at/after start), not the pause instant.
void TestJobPersistence::pauseResumeCompletionPersistsFinalEndedUtc()
{
    const CrackingJob j = persistThenReopen([](FakeBackend &b, JobQueue &q, const QUuid &id) {
        b.firePaused(id);          // Paused (no endedUtc)
        q.resume(id);              // Preparing; endedUtc cleared, startedUtc kept
        b.fireRunning(id);         // Running again
        b.fireFinished(id, 1, HashcatStatusCode::Exhausted); // final terminal
    });
    QCOMPARE(j.state, JobState::Exhausted);
    QVERIFY(j.startedUtc.isValid());
    QVERIFY2(j.endedUtc.isValid(), "final completion after resume must persist endedUtc");
    QVERIFY2(j.endedUtc >= j.startedUtc, "final endedUtc must be at/after the original start");
    QVERIFY(j.runtimeMs() >= 0);
}

QTEST_GUILESS_MAIN(TestJobPersistence)
#include "test_jobpersistence.moc"
