/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 *
 * Release-level acceptance test for the PRIMARY use case:
 *
 *   encrypted MS Office document -> Recover Password -> Dictionary
 *   -> CaseKey Common -> Start -> recovered password.
 *
 * It runs HEADLESSLY and always in CI: extraction is driven with a
 * FakeProcessRunner standing in for office2john, and the recovery engine is a
 * fake backend that emits the known password (the LIVE crack with real hashcat
 * + office2john is the optional real-tool integration test, which QSKIPs when
 * those tools are absent). The point here is to prove the model/persistence
 * chain end to end: every artifact the examiner relies on is actually recorded,
 * survives a reopen, and the report points at the exact extraction/engine/
 * dictionary -- with the evidence left byte-for-byte unchanged.
 */
#include "forensic/caseworkspace.h"
#include "forensic/dictionary/dictionarylibrary.h"
#include "forensic/execution/jobexecutionbackend.h"
#include "forensic/execution/jobqueue.h"
#include "forensic/extraction/toolresolver.h"
#include "forensic/planner/attackplanner.h"
#include "forensic/recovery/recoverycontroller.h"
#include "forensic/report/reportbuilder.h"
#include "fakeprocessrunner.h"

#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <QtTest>

using namespace forensic;

// A recovery backend that immediately "recovers" the configured password: on
// start it reports Running, emits the credential, then finishes cracked. It runs
// no process, so the model/persistence path is exercised deterministically.
class InstantRecoverBackend : public JobExecutionBackend
{
    Q_OBJECT
public:
    QString hash, password;
    void start(const CrackingJob &job, const StartOptions &) override
    {
        emit running(job.id);
        emit cracked(job.id, hash, password.toUtf8());
        emit finished(job.id, 0, HashcatStatusCode::Cracked);
    }
    void pause(const QUuid &) override {}
    void resume(const CrackingJob &job, const StartOptions &) override { emit running(job.id); }
    void stop(const QUuid &id) override { emit stopped(id); }
};

class TestAcceptanceOffice : public QObject
{
    Q_OBJECT
private slots:
    void officeDictionaryWorkflowEndToEnd();
};

void TestAcceptanceOffice::officeDictionaryWorkflowEndToEnd()
{
    const QString password = QStringLiteral("Sunshine2020");
    const QString officeHash = QStringLiteral("$office$*2013*100000*256*16*abcdef*0011*deadbeef");

    QTemporaryDir caseParent, res, src;
    QString root;
    QUuid jobId, evId, extractionId;
    QString dictSha;
    qint64 dictCount = -1;

    {
        // (1) Open/create a case.
        QString err;
        auto ws = CaseWorkspace::create(caseParent.path(), CaseInfo{}, &err);
        QVERIFY2(ws != nullptr, qPrintable(err));
        root = ws->rootPath();

        // (2) Add the DOCX. Encrypted OOXML is an OLE2 compound file, so the
        //     content detector classifies it as ms-office from its magic bytes.
        const QString docx = src.filePath("secret.docx");
        {
            QFile f(docx);
            QVERIFY(f.open(QIODevice::WriteOnly));
            f.write(QByteArray("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 8)); // OLE2 magic
            f.write(QByteArray(512, '\0'));                            // plausible body
        }
        auto intake = ws->addEvidence(docx);
        QVERIFY2(intake.ok, qPrintable(intake.error));
        evId = intake.item.id;
        // (3) Evidence integrity is recorded at intake.
        QCOMPARE(intake.item.sha256.size(), 64);
        QCOMPARE(intake.item.type.id, QStringLiteral("ms-office"));
        const QString shaAtIntake = intake.item.sha256;

        // (4) Recover Password auto-extracts the Office hash (fake office2john).
        FakeProcessRunner runner;
        runner.nextResult = FakeProcessRunner::ok("secret.docx:" + officeHash.toUtf8() + "\n");
        ToolResolver tools;
        tools.setTool("office2john", ResolvedTool{true, "office2john", {}, "jumbo-1.9"});
        ExtractionContext ctx; ctx.runner = &runner; ctx.tools = &tools;
        auto outcome = ws->extractHash(evId, ctx);
        QVERIFY2(outcome.ok, qPrintable(outcome.error));
        QCOMPARE(outcome.result.status, ExtractionStatus::Success);
        extractionId = outcome.record.id;
        // A single candidate mode (Office 2013 -> 9600) resolves without prompting.
        quint32 mode = outcome.result.candidateModes.value(0).mode;
        QCOMPARE(mode, 9600u);
        QString mErr;
        QVERIFY2(ws->selectExtractionMode(extractionId, mode, &mErr), qPrintable(mErr));
        const QString hashFile = QDir(ws->extractionsDir())
            .filePath(extractionId.toString(QUuid::WithoutBraces) + "/hash.txt");

        // (5)+(6) The managed dictionary (CaseKey Common) provides the default,
        //         requires no case knowledge, and is recorded by id/sha/count.
        {
            QFile mf(QDir(res.path()).filePath("manifest.json"));
            QVERIFY(mf.open(QIODevice::WriteOnly));
            mf.write(R"({"version":1,"dictionaries":[
              {"id":"casekey-common","displayName":"CaseKey Common","description":"d",
               "path":"casekey-common.txt","source":"test","license":"GPL-3.0-or-later"}]})");
        }
        {
            QFile wl(QDir(res.path()).filePath("casekey-common.txt"));
            QVERIFY(wl.open(QIODevice::WriteOnly));
            wl.write(("decoy1\n" + password + "\ndecoy2\n").toUtf8());
        }
        DictionaryLibrary lib;
        lib.setBuiltinManifest(QDir(res.path()).filePath("manifest.json"));
        lib.setLibraryDir(res.filePath("library"));
        QVERIFY(lib.reload());
        QCOMPARE(lib.defaultEntryId(), QStringLiteral("casekey-common"));
        bool found = false;
        const DictionaryEntry dict = lib.entry(lib.defaultEntryId(), &found);
        QVERIFY(found);
        QVERIFY(dict.fileExists());
        QString rErr;
        QVERIFY2(lib.revalidate(dict.id, &dictCount, &dictSha, &rErr), qPrintable(rErr));
        QCOMPARE(dictCount, qint64(3));
        QCOMPARE(dictSha.size(), 64);

        DictionaryProvenance prov;
        prov.id = dict.id;
        prov.displayName = dict.displayName;
        prov.path = dict.absolutePath;
        prov.sha256 = dictSha;
        prov.candidateCount = dictCount;

        // Plan a plain Dictionary attack with EMPTY case knowledge.
        PlannerContext pctx;
        pctx.hashMode = mode;
        pctx.hashTypeName = QStringLiteral("MS Office 2013+");
        pctx.hashFile = hashFile;
        pctx.planDir = res.filePath("plan");
        pctx.commonWordlist = dict.absolutePath;
        const PlanResult plan = AttackPlanner().plan(AttackTemplate::CommonPasswords,
                                                     CaseKnowledge{}, pctx);
        QVERIFY2(plan.ok, qPrintable(plan.error));

        // (7) hashcat expresses the attack and is the selected engine. Keep the
        //     registry in a named local: selectForSpec returns a pointer into it.
        const RecoveryEngineRegistry engines = RecoveryEngineRegistry::withBuiltins();
        const RecoveryEngine *engine = engines.selectForSpec(plan.spec);
        QVERIFY(engine);
        QCOMPARE(engine->id(), QStringLiteral("hashcat"));

        // Drive the real controller + queue with the instant-recover backend.
        InstantRecoverBackend backend;
        backend.hash = officeHash;
        backend.password = password;
        JobQueue queue(&backend);
        RecoveryController controller(&queue);
        controller.setWorkspace(ws.get());

        // (8)+(9) Persist-before-launch is the controller's invariant; the job
        //         records the EXACT extraction it attacks.
        jobId = controller.queueRecoveryJob(plan.spec, evId,
                                            QStringLiteral("/tools/hashcat/hashcat"),
                                            QStringLiteral("v7.1.2"),
                                            QStringLiteral("hashcat"), prov, extractionId);
        QVERIFY(!jobId.isNull());
        // Evidence is never modified by the run.
        QCOMPARE(ws->verifyEvidenceIntegrity(evId).currentSha256, shaAtIntake);
    }

    // Reopen the case from disk: everything the examiner relies on persisted.
    QString err;
    auto ws = CaseWorkspace::open(root, &err);
    QVERIFY2(ws != nullptr, qPrintable(err));

    CrackingJob job;
    for (const CrackingJob &j : ws->jobs())
        if (j.id == jobId) job = j;
    QCOMPARE(job.id, jobId);
    // (12) Final state + endedUtc persisted.
    QCOMPARE(job.state, JobState::Recovered);
    QVERIFY(job.startedUtc.isValid());
    QVERIFY2(job.endedUtc.isValid(), "final endedUtc must be persisted");
    // (9) Exact extraction recorded. (7) engine + tool recorded. (6) dictionary.
    QCOMPARE(job.extractionId, extractionId);
    QCOMPARE(job.engineId, QStringLiteral("hashcat"));
    QCOMPARE(job.enginePath, QStringLiteral("/tools/hashcat/hashcat"));
    QCOMPARE(job.dictionary.id, QStringLiteral("casekey-common"));
    QCOMPARE(job.dictionary.sha256, dictSha);
    QCOMPARE(job.dictionary.candidateCount, dictCount);

    // (11) The recovered result persisted and is associated to the evidence.
    QCOMPARE(ws->recoveredCredentials().size(), 1);
    const RecoveredCredential cred = ws->recoveredCredentials().first();
    QCOMPARE(cred.evidenceId, evId);
    QCOMPARE(cred.jobId, jobId);
    QCOMPARE(cred.plaintext, password);

    // (13) The report points to the exact extraction, engine and dictionary.
    const RecoveryReport rep = ReportBuilder::build(*ws, job, "acceptance");
    QCOMPARE(rep.extractionId, extractionId.toString(QUuid::WithoutBraces));
    QCOMPARE(rep.extractorId, QStringLiteral("office2john"));
    QCOMPARE(rep.engineId, QStringLiteral("hashcat"));
    QCOMPARE(rep.dictionaryId, QStringLiteral("casekey-common"));
    QVERIFY(rep.recovered);
    QCOMPARE(rep.recoveredPlaintext, password);

    // (14) Evidence SHA-256 unchanged across the whole workflow + reopen.
    const auto integ = ws->verifyEvidenceIntegrity(evId);
    QVERIFY(integ.ok);
}

QTEST_GUILESS_MAIN(TestAcceptanceOffice)
#include "test_acceptance_office.moc"
