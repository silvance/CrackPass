/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "forensic/execution/hashcatexecutionbackend.h"

#include <QtTest>

using namespace forensic;

class TestBackendCompose : public QObject
{
    Q_OBJECT
private slots:
    void freshRunInjectsStatusAndSession();
    void resumeUsesRestore();
    void executesRecordedBinaryNotConstructionTimePath();
};

void TestBackendCompose::freshRunInjectsStatusAndSession()
{
    CrackingJob job;
    job.engineArgs = {"-m", "13400", "-a", "0", "hash.txt", "wl.txt"};
    JobExecutionBackend::StartOptions opts;
    opts.sessionName = "cp-1";
    opts.potfilePath = "/case/job.pot";
    opts.outfilePath = "/case/cracked.out";
    opts.restorePath = "/case/session.restore";
    opts.restore = false;

    const QStringList args = HashcatExecutionBackend::composeArgs(job, opts);
    // Original attack args preserved.
    QVERIFY(args.mid(0, 6) == (QStringList{"-m", "13400", "-a", "0", "hash.txt", "wl.txt"}));
    // Machine-readable status injected (not terminal scraping).
    QVERIFY(args.contains("--status-json"));
    QVERIFY(args.contains("--status"));
    QVERIFY(args.contains("--session") && args.contains("cp-1"));
    QVERIFY(args.contains("--potfile-path") && args.contains("/case/job.pot"));
    QVERIFY(args.contains("--outfile") && args.contains("/case/cracked.out"));
}

void TestBackendCompose::resumeUsesRestore()
{
    CrackingJob job;
    job.engineArgs = {"-m", "13400", "-a", "0", "hash.txt", "wl.txt"};
    JobExecutionBackend::StartOptions opts;
    opts.sessionName = "cp-1";
    opts.restorePath = "/case/session.restore";
    opts.restore = true;

    const QStringList args = HashcatExecutionBackend::composeArgs(job, opts);
    QVERIFY(args.contains("--restore"));
    QVERIFY(args.contains("--session") && args.contains("cp-1"));
    // A resume must not re-supply the original attack positionals.
    QVERIFY(!args.contains("wl.txt"));
    QVERIFY(args.contains("--status-json"));
}

void TestBackendCompose::executesRecordedBinaryNotConstructionTimePath()
{
    // Provenance: the executed binary must match the one recorded on the job, so
    // that if the configured hashcat path changes between job creation and
    // execution, the process actually run is still the one the record names.
    CrackingJob job;
    job.enginePath = "/tools/B/hashcat.exe"; // recorded at job creation
    QCOMPARE(HashcatExecutionBackend::programFor(job, "/tools/A/hashcat.exe"),
             QStringLiteral("/tools/B/hashcat.exe"));

    // Fallback only when the job records no path (legacy/hand-built jobs).
    CrackingJob legacy;
    QCOMPARE(HashcatExecutionBackend::programFor(legacy, "/tools/A/hashcat.exe"),
             QStringLiteral("/tools/A/hashcat.exe"));
}

QTEST_GUILESS_MAIN(TestBackendCompose)
#include "test_backendcompose.moc"
