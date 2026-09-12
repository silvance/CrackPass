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
};

void TestBackendCompose::freshRunInjectsStatusAndSession()
{
    CrackingJob job;
    job.hashcatArgs = {"-m", "13400", "-a", "0", "hash.txt", "wl.txt"};
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
    job.hashcatArgs = {"-m", "13400", "-a", "0", "hash.txt", "wl.txt"};
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

QTEST_GUILESS_MAIN(TestBackendCompose)
#include "test_backendcompose.moc"
