/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "forensic/crackingjob.h"
#include "forensic/recoveredcredential.h"

#include <QtTest>

using forensic::ComputeDevice;
using forensic::CrackingJob;
using forensic::JobState;
using forensic::RecoveredCredential;

class TestDataModels : public QObject
{
    Q_OBJECT

private slots:
    void crackingJobRoundTrip();
    void recoveredCredentialRoundTrip();
    void runtimeComputation();
};

void TestDataModels::crackingJobRoundTrip()
{
    CrackingJob j;
    j.id = QUuid::createUuid();
    j.caseId = "case-1";
    j.evidenceId = QUuid::createUuid();
    j.hashMode = 13400;
    j.attackMode = 0;
    j.hashcatArgs = {"-m", "13400", "-a", "0", "hash.txt", "words.txt"};
    j.hashcatPath = "/usr/bin/hashcat";
    j.hashcatVersion = "v7.1.2";
    j.devices = {ComputeDevice{1, "NVIDIA RTX 4090", "CUDA"}};
    j.startedUtc = QDateTime::currentDateTimeUtc();
    j.endedUtc = j.startedUtc.addSecs(90);
    j.state = JobState::Recovered;
    j.result = "cracked";

    const CrackingJob back = CrackingJob::fromJson(j.toJson());
    QCOMPARE(back.id, j.id);
    QCOMPARE(back.evidenceId, j.evidenceId);
    QCOMPARE(back.hashMode, j.hashMode);
    QCOMPARE(back.hashcatArgs, j.hashcatArgs);
    QCOMPARE(back.hashcatVersion, j.hashcatVersion);
    QCOMPARE(back.devices.size(), 1);
    QCOMPARE(back.devices.first().name, QStringLiteral("NVIDIA RTX 4090"));
    QCOMPARE(back.state, JobState::Recovered);
}

void TestDataModels::recoveredCredentialRoundTrip()
{
    RecoveredCredential c;
    c.id = QUuid::createUuid();
    c.caseId = "case-1";
    c.jobId = QUuid::createUuid();
    c.evidenceId = QUuid::createUuid();
    c.hash = "$pdf$...";
    c.plaintext = "hunter2";
    c.recoveredUtc = QDateTime::currentDateTimeUtc();

    const RecoveredCredential back = RecoveredCredential::fromJson(c.toJson());
    QCOMPARE(back.id, c.id);
    QCOMPARE(back.jobId, c.jobId);
    QCOMPARE(back.evidenceId, c.evidenceId);
    QCOMPARE(back.hash, c.hash);
    QCOMPARE(back.plaintext, c.plaintext);
}

void TestDataModels::runtimeComputation()
{
    CrackingJob j;
    j.startedUtc = QDateTime::currentDateTimeUtc();
    j.endedUtc = j.startedUtc.addSecs(5);
    QCOMPARE(j.runtimeMs(), 5000);
}

QTEST_GUILESS_MAIN(TestDataModels)
#include "test_datamodels.moc"
