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
    void nonUtf8CredentialRoundTrip();
    void legacyCredentialWithoutRawBytes();
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
    c.rawPlaintext = QByteArray("hunter2");
    c.encoding = "utf-8";
    c.recoveredUtc = QDateTime::currentDateTimeUtc();

    const RecoveredCredential back = RecoveredCredential::fromJson(c.toJson());
    QCOMPARE(back.id, c.id);
    QCOMPARE(back.jobId, c.jobId);
    QCOMPARE(back.evidenceId, c.evidenceId);
    QCOMPARE(back.hash, c.hash);
    QCOMPARE(back.plaintext, c.plaintext);
    QCOMPARE(back.rawPlaintext, c.rawPlaintext);
    QCOMPARE(back.encoding, c.encoding);
}

void TestDataModels::nonUtf8CredentialRoundTrip()
{
    // A password whose bytes are not valid UTF-8 must survive persistence
    // exactly, via the rawHex field.
    RecoveredCredential c;
    c.id = QUuid::createUuid();
    c.hash = "$pdf$...";
    c.rawPlaintext = QByteArray::fromHex("70e4ff"); // not valid UTF-8
    c.plaintext = QStringLiteral("$HEX[70e4ff]");
    c.encoding = "raw";
    c.recoveredUtc = QDateTime::currentDateTimeUtc();

    const RecoveredCredential back = RecoveredCredential::fromJson(c.toJson());
    QCOMPARE(back.rawPlaintext, c.rawPlaintext); // exact bytes preserved
    QCOMPARE(back.plaintext, c.plaintext);
    QCOMPARE(back.encoding, QStringLiteral("raw"));
}

void TestDataModels::legacyCredentialWithoutRawBytes()
{
    // A record written before raw bytes were tracked (plaintext only) still
    // loads, with rawPlaintext reconstructed from the display text.
    QJsonObject obj;
    obj[QStringLiteral("id")] = QUuid::createUuid().toString(QUuid::WithoutBraces);
    obj[QStringLiteral("hash")] = QStringLiteral("$pdf$...");
    obj[QStringLiteral("plaintext")] = QStringLiteral("legacypw");
    const RecoveredCredential back = RecoveredCredential::fromJson(obj);
    QCOMPARE(back.plaintext, QStringLiteral("legacypw"));
    QCOMPARE(back.rawPlaintext, QByteArray("legacypw"));
    QCOMPARE(back.encoding, QStringLiteral("utf-8"));
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
