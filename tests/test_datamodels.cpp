/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "forensic/crackingjob.h"
#include "forensic/recoveredcredential.h"

#include <QJsonArray>
#include <QJsonObject>
#include <QtTest>

using forensic::ComputeDevice;
using forensic::CrackingJob;
using forensic::JobState;
using forensic::RecoveredCredential;
using forensic::ResultKind;

class TestDataModels : public QObject
{
    Q_OBJECT

private slots:
    void crackingJobRoundTrip();
    void legacyHashcatJobLoads();
    void recoveredCredentialRoundTrip();
    void legacyCredentialIsPassword();
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
    j.engineId = "hashcat";
    j.engineDisplayName = "hashcat";
    j.engineArgs = {"-m", "13400", "-a", "0", "hash.txt", "words.txt"};
    j.enginePath = "/usr/bin/hashcat";
    j.engineVersion = "v7.1.2";
    j.engineExeSha256 = "abc123";
    j.devices = {ComputeDevice{1, "NVIDIA RTX 4090", "CUDA"}};
    j.startedUtc = QDateTime::currentDateTimeUtc();
    j.endedUtc = j.startedUtc.addSecs(90);
    j.state = JobState::Recovered;
    j.result = "cracked";

    const QJsonObject obj = j.toJson();
    // New records use engine-neutral field names, not the legacy hashcat* ones.
    QVERIFY(obj.contains(QStringLiteral("engineArgs")));
    QVERIFY(obj.contains(QStringLiteral("enginePath")));
    QVERIFY(obj.contains(QStringLiteral("engineVersion")));
    QVERIFY(!obj.contains(QStringLiteral("hashcatArgs")));

    const CrackingJob back = CrackingJob::fromJson(obj);
    QCOMPARE(back.id, j.id);
    QCOMPARE(back.evidenceId, j.evidenceId);
    QCOMPARE(back.hashMode, j.hashMode);
    QCOMPARE(back.engineArgs, j.engineArgs);
    QCOMPARE(back.enginePath, j.enginePath);
    QCOMPARE(back.engineVersion, j.engineVersion);
    QCOMPARE(back.engineDisplayName, j.engineDisplayName);
    QCOMPARE(back.engineExeSha256, j.engineExeSha256);
    QCOMPARE(back.engineId, j.engineId);
    QCOMPARE(back.devices.size(), 1);
    QCOMPARE(back.devices.first().name, QStringLiteral("NVIDIA RTX 4090"));
    QCOMPARE(back.state, JobState::Recovered);
}

void TestDataModels::legacyHashcatJobLoads()
{
    // A job record written before the engine-neutral migration used hashcat*
    // field names and no engineId. It must load with full provenance and
    // migrate to engineId "hashcat".
    QJsonObject obj;
    obj[QStringLiteral("id")] = QUuid::createUuid().toString(QUuid::WithoutBraces);
    obj[QStringLiteral("caseId")] = QStringLiteral("case-legacy");
    obj[QStringLiteral("hashMode")] = 13400;
    obj[QStringLiteral("hashcatPath")] = QStringLiteral("/usr/bin/hashcat");
    obj[QStringLiteral("hashcatVersion")] = QStringLiteral("v6.2.6");
    QJsonArray args; args.append(QStringLiteral("-m")); args.append(QStringLiteral("13400"));
    obj[QStringLiteral("hashcatArgs")] = args;

    const CrackingJob j = CrackingJob::fromJson(obj);
    QCOMPARE(j.engineId, QStringLiteral("hashcat")); // migrated from absent
    QCOMPARE(j.enginePath, QStringLiteral("/usr/bin/hashcat"));
    QCOMPARE(j.engineVersion, QStringLiteral("v6.2.6"));
    QCOMPARE(j.engineArgs, (QStringList{QStringLiteral("-m"), QStringLiteral("13400")}));
}

void TestDataModels::recoveredCredentialRoundTrip()
{
    RecoveredCredential c;
    c.id = QUuid::createUuid();
    c.caseId = "case-1";
    c.jobId = QUuid::createUuid();
    c.evidenceId = QUuid::createUuid();
    c.engineId = "bkcrack";
    c.kind = ResultKind::InternalKey;
    c.hash = "/case/e.zip!secret.doc";
    c.plaintext = "c1cb4c4d 887e6dad 42163b2a";
    c.rawPlaintext = QByteArray("c1cb4c4d 887e6dad 42163b2a");
    c.encoding = "utf-8";
    c.recoveredUtc = QDateTime::currentDateTimeUtc();

    const RecoveredCredential back = RecoveredCredential::fromJson(c.toJson());
    QCOMPARE(back.id, c.id);
    QCOMPARE(back.jobId, c.jobId);
    QCOMPARE(back.evidenceId, c.evidenceId);
    QCOMPARE(back.engineId, c.engineId);
    QCOMPARE(back.kind, ResultKind::InternalKey); // key material, not a password
    QCOMPARE(back.hash, c.hash);
    QCOMPARE(back.plaintext, c.plaintext);
    QCOMPARE(back.rawPlaintext, c.rawPlaintext);
    QCOMPARE(back.encoding, c.encoding);
}

void TestDataModels::legacyCredentialIsPassword()
{
    // A record written before result kinds existed has no "kind"/"engineId";
    // it must load as a recovered Password.
    QJsonObject obj;
    obj[QStringLiteral("id")] = QUuid::createUuid().toString(QUuid::WithoutBraces);
    obj[QStringLiteral("hash")] = QStringLiteral("$pdf$...");
    obj[QStringLiteral("plaintext")] = QStringLiteral("hunter2");
    const RecoveredCredential c = RecoveredCredential::fromJson(obj);
    QCOMPARE(c.kind, ResultKind::Password);
    QCOMPARE(c.plaintext, QStringLiteral("hunter2"));
    QVERIFY(c.engineId.isEmpty());
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
