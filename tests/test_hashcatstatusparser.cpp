/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "forensic/execution/hashcatstatusparser.h"

#include <QtTest>

using namespace forensic;

class TestHashcatStatusParser : public QObject
{
    Q_OBJECT

private slots:
    void parsesRunningStatus();
    void aggregatesDeviceSpeeds();
    void percentAndRemaining();
    void rejectsNonStatusJson();
    void parseLatestPicksLastValid();
};

static QByteArray sampleStatus()
{
    return QByteArray(
        "{\"session\":\"cp\",\"status\":3,\"target\":\"hash.txt\","
        "\"progress\":[500,1000],\"recovered_hashes\":[0,1],"
        "\"devices\":[{\"device_id\":1,\"device_name\":\"NVIDIA RTX 4090\",\"speed\":1200},"
        "{\"device_id\":2,\"device_name\":\"NVIDIA RTX 4090\",\"speed\":800}],"
        "\"time_start\":1000,\"estimated_stop\":1100}");
}

void TestHashcatStatusParser::parsesRunningStatus()
{
    const RecoveryStatus s = HashcatStatusParser::parse(sampleStatus());
    QVERIFY(s.valid);
    QCOMPARE(s.nativeStatusCode, HashcatStatusCode::Running);
    QCOMPARE(s.state, RecoveryState::Running); // native code mapped to neutral state
    QCOMPARE(s.progressDone, qint64(500));
    QCOMPARE(s.progressTotal, qint64(1000));
    QCOMPARE(s.totalHashes, 1);
    QCOMPARE(s.devices.size(), 2);
}

void TestHashcatStatusParser::aggregatesDeviceSpeeds()
{
    const RecoveryStatus s = HashcatStatusParser::parse(sampleStatus());
    QCOMPARE(s.aggregateSpeed, qint64(2000)); // 1200 + 800
}

void TestHashcatStatusParser::percentAndRemaining()
{
    const RecoveryStatus s = HashcatStatusParser::parse(sampleStatus());
    QCOMPARE(s.progressPercent(), 50.0);
    QCOMPARE(s.remainingSeconds(1040), qint64(60)); // 1100 - 1040
    QCOMPARE(s.remainingSeconds(2000), qint64(0));  // past estimate -> clamped
}

void TestHashcatStatusParser::rejectsNonStatusJson()
{
    QVERIFY(!HashcatStatusParser::parse("not json").valid);
    QVERIFY(!HashcatStatusParser::parse("{\"hello\":1}").valid); // no status/progress
}

void TestHashcatStatusParser::parseLatestPicksLastValid()
{
    QByteArray chunk;
    chunk += "some banner line\n";
    chunk += "{\"status\":3,\"progress\":[10,100]}\n";
    chunk += "{\"status\":5,\"progress\":[100,100]}\n";
    const RecoveryStatus s = HashcatStatusParser::parseLatest(chunk);
    QVERIFY(s.valid);
    QCOMPARE(s.nativeStatusCode, HashcatStatusCode::Exhausted);
    QCOMPARE(s.state, RecoveryState::Exhausted);
    QCOMPARE(s.progressDone, qint64(100));
}

QTEST_GUILESS_MAIN(TestHashcatStatusParser)
#include "test_hashcatstatusparser.moc"
