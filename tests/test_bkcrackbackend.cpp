/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "forensic/execution/bkcrackexecutionbackend.h"
#include "forensic/execution/hashcatstatus.h"

#include <QtTest>

using namespace forensic;

class TestBkcrackBackend : public QObject
{
    Q_OBJECT
private slots:
    void composeArgsIsTheJobArgv();
    void programPrefersJobPath();
    void parsesKeysWithLabel();
    void parsesKeysBareTriple();
    void rejectsNonKeysLines();
    void doesNotReadKeysFromProgress();
    void parsesProgress();
    void rejectsNonProgress();
    void targetLabelFromArgv();
};

static CrackingJob bkcrackJob()
{
    CrackingJob j;
    j.id = QUuid::createUuid();
    j.engineId = QStringLiteral("bkcrack");
    j.enginePath = QStringLiteral("/tools/bkcrack");
    j.engineArgs = {QStringLiteral("-C"), QStringLiteral("/case/e.zip"),
                     QStringLiteral("-c"), QStringLiteral("secret.doc"),
                     QStringLiteral("-p"), QStringLiteral("/case/known.bin")};
    return j;
}

void TestBkcrackBackend::composeArgsIsTheJobArgv()
{
    QCOMPARE(BkcrackExecutionBackend::composeArgs(bkcrackJob(), {}), bkcrackJob().engineArgs);
}

void TestBkcrackBackend::programPrefersJobPath()
{
    CrackingJob j = bkcrackJob();
    QCOMPARE(BkcrackExecutionBackend::programFor(j, QStringLiteral("/fallback/bkcrack")),
             QStringLiteral("/tools/bkcrack"));
    j.enginePath.clear();
    QCOMPARE(BkcrackExecutionBackend::programFor(j, QStringLiteral("/fallback/bkcrack")),
             QStringLiteral("/fallback/bkcrack"));
}

void TestBkcrackBackend::parsesKeysWithLabel()
{
    QCOMPARE(BkcrackExecutionBackend::parseKeysLine(QStringLiteral("Keys: C1CB4C4D 887E6DAD 42163B2A")),
             QStringLiteral("c1cb4c4d 887e6dad 42163b2a"));
}

void TestBkcrackBackend::parsesKeysBareTriple()
{
    // Some bkcrack versions print the triple on its own line after a "Keys" line.
    QCOMPARE(BkcrackExecutionBackend::parseKeysLine(QStringLiteral("c1cb4c4d 887e6dad 42163b2a")),
             QStringLiteral("c1cb4c4d 887e6dad 42163b2a"));
}

void TestBkcrackBackend::rejectsNonKeysLines()
{
    QVERIFY(BkcrackExecutionBackend::parseKeysLine(QStringLiteral("Z reduction using 12 bytes")).isEmpty());
    QVERIFY(BkcrackExecutionBackend::parseKeysLine(QString()).isEmpty());
    // Too-short hex words must not be mistaken for keys.
    QVERIFY(BkcrackExecutionBackend::parseKeysLine(QStringLiteral("dead beef cafe")).isEmpty());
}

void TestBkcrackBackend::doesNotReadKeysFromProgress()
{
    // A progress line must never be misparsed as keys, even if counts look hex-ish.
    QVERIFY(BkcrackExecutionBackend::parseKeysLine(
                QStringLiteral("50.0 % (12345678 / 16777216)")).isEmpty());
}

void TestBkcrackBackend::parsesProgress()
{
    HashcatStatus st;
    QVERIFY(BkcrackExecutionBackend::parseProgressLine(
        QStringLiteral("50.0 % (8388608 / 16777216)"), st));
    QVERIFY(st.valid);
    QCOMPARE(st.statusCode, HashcatStatusCode::Running);
    QCOMPARE(st.progressDone, Q_INT64_C(8388608));
    QCOMPARE(st.progressTotal, Q_INT64_C(16777216));
}

void TestBkcrackBackend::rejectsNonProgress()
{
    HashcatStatus st;
    QVERIFY(!BkcrackExecutionBackend::parseProgressLine(
        QStringLiteral("Keys: c1cb4c4d 887e6dad 42163b2a"), st));
    QVERIFY(!BkcrackExecutionBackend::parseProgressLine(QString(), st));
}

void TestBkcrackBackend::targetLabelFromArgv()
{
    QCOMPARE(BkcrackExecutionBackend::targetLabel(bkcrackJob()),
             QStringLiteral("/case/e.zip!secret.doc"));
}

QTEST_GUILESS_MAIN(TestBkcrackBackend)
#include "test_bkcrackbackend.moc"
