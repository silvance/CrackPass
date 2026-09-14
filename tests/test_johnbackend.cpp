/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "forensic/execution/johnexecutionbackend.h"
#include "forensic/execution/hashcatstatus.h"
#include "forensic/execution/crackedplain.h"

#include <QtTest>

using namespace forensic;

class TestJohnBackend : public QObject
{
    Q_OBJECT
private slots:
    void composeStartArgs();
    void composeRestoreArgs();
    void programPrefersJobPath();
    void potSplitExactWhenHashKnown();
    void potSplitFallsBackToFirstColon();
    void potDecodesHexPlaintext();
    void potIgnoresBlankOrColonlessLines();
    void progressParsesGuessesAndSpeed();
    void progressScalesSpeedSuffix();
    void progressRejectsNonStatusLines();
    void failedToStartEmitsOneFailureAndNeverRunning();
};

static CrackingJob johnJob()
{
    CrackingJob j;
    j.id = QUuid::createUuid();
    j.engineId = QStringLiteral("john");
    j.enginePath = QStringLiteral("/tools/john/run/john");
    j.engineArgs = {QStringLiteral("--wordlist=wl.txt"), QStringLiteral("hash.txt")};
    j.hashFile = QStringLiteral("hash.txt");
    return j;
}

static JobExecutionBackend::StartOptions opts(bool restore)
{
    JobExecutionBackend::StartOptions o;
    o.workingDir = QStringLiteral("/case/job");
    o.sessionName = QStringLiteral("cp-abcd1234");
    o.potfilePath = QStringLiteral("/case/job/job.potfile");
    o.restore = restore;
    return o;
}

void TestJohnBackend::composeStartArgs()
{
    const QStringList args = JohnExecutionBackend::composeArgs(johnJob(), opts(false));
    // Attack argv first, then session + pot plumbing, then status cadence.
    QCOMPARE(args.value(0), QStringLiteral("--wordlist=wl.txt"));
    QCOMPARE(args.value(1), QStringLiteral("hash.txt"));
    QVERIFY(args.contains(QStringLiteral("--session=cp-abcd1234")));
    QVERIFY(args.contains(QStringLiteral("--pot=/case/job/job.potfile")));
    QVERIFY(args.contains(QStringLiteral("--progress-every=5")));
}

void TestJohnBackend::composeRestoreArgs()
{
    const QStringList args = JohnExecutionBackend::composeArgs(johnJob(), opts(true));
    // Restore reloads everything from the session; only the session is named.
    QCOMPARE(args, (QStringList{QStringLiteral("--restore=cp-abcd1234")}));
}

void TestJohnBackend::programPrefersJobPath()
{
    CrackingJob j = johnJob();
    QCOMPARE(JohnExecutionBackend::programFor(j, QStringLiteral("/fallback/john")),
             QStringLiteral("/tools/john/run/john"));
    j.enginePath.clear();
    QCOMPARE(JohnExecutionBackend::programFor(j, QStringLiteral("/fallback/john")),
             QStringLiteral("/fallback/john"));
}

void TestJohnBackend::potSplitExactWhenHashKnown()
{
    // A ciphertext that itself contains colons must still split correctly when
    // we know the target hash (prefix match), not at the first colon.
    const QString hash = QStringLiteral("$netntlmv2$user::DOMAIN$1122:3344");
    const QString line = hash + QStringLiteral(":secretpw");
    QCOMPARE(JohnExecutionBackend::potPlaintextToken(line, hash), QStringLiteral("secretpw"));
}

void TestJohnBackend::potSplitFallsBackToFirstColon()
{
    // Without a known hash, split on the first colon (best effort).
    const QString line = QStringLiteral("$office$*something:hunter2");
    QCOMPARE(JohnExecutionBackend::potPlaintextToken(line, QString()),
             QStringLiteral("hunter2"));
}

void TestJohnBackend::potDecodesHexPlaintext()
{
    // john $HEX[..]-wraps awkward plaintexts; the token decodes losslessly.
    const QString hash = QStringLiteral("$pdf$abc");
    const QString token = JohnExecutionBackend::potPlaintextToken(
        hash + QStringLiteral(":$HEX[70e4ff]"), hash);
    QCOMPARE(token, QStringLiteral("$HEX[70e4ff]"));
    QCOMPARE(decodeHashcatPlain(token).raw, QByteArray::fromHex("70e4ff"));
}

void TestJohnBackend::potIgnoresBlankOrColonlessLines()
{
    QVERIFY(JohnExecutionBackend::potPlaintextToken(QString(), QString()).isEmpty());
    QVERIFY(JohnExecutionBackend::potPlaintextToken(QStringLiteral("   "), QString()).isEmpty());
    QVERIFY(JohnExecutionBackend::potPlaintextToken(QStringLiteral("nocolonhere"), QString()).isEmpty());
}

void TestJohnBackend::progressParsesGuessesAndSpeed()
{
    RecoveryStatus st;
    const QString line = QStringLiteral("2g 0:00:00:05 12.34% (ETA: 12:00:00) 4567p/s 4321c/s 4321C/s a..b");
    QVERIFY(JohnExecutionBackend::parseProgressLine(line, st));
    QVERIFY(st.valid);
    QCOMPARE(st.state, RecoveryState::Running);
    QCOMPARE(st.nativeStatusCode, 0); // John never invents a hashcat status code
    QCOMPARE(st.recoveredHashes, 2);
    QCOMPARE(st.aggregateSpeed, static_cast<qint64>(4321)); // prefers c/s
}

void TestJohnBackend::progressScalesSpeedSuffix()
{
    RecoveryStatus st;
    QVERIFY(JohnExecutionBackend::parseProgressLine(
        QStringLiteral("0g 0:00:01:00 1.5Mc/s done"), st));
    QCOMPARE(st.aggregateSpeed, static_cast<qint64>(1500000));
}

void TestJohnBackend::progressRejectsNonStatusLines()
{
    RecoveryStatus st;
    QVERIFY(!JohnExecutionBackend::parseProgressLine(
        QStringLiteral("Loaded 1 password hash (PDF ...)"), st));
    QVERIFY(!JohnExecutionBackend::parseProgressLine(QString(), st));
}

void TestJohnBackend::failedToStartEmitsOneFailureAndNeverRunning()
{
    // A process that cannot start must produce exactly one clean failure and
    // must NEVER transiently appear as Running (running is tied to the real
    // QProcess::started signal, not emitted optimistically after start()).
    JohnExecutionBackend backend(QStringLiteral("/nonexistent/definitely/not/here/john"));
    CrackingJob j = johnJob();
    j.enginePath = QStringLiteral("/nonexistent/definitely/not/here/john");

    QSignalSpy running(&backend, SIGNAL(running(QUuid)));
    QSignalSpy failed(&backend, SIGNAL(failed(QUuid, QString)));
    QVERIFY(running.isValid());
    QVERIFY(failed.isValid());

    backend.start(j, opts(false));

    QTRY_COMPARE_WITH_TIMEOUT(failed.count(), 1, 5000);
    QCOMPARE(running.count(), 0); // never appeared Running
    // The reported failure carries this job's id.
    QCOMPARE(failed.first().at(0).toUuid(), j.id);
}

QTEST_GUILESS_MAIN(TestJohnBackend)
#include "test_johnbackend.moc"
