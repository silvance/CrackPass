/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "forensic/execution/hashcatstatusstream.h"

#include <QtTest>

using namespace forensic;

class TestStatusStream : public QObject
{
    Q_OBJECT
private:
    static QByteArray rec(int status, qint64 done, qint64 total)
    {
        return QByteArray("{\"status\":") + QByteArray::number(status)
             + ",\"progress\":[" + QByteArray::number(done) + "," + QByteArray::number(total) + "]}\n";
    }

private slots:
    void wholeLine();
    void splitAtEveryByte();
    void multipleRecordsInOneChunk();
    void partialWithoutNewlineYieldsNothing();
    void ignoresNonJsonBanner();
};

void TestStatusStream::wholeLine()
{
    HashcatStatusStream s;
    const auto out = s.append(rec(3, 5, 10));
    QCOMPARE(out.size(), 1);
    QCOMPARE(out.first().progressDone, qint64(5));
    QCOMPARE(s.pendingBytes(), 0);
}

// The core regression: feed one record one byte at a time; it must emerge
// exactly once, only after its terminating newline.
void TestStatusStream::splitAtEveryByte()
{
    const QByteArray full = rec(3, 123, 456);
    for (int split = 1; split < full.size(); ++split) {
        HashcatStatusStream s;
        const auto a = s.append(full.left(split));
        const auto b = s.append(full.mid(split));
        const int total = a.size() + b.size();
        QCOMPARE(total, 1);
        const RecoveryStatus st = a.isEmpty() ? b.first() : a.first();
        QCOMPARE(st.progressDone, qint64(123));
        QCOMPARE(st.progressTotal, qint64(456));
        // Nothing should surface before the newline is delivered.
        if (!full.left(split).contains('\n'))
            QVERIFY(a.isEmpty());
    }
}

void TestStatusStream::multipleRecordsInOneChunk()
{
    HashcatStatusStream s;
    const auto out = s.append(rec(3, 1, 10) + rec(5, 10, 10));
    QCOMPARE(out.size(), 2);
    QCOMPARE(out.at(0).nativeStatusCode, 3);
    QCOMPARE(out.at(1).nativeStatusCode, 5);
}

void TestStatusStream::partialWithoutNewlineYieldsNothing()
{
    HashcatStatusStream s;
    QByteArray r = rec(3, 7, 9);
    r.chop(1); // drop the trailing newline
    QVERIFY(s.append(r).isEmpty());
    QVERIFY(s.pendingBytes() > 0);
    // The completing newline releases exactly one record.
    const auto out = s.append("\n");
    QCOMPARE(out.size(), 1);
    QCOMPARE(out.first().progressDone, qint64(7));
}

void TestStatusStream::ignoresNonJsonBanner()
{
    HashcatStatusStream s;
    const auto out = s.append(QByteArray("hashcat (v7.1.2) starting\n") + rec(3, 2, 4));
    QCOMPARE(out.size(), 1);
}

QTEST_GUILESS_MAIN(TestStatusStream)
#include "test_statusstream.moc"
