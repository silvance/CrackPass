/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "forensic/bkcrack/bkcrackcommandbuilder.h"

#include <QtTest>

using namespace forensic;

class TestBkcrackCommandBuilder : public QObject
{
    Q_OBJECT
private slots:
    void plaintextFileAttack();
    void plaintextFileWithOffset();
    void bytesAtOffsetAttack();
    void hexIsNormalized();
    void refusesNoArchive();
    void refusesNoTargetEntry();
    void refusesNoPlaintext();
    void refusesBothPlaintextSources();
    void refusesInvalidHex();
    void refusesTooShortHex();
    void extraArgsAppended();
};

static BkcrackAttackSpec base()
{
    BkcrackAttackSpec s;
    s.zipPath = QStringLiteral("/case/eArchive.zip");
    s.targetEntry = QStringLiteral("secret.doc");
    return s;
}

void TestBkcrackCommandBuilder::plaintextFileAttack()
{
    BkcrackAttackSpec s = base();
    s.plainFile = QStringLiteral("/case/known.bin");
    const BkcrackBuildResult r = BkcrackCommandBuilder::build(s);
    QVERIFY(r.valid);
    QVERIFY(r.error.isEmpty());
    QCOMPARE(r.args, (QStringList{QStringLiteral("-C"), QStringLiteral("/case/eArchive.zip"),
                                  QStringLiteral("-c"), QStringLiteral("secret.doc"),
                                  QStringLiteral("-p"), QStringLiteral("/case/known.bin")}));
}

void TestBkcrackCommandBuilder::plaintextFileWithOffset()
{
    BkcrackAttackSpec s = base();
    s.plainFile = QStringLiteral("/case/known.bin");
    s.plainOffset = 42;
    const BkcrackBuildResult r = BkcrackCommandBuilder::build(s);
    QVERIFY(r.valid);
    QVERIFY(r.args.contains(QStringLiteral("-o")));
    const int i = r.args.indexOf(QStringLiteral("-o"));
    QCOMPARE(r.args.value(i + 1), QStringLiteral("42"));
}

void TestBkcrackCommandBuilder::bytesAtOffsetAttack()
{
    BkcrackAttackSpec s = base();
    s.plainHex = QStringLiteral("504b0304140000000800abcd"); // exactly 12 bytes
    s.plainOffset = 0;
    const BkcrackBuildResult r = BkcrackCommandBuilder::build(s);
    QVERIFY(r.valid);
    QCOMPARE(r.args, (QStringList{QStringLiteral("-C"), QStringLiteral("/case/eArchive.zip"),
                                  QStringLiteral("-c"), QStringLiteral("secret.doc"),
                                  QStringLiteral("-x"), QStringLiteral("0"),
                                  QStringLiteral("504b0304140000000800abcd")}));
}

void TestBkcrackCommandBuilder::hexIsNormalized()
{
    BkcrackAttackSpec s = base();
    s.plainHex = QStringLiteral("50 4B 03 04 14 00 00 00 08 00 AB CD"); // spaces + uppercase
    const BkcrackBuildResult r = BkcrackCommandBuilder::build(s);
    QVERIFY(r.valid);
    QCOMPARE(r.args.last(), QStringLiteral("504b0304140000000800abcd")); // stripped + lowercased
}

void TestBkcrackCommandBuilder::refusesNoArchive()
{
    BkcrackAttackSpec s = base();
    s.zipPath.clear();
    s.plainFile = QStringLiteral("k.bin");
    QVERIFY(!BkcrackCommandBuilder::build(s).valid);
}

void TestBkcrackCommandBuilder::refusesNoTargetEntry()
{
    BkcrackAttackSpec s = base();
    s.targetEntry.clear();
    s.plainFile = QStringLiteral("k.bin");
    QVERIFY(!BkcrackCommandBuilder::build(s).valid);
}

void TestBkcrackCommandBuilder::refusesNoPlaintext()
{
    const BkcrackBuildResult r = BkcrackCommandBuilder::build(base());
    QVERIFY(!r.valid);
    QVERIFY(r.error.contains(QStringLiteral("known plaintext")));
}

void TestBkcrackCommandBuilder::refusesBothPlaintextSources()
{
    BkcrackAttackSpec s = base();
    s.plainFile = QStringLiteral("k.bin");
    s.plainHex = QStringLiteral("504b0304140000000800abcd");
    const BkcrackBuildResult r = BkcrackCommandBuilder::build(s);
    QVERIFY(!r.valid);
    QVERIFY(r.error.contains(QStringLiteral("not both")));
}

void TestBkcrackCommandBuilder::refusesInvalidHex()
{
    BkcrackAttackSpec s = base();
    s.plainHex = QStringLiteral("504b0304zzzz0000abcd"); // non-hex chars
    QVERIFY(!BkcrackCommandBuilder::build(s).valid);

    BkcrackAttackSpec odd = base();
    odd.plainHex = QStringLiteral("504b0304140000000800abc"); // odd length
    QVERIFY(!BkcrackCommandBuilder::build(odd).valid);
}

void TestBkcrackCommandBuilder::refusesTooShortHex()
{
    BkcrackAttackSpec s = base();
    s.plainHex = QStringLiteral("504b03041400"); // 6 bytes < 12
    const BkcrackBuildResult r = BkcrackCommandBuilder::build(s);
    QVERIFY(!r.valid);
    QVERIFY(r.error.contains(QStringLiteral("at least")));
}

void TestBkcrackCommandBuilder::extraArgsAppended()
{
    BkcrackAttackSpec s = base();
    s.plainFile = QStringLiteral("k.bin");
    s.extraArgs = {QStringLiteral("-e")};
    const BkcrackBuildResult r = BkcrackCommandBuilder::build(s);
    QVERIFY(r.valid);
    QCOMPARE(r.args.last(), QStringLiteral("-e"));
}

QTEST_GUILESS_MAIN(TestBkcrackCommandBuilder)
#include "test_bkcrackcommandbuilder.moc"
