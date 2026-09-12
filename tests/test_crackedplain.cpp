/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#include "forensic/execution/crackedplain.h"
#include "forensic/execution/hashcatexecutionbackend.h"

#include <QtTest>

using namespace forensic;

class TestCrackedPlain : public QObject
{
    Q_OBJECT
private:
    // Build the $HEX[...] form hashcat would emit for a given password.
    static QString hexOf(const QString &plain)
    {
        return QStringLiteral("$HEX[") + QString::fromLatin1(plain.toUtf8().toHex()) + QLatin1Char(']');
    }

private slots:
    void plainPassthrough();
    void colonPassword();
    void spacePassword();
    void unicodePassword();
    void literalDollarHexText();
    void outfileFormatIsPlain();
};

void TestCrackedPlain::plainPassthrough()
{
    QCOMPARE(decodeHashcatPlain("hunter2"), QStringLiteral("hunter2"));
}

void TestCrackedPlain::colonPassword()
{
    // With plaintext-only outfile the colon is literal; and $HEX round-trips it.
    QCOMPARE(decodeHashcatPlain("pass:word"), QStringLiteral("pass:word"));
    QCOMPARE(decodeHashcatPlain(hexOf("pa:ss:wd")), QStringLiteral("pa:ss:wd"));
}

void TestCrackedPlain::spacePassword()
{
    QCOMPARE(decodeHashcatPlain(hexOf("correct horse battery")),
             QStringLiteral("correct horse battery"));
}

void TestCrackedPlain::unicodePassword()
{
    QCOMPARE(decodeHashcatPlain(hexOf(QString::fromUtf8("café𝔫🔑"))),
             QString::fromUtf8("café𝔫🔑"));
}

void TestCrackedPlain::literalDollarHexText()
{
    // A password that is not $HEX-wrapped is returned verbatim, even if it
    // merely looks similar.
    QCOMPARE(decodeHashcatPlain("$dollar$word"), QStringLiteral("$dollar$word"));
}

void TestCrackedPlain::outfileFormatIsPlain()
{
    CrackingJob job;
    job.hashcatArgs = {"-m", "13400", "-a", "0", "hash.txt", "wl.txt"};
    JobExecutionBackend::StartOptions opts;
    opts.sessionName = "s";
    opts.outfilePath = "/case/cracked.out";
    const QStringList args = HashcatExecutionBackend::composeArgs(job, opts);
    const int i = args.indexOf("--outfile-format");
    QVERIFY(i >= 0);
    QCOMPARE(args.at(i + 1), QStringLiteral("2")); // plaintext-only
}

QTEST_GUILESS_MAIN(TestCrackedPlain)
#include "test_crackedplain.moc"
