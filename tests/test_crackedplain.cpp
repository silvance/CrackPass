/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
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
    void nonUtf8BytesPreservedLosslessly();
    void outfileFormatIsPlain();
};

void TestCrackedPlain::plainPassthrough()
{
    const DecodedPlain d = decodeHashcatPlain("hunter2");
    QCOMPARE(d.display, QStringLiteral("hunter2"));
    QCOMPARE(d.raw, QByteArray("hunter2"));
    QCOMPARE(d.encoding, QStringLiteral("utf-8"));
}

void TestCrackedPlain::colonPassword()
{
    // With plaintext-only outfile the colon is literal; and $HEX round-trips it.
    QCOMPARE(decodeHashcatPlain("pass:word").display, QStringLiteral("pass:word"));
    const DecodedPlain d = decodeHashcatPlain(hexOf("pa:ss:wd"));
    QCOMPARE(d.display, QStringLiteral("pa:ss:wd"));
    QCOMPARE(d.raw, QByteArray("pa:ss:wd"));
}

void TestCrackedPlain::spacePassword()
{
    QCOMPARE(decodeHashcatPlain(hexOf("correct horse battery")).display,
             QStringLiteral("correct horse battery"));
}

void TestCrackedPlain::unicodePassword()
{
    const DecodedPlain d = decodeHashcatPlain(hexOf(QString::fromUtf8("café𝔫🔑")));
    QCOMPARE(d.display, QString::fromUtf8("café𝔫🔑"));
    QCOMPARE(d.raw, QString::fromUtf8("café𝔫🔑").toUtf8());
    QCOMPARE(d.encoding, QStringLiteral("utf-8"));
}

void TestCrackedPlain::literalDollarHexText()
{
    // A password that is not $HEX-wrapped is returned verbatim, even if it
    // merely looks similar.
    QCOMPARE(decodeHashcatPlain("$dollar$word").display, QStringLiteral("$dollar$word"));
}

void TestCrackedPlain::nonUtf8BytesPreservedLosslessly()
{
    // A password whose bytes are not valid UTF-8 (e.g. Latin-1 "pä" as 0x70 0xE4)
    // must survive as its exact bytes, shown in canonical $HEX[..] form.
    const QByteArray rawBytes = QByteArray::fromHex("70e4");
    const QString token = QStringLiteral("$HEX[") + QString::fromLatin1(rawBytes.toHex()) + QLatin1Char(']');
    const DecodedPlain d = decodeHashcatPlain(token);
    QCOMPARE(d.raw, rawBytes);                       // exact bytes preserved
    QCOMPARE(d.encoding, QStringLiteral("raw"));
    QCOMPARE(d.display, QStringLiteral("$HEX[70e4]")); // reversible, not mangled
    QVERIFY(!d.display.contains(QChar(QChar::ReplacementCharacter)));
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
