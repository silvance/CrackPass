/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "forensic/extraction/moderesolution.h"

#include <QtTest>

using namespace forensic;

class TestModeResolution : public QObject
{
    Q_OBJECT

private:
    static QVector<quint32> modeValues(const QVector<HashcatModeOption> &opts)
    {
        QVector<quint32> v;
        for (const auto &o : opts) v.append(o.mode);
        return v;
    }

private slots:
    void officeVersions();
    void officeLegacyAmbiguous();
    void pdfByRevision();
    void zipWinZipVsPkzip();
    void rarVariants();
    void sevenZipAndKeePass();
    void unrecognizedIsEmpty();
};

void TestModeResolution::officeVersions()
{
    QCOMPARE(modeValues(modes::forOffice("$office$*2007*1*...")), (QVector<quint32>{9400}));
    QCOMPARE(modeValues(modes::forOffice("$office$*2010*1*...")), (QVector<quint32>{9500}));
    QCOMPARE(modeValues(modes::forOffice("$office$*2013*1*...")), (QVector<quint32>{9600}));
}

void TestModeResolution::officeLegacyAmbiguous()
{
    const auto o0 = modes::forOffice("$oldoffice$0*aaa*bbb*ccc");
    QCOMPARE(o0.size(), 3);
    QVERIFY(modeValues(o0).contains(9700));
    const auto o3 = modes::forOffice("$oldoffice$3*aaa*bbb*ccc");
    QCOMPARE(o3.size(), 3);
    QVERIFY(modeValues(o3).contains(9800));
}

void TestModeResolution::pdfByRevision()
{
    QCOMPARE(modeValues(modes::forPdf("$pdf$1*2*40*...")), (QVector<quint32>{10400}));
    QCOMPARE(modeValues(modes::forPdf("$pdf$2*3*128*...")), (QVector<quint32>{10500}));
    QCOMPARE(modeValues(modes::forPdf("$pdf$4*4*128*...")), (QVector<quint32>{10500}));
    QCOMPARE(modeValues(modes::forPdf("$pdf$5*5*256*...")), (QVector<quint32>{10600}));
    QCOMPARE(modeValues(modes::forPdf("$pdf$5*6*256*...")), (QVector<quint32>{10700}));
    // Unknown revision -> all four candidates, not a guess.
    QCOMPARE(modes::forPdf("$pdf$9*9*...").size(), 4);
}

void TestModeResolution::zipWinZipVsPkzip()
{
    QCOMPARE(modeValues(modes::forZip("$zip2$*0*...*$/zip2$")), (QVector<quint32>{13600}));
    const auto pk = modes::forZip("$pkzip2$1*1*2*0*...");
    QVERIFY(pk.size() > 1); // ambiguous
    QVERIFY(modeValues(pk).contains(17200));
}

void TestModeResolution::rarVariants()
{
    QCOMPARE(modeValues(modes::forRar("$rar5$16*...")), (QVector<quint32>{13000}));
    QCOMPARE(modeValues(modes::forRar("$RAR3$*0*aaa*bbb")), (QVector<quint32>{12500}));
    const auto p = modes::forRar("$RAR3$*1*aaa*bbb");
    QCOMPARE(p.size(), 2);
    QVERIFY(modeValues(p).contains(23700));
}

void TestModeResolution::sevenZipAndKeePass()
{
    QCOMPARE(modeValues(modes::forSevenZip("$7z$0$...")), (QVector<quint32>{11600}));
    QCOMPARE(modeValues(modes::forKeePass("$keepass$*1*...")), (QVector<quint32>{13400}));
}

void TestModeResolution::unrecognizedIsEmpty()
{
    QVERIFY(modes::forOffice("$notoffice$").isEmpty());
    QVERIFY(modes::forPdf("garbage").isEmpty());
    QVERIFY(modes::forZip("$rar5$").isEmpty());
    QVERIFY(modes::forKeePass("$7z$").isEmpty());
}

QTEST_GUILESS_MAIN(TestModeResolution)
#include "test_moderesolution.moc"
