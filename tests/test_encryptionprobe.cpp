/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "forensic/extraction/encryptionprobe.h"

#include <QFile>
#include <QTemporaryDir>
#include <QtTest>

using namespace forensic;

class TestEncryptionProbe : public QObject
{
    Q_OBJECT

private:
    static QString write(QTemporaryDir &d, const QString &name, const QByteArray &bytes)
    {
        const QString p = d.filePath(name);
        QFile f(p); f.open(QIODevice::WriteOnly); f.write(bytes); f.close();
        return p;
    }

private slots:
    void zipEncryptedFlagSet();
    void zipEncryptedFlagClear();
    void zipNoEntriesUnknown();
    void pdfEncryptDict();
    void pdfNoEncrypt();
    void keepassAlwaysEncrypted();
    void bitlockerAlwaysEncrypted();
    void otherTypesUnknown();
};

void TestEncryptionProbe::zipEncryptedFlagSet()
{
    QTemporaryDir d;
    // Local file header: PK\x03\x04, version(2), general-purpose flag(2)=0x0001.
    QByteArray b("\x50\x4b\x03\x04\x14\x00\x01\x00", 8);
    b.append(QByteArray(32, '\0'));
    QCOMPARE(EncryptionProbe::probeZip(write(d, "a.zip", b)), EncryptionState::Encrypted);
}

void TestEncryptionProbe::zipEncryptedFlagClear()
{
    QTemporaryDir d;
    QByteArray b("\x50\x4b\x03\x04\x14\x00\x00\x00", 8);
    b.append(QByteArray(32, '\0'));
    QCOMPARE(EncryptionProbe::probeZip(write(d, "a.zip", b)), EncryptionState::NotEncrypted);
}

void TestEncryptionProbe::zipNoEntriesUnknown()
{
    QTemporaryDir d;
    QCOMPARE(EncryptionProbe::probeZip(write(d, "x.bin", QByteArray("no zip here"))),
             EncryptionState::Unknown);
}

void TestEncryptionProbe::pdfEncryptDict()
{
    QTemporaryDir d;
    const QByteArray b("%PDF-1.6\n... /Encrypt 12 0 R ... trailer");
    QCOMPARE(EncryptionProbe::probePdf(write(d, "a.pdf", b)), EncryptionState::Encrypted);
}

void TestEncryptionProbe::pdfNoEncrypt()
{
    QTemporaryDir d;
    const QByteArray b("%PDF-1.6\nplain content, no encryption dictionary");
    QCOMPARE(EncryptionProbe::probePdf(write(d, "a.pdf", b)), EncryptionState::NotEncrypted);
}

void TestEncryptionProbe::keepassAlwaysEncrypted()
{
    QTemporaryDir d;
    const ArtifactType kp{"keepass-kdbx", "KeePass", 0.98};
    QCOMPARE(EncryptionProbe::probe(kp, write(d, "a.kdbx", QByteArray("\x03\xd9\xa2\x9a", 4))),
             EncryptionState::Encrypted);
}

void TestEncryptionProbe::bitlockerAlwaysEncrypted()
{
    QTemporaryDir d;
    const ArtifactType bl{"bitlocker", "BitLocker volume", 0.97};
    QCOMPARE(EncryptionProbe::probe(bl, write(d, "vol.bin", QByteArray("\xEB\x58\x90-FVE-FS-", 11))),
             EncryptionState::Encrypted);
}

void TestEncryptionProbe::otherTypesUnknown()
{
    QTemporaryDir d;
    const ArtifactType rar{"rar", "RAR", 0.95};
    QCOMPARE(EncryptionProbe::probe(rar, write(d, "a.rar", QByteArray("Rar!"))),
             EncryptionState::Unknown);
}

QTEST_GUILESS_MAIN(TestEncryptionProbe)
#include "test_encryptionprobe.moc"
