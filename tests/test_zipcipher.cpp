/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "forensic/extraction/zipcipher.h"

#include <QtTest>

using namespace forensic;

namespace {

void putU16(QByteArray &b, quint16 v)
{
    b.append(char(v & 0xff));
    b.append(char((v >> 8) & 0xff));
}
void putU32(QByteArray &b, quint32 v)
{
    b.append(char(v & 0xff));
    b.append(char((v >> 8) & 0xff));
    b.append(char((v >> 16) & 0xff));
    b.append(char((v >> 24) & 0xff));
}

// A WinZip AES extra field (header id 0x9901).
QByteArray aesExtra()
{
    QByteArray e;
    putU16(e, 0x9901); // header id
    putU16(e, 7);      // data size
    e.append(QByteArray(7, '\0'));
    return e;
}

// Build a central-directory file header (PK\x01\x02).
QByteArray centralHeader(const QByteArray &name, quint16 flag, quint16 method,
                         const QByteArray &extra = QByteArray())
{
    QByteArray b;
    b.append("PK\x01\x02", 4);
    putU16(b, 20);              // version made by
    putU16(b, 20);              // version needed
    putU16(b, flag);            // general purpose bit flag
    putU16(b, method);          // compression method
    putU16(b, 0); putU16(b, 0); // time, date
    putU32(b, 0);               // crc32
    putU32(b, 123);             // compressed size
    putU32(b, 456);             // uncompressed size
    putU16(b, quint16(name.size()));
    putU16(b, quint16(extra.size()));
    putU16(b, 0);               // comment length
    putU16(b, 0);               // disk number start
    putU16(b, 0);               // internal attrs
    putU32(b, 0);               // external attrs
    putU32(b, 0);               // local header offset
    b.append(name);
    b.append(extra);
    return b;
}

// Build a local file header (PK\x03\x04).
QByteArray localHeader(const QByteArray &name, quint16 flag, quint16 method,
                       const QByteArray &extra = QByteArray())
{
    QByteArray b;
    b.append("PK\x03\x04", 4);
    putU16(b, 20);              // version needed
    putU16(b, flag);            // general purpose bit flag
    putU16(b, method);          // compression method
    putU16(b, 0); putU16(b, 0); // time, date
    putU32(b, 0);               // crc32
    putU32(b, 123);             // compressed size
    putU32(b, 456);             // uncompressed size
    putU16(b, quint16(name.size()));
    putU16(b, quint16(extra.size()));
    b.append(name);
    b.append(extra);
    return b;
}

constexpr quint16 kEncrypted = 0x0001;

} // namespace

class TestZipCipher : public QObject
{
    Q_OBJECT
private slots:
    void notZipData();
    void unencryptedEntry();
    void zipCryptoEntry();
    void aesByMethod();
    void aesByExtraField();
    void mixedArchive();
    void localHeaderFallback();
    void zipCryptoEntryNamesListed();
    void truncatedNameDoesNotCrash();
};

void TestZipCipher::notZipData()
{
    const ZipCipherScan s = ZipCipherClassifier::scanData(QByteArray("not a zip at all"));
    QVERIFY(!s.isZip);
    QVERIFY(!s.anyEncrypted());
    QVERIFY(!s.hasZipCrypto());
}

void TestZipCipher::unencryptedEntry()
{
    const ZipCipherScan s = ZipCipherClassifier::scanData(centralHeader("a.txt", 0, 8));
    QVERIFY(s.isZip);
    QCOMPARE(s.entries.size(), 1);
    QCOMPARE(s.entries.first().cipher, ZipEntryCipher::None);
    QVERIFY(!s.anyEncrypted());
    QVERIFY(!s.hasZipCrypto());
}

void TestZipCipher::zipCryptoEntry()
{
    // Encrypted, normal deflate method -> legacy ZipCrypto (bkcrack applies).
    const ZipCipherScan s = ZipCipherClassifier::scanData(centralHeader("secret.txt", kEncrypted, 8));
    QVERIFY(s.isZip);
    QCOMPARE(s.entries.first().cipher, ZipEntryCipher::ZipCrypto);
    QVERIFY(s.hasZipCrypto());
    QVERIFY(!s.hasAes());
}

void TestZipCipher::aesByMethod()
{
    // Encrypted with compression method 99 -> WinZip AES (bkcrack does not apply).
    const ZipCipherScan s = ZipCipherClassifier::scanData(centralHeader("secret.txt", kEncrypted, 99));
    QCOMPARE(s.entries.first().cipher, ZipEntryCipher::Aes);
    QVERIFY(s.hasAes());
    QVERIFY(!s.hasZipCrypto());
}

void TestZipCipher::aesByExtraField()
{
    // Defensive: even if the method field is not 99, an AES extra field marks AES.
    const ZipCipherScan s =
        ZipCipherClassifier::scanData(centralHeader("secret.txt", kEncrypted, 8, aesExtra()));
    QCOMPARE(s.entries.first().cipher, ZipEntryCipher::Aes);
    QVERIFY(s.hasAes());
    QVERIFY(!s.hasZipCrypto());
}

void TestZipCipher::mixedArchive()
{
    QByteArray d;
    d += centralHeader("plain.txt", 0, 8);            // unencrypted
    d += centralHeader("legacy.txt", kEncrypted, 8);  // ZipCrypto
    d += centralHeader("modern.txt", kEncrypted, 99); // AES
    const ZipCipherScan s = ZipCipherClassifier::scanData(d);
    QCOMPARE(s.entries.size(), 3);
    QVERIFY(s.anyEncrypted());
    QVERIFY(s.hasZipCrypto());
    QVERIFY(s.hasAes());
}

void TestZipCipher::localHeaderFallback()
{
    // No central directory present -> fall back to local file headers.
    const ZipCipherScan s = ZipCipherClassifier::scanData(localHeader("secret.txt", kEncrypted, 0));
    QVERIFY(s.isZip);
    QCOMPARE(s.entries.size(), 1);
    QCOMPARE(s.entries.first().cipher, ZipEntryCipher::ZipCrypto);
}

void TestZipCipher::zipCryptoEntryNamesListed()
{
    QByteArray d;
    d += centralHeader("a.bin", kEncrypted, 8);   // ZipCrypto
    d += centralHeader("b.bin", kEncrypted, 99);  // AES
    d += centralHeader("c.bin", kEncrypted, 0);   // ZipCrypto (stored)
    const ZipCipherScan s = ZipCipherClassifier::scanData(d);
    QCOMPARE(s.zipCryptoEntryNames(), (QStringList{QStringLiteral("a.bin"), QStringLiteral("c.bin")}));
}

void TestZipCipher::truncatedNameDoesNotCrash()
{
    // A central header whose declared name length runs past the buffer must be
    // handled without reading out of bounds (and without inventing an entry).
    QByteArray d = centralHeader("secret.txt", kEncrypted, 8);
    d.chop(6); // cut into the name
    const ZipCipherScan s = ZipCipherClassifier::scanData(d);
    QVERIFY(s.entries.isEmpty()); // record was rejected as truncated
    QVERIFY(s.isZip);             // but the signature was still seen
}

QTEST_GUILESS_MAIN(TestZipCipher)
#include "test_zipcipher.moc"
