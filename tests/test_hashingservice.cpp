/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#include "forensic/hashingservice.h"

#include <QCryptographicHash>
#include <QFile>
#include <QTemporaryDir>
#include <QtTest>

using forensic::HashingService;

class TestHashingService : public QObject
{
    Q_OBJECT

private slots:
    void knownVector();
    void largeFileMatchesQt();
    void readOnlyDoesNotModify();
    void missingFileFails();
};

// SHA-256("abc") is a published test vector.
void TestHashingService::knownVector()
{
    QTemporaryDir dir;
    const QString path = dir.filePath("abc.bin");
    QFile f(path);
    QVERIFY(f.open(QIODevice::WriteOnly));
    f.write("abc");
    f.close();

    QCOMPARE(HashingService::sha256File(path),
             QStringLiteral("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}

// A multi-chunk file must match Qt's own one-shot digest.
void TestHashingService::largeFileMatchesQt()
{
    QTemporaryDir dir;
    const QString path = dir.filePath("big.bin");
    QByteArray data;
    data.resize(static_cast<int>(HashingService::ChunkSize) * 2 + 12345);
    for (int i = 0; i < data.size(); ++i)
        data[i] = static_cast<char>((i * 31 + 7) & 0xff);

    QFile f(path);
    QVERIFY(f.open(QIODevice::WriteOnly));
    f.write(data);
    f.close();

    const QString expected =
        QString::fromLatin1(QCryptographicHash::hash(data, QCryptographicHash::Sha256).toHex());
    QCOMPARE(HashingService::sha256File(path), expected);
}

void TestHashingService::readOnlyDoesNotModify()
{
    QTemporaryDir dir;
    const QString path = dir.filePath("evidence.bin");
    QFile f(path);
    QVERIFY(f.open(QIODevice::WriteOnly));
    f.write("original evidence content");
    f.close();

    const QByteArray before = [&] { QFile r(path); r.open(QIODevice::ReadOnly); return r.readAll(); }();
    HashingService::sha256File(path);
    const QByteArray after = [&] { QFile r(path); r.open(QIODevice::ReadOnly); return r.readAll(); }();
    QCOMPARE(after, before);
}

void TestHashingService::missingFileFails()
{
    QString error;
    const QString result = HashingService::sha256File("/no/such/file/here.bin", &error);
    QVERIFY(result.isEmpty());
    QVERIFY(!error.isEmpty());
}

QTEST_GUILESS_MAIN(TestHashingService)
#include "test_hashingservice.moc"
