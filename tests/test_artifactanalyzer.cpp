/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "forensic/artifactanalyzerregistry.h"

#include <QFile>
#include <QTemporaryDir>
#include <QtTest>

using forensic::ArtifactAnalyzerRegistry;
using forensic::ArtifactType;

class TestArtifactAnalyzer : public QObject
{
    Q_OBJECT

private:
    static QString writeBytes(QTemporaryDir &dir, const QString &name, const QByteArray &bytes)
    {
        const QString path = dir.filePath(name);
        QFile f(path);
        f.open(QIODevice::WriteOnly);
        f.write(bytes);
        f.close();
        return path;
    }

private slots:
    void detectsPdf();
    void detectsKeePass();
    void detectsZip();
    void unknownForRandomBytes();
};

void TestArtifactAnalyzer::detectsPdf()
{
    QTemporaryDir dir;
    auto reg = ArtifactAnalyzerRegistry::withBuiltins();
    const QString path = writeBytes(dir, "doc.pdf", QByteArray("%PDF-1.7\nrest"));
    QCOMPARE(reg.identify(path).id, QStringLiteral("pdf"));
}

void TestArtifactAnalyzer::detectsKeePass()
{
    QTemporaryDir dir;
    auto reg = ArtifactAnalyzerRegistry::withBuiltins();
    const QString path = writeBytes(dir, "db.kdbx", QByteArray("\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5", 8));
    QCOMPARE(reg.identify(path).id, QStringLiteral("keepass-kdbx"));
}

void TestArtifactAnalyzer::detectsZip()
{
    QTemporaryDir dir;
    auto reg = ArtifactAnalyzerRegistry::withBuiltins();
    const QString path = writeBytes(dir, "a.zip", QByteArray("\x50\x4b\x03\x04rest of zip", 15));
    QCOMPARE(reg.identify(path).id, QStringLiteral("zip"));
}

void TestArtifactAnalyzer::unknownForRandomBytes()
{
    QTemporaryDir dir;
    auto reg = ArtifactAnalyzerRegistry::withBuiltins();
    const QString path = writeBytes(dir, "rand.bin", QByteArray("just some plain text bytes here"));
    QVERIFY(reg.identify(path).isUnknown());
}

QTEST_GUILESS_MAIN(TestArtifactAnalyzer)
#include "test_artifactanalyzer.moc"
