/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "forensic/extractorregistry.h"

#include <QtTest>

using forensic::ArtifactType;
using forensic::ExtractorRegistry;

class TestExtractorRegistry : public QObject
{
    Q_OBJECT

private:
    static ArtifactType type(const QString &id) { return ArtifactType{id, id, 0.9}; }

private slots:
    void coversAllTargetFormats();
    void noExtractorForUnknown();
    void resolvesToolIds();
};

void TestExtractorRegistry::coversAllTargetFormats()
{
    auto reg = ExtractorRegistry::withBuiltins();
    for (const QString &id : {"ms-office", "pdf", "zip", "rar", "7z", "keepass-kdbx"}) {
        QVERIFY2(reg.hasExtractorFor(type(id)), qPrintable(QStringLiteral("missing extractor for %1").arg(id)));
    }
}

void TestExtractorRegistry::noExtractorForUnknown()
{
    auto reg = ExtractorRegistry::withBuiltins();
    QVERIFY(!reg.hasExtractorFor(ArtifactType::unknown()));
    QCOMPARE(reg.extractorFor(ArtifactType::unknown()), nullptr);
    // A recognized-but-unsupported type (e.g. a bare unknown token) has none.
    QVERIFY(!reg.hasExtractorFor(type("tar")));
}

void TestExtractorRegistry::resolvesToolIds()
{
    auto reg = ExtractorRegistry::withBuiltins();
    QCOMPARE(reg.extractorFor(type("pdf"))->toolId(), QStringLiteral("pdf2john"));
    QCOMPARE(reg.extractorFor(type("keepass-kdbx"))->toolId(), QStringLiteral("keepass2john"));
    QCOMPARE(reg.extractorFor(type("ms-office"))->id(), QStringLiteral("office2john"));
}

QTEST_GUILESS_MAIN(TestExtractorRegistry)
#include "test_extractorregistry.moc"
