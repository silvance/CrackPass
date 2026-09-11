/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#include "forensic/extractorregistry.h"

#include <QtTest>

using forensic::ArtifactType;
using forensic::ExtractionStatus;
using forensic::ExtractorRegistry;

class TestExtractorRegistry : public QObject
{
    Q_OBJECT

private slots:
    void resolvesKnownType();
    void noExtractorForUnknown();
    void noExtractorForUnsupportedType();
    void extractIsNotImplementedYet();
};

void TestExtractorRegistry::resolvesKnownType()
{
    auto reg = ExtractorRegistry::withBuiltins();
    const ArtifactType pdf{QStringLiteral("pdf"), QStringLiteral("PDF"), 0.95};
    QVERIFY(reg.hasExtractorFor(pdf));
    auto *ex = reg.extractorFor(pdf);
    QVERIFY(ex != nullptr);
    QCOMPARE(ex->defaultHashMode(), 10500u);
}

void TestExtractorRegistry::noExtractorForUnknown()
{
    auto reg = ExtractorRegistry::withBuiltins();
    QVERIFY(!reg.hasExtractorFor(ArtifactType::unknown()));
    QCOMPARE(reg.extractorFor(ArtifactType::unknown()), nullptr);
}

void TestExtractorRegistry::noExtractorForUnsupportedType()
{
    auto reg = ExtractorRegistry::withBuiltins();
    const ArtifactType zip{QStringLiteral("zip"), QStringLiteral("ZIP"), 0.6};
    QVERIFY(!reg.hasExtractorFor(zip));
}

void TestExtractorRegistry::extractIsNotImplementedYet()
{
    auto reg = ExtractorRegistry::withBuiltins();
    const ArtifactType pdf{QStringLiteral("pdf"), QStringLiteral("PDF"), 0.95};
    forensic::EvidenceItem dummy;
    const auto result = reg.extractorFor(pdf)->extract(dummy);
    QCOMPARE(result.status, ExtractionStatus::NotImplemented);
}

QTEST_GUILESS_MAIN(TestExtractorRegistry)
#include "test_extractorregistry.moc"
