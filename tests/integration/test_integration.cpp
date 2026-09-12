/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 *
 * OPTIONAL real-tool integration test. It exercises the actual hashcat and
 * *2john binaries against a known corpus. It SKIPS cleanly when those tools or
 * the corpus are absent, so it never breaks normal unit-test builds.
 */
#include "integrationchain.h"
#include "integrationenv.h"

#include <QTemporaryDir>
#include <QtTest>

using namespace forensic::itest;

class TestIntegration : public QObject
{
    Q_OBJECT
private:
    IntegrationEnv m_env;
    QVector<FixtureSpec> m_corpus;

private slots:
    void initTestCase();
    void fullChain_data();
    void fullChain();
};

void TestIntegration::initTestCase()
{
    m_env = IntegrationEnv::detect();
    if (!m_env.hashcatAvailable())
        QSKIP("hashcat not available (set CRACKPASS_HASHCAT) - integration test skipped");
    if (!m_env.corpusAvailable())
        QSKIP("corpus not available (set CRACKPASS_CORPUS) - integration test skipped");
    m_corpus = loadCorpus(m_env.corpusDir);
    if (m_corpus.isEmpty())
        QSKIP("corpus manifest empty - integration test skipped");
}

void TestIntegration::fullChain_data()
{
    QTest::addColumn<int>("index");
    for (int i = 0; i < m_corpus.size(); ++i) {
        const FixtureSpec &fx = m_corpus.at(i);
        const QString tool = extractorForType(fx.expectedType);
        // Only rows we can actually run: encrypted fixtures need their extractor.
        if (fx.encrypted && !m_env.extractors.value(tool).available)
            continue;
        QTest::newRow(qPrintable(QFileInfo(fx.path).fileName())) << i;
    }
}

void TestIntegration::fullChain()
{
    QFETCH(int, index);
    const FixtureSpec fx = m_corpus.at(index);
    if (!QFileInfo::exists(fx.path))
        QSKIP("fixture file missing");

    QTemporaryDir caseParent;
    const ChainResult r = runChain(m_env, caseParent.path(), fx, extractorForType(fx.expectedType));
    // On failure the message names the exact stage that broke.
    QVERIFY2(r.ok, qPrintable(QStringLiteral("[stage=%1] %2").arg(r.stage, r.message)));
    if (fx.encrypted) {
        QCOMPARE(r.recovered, fx.expectedPassword);
        QCOMPARE(r.sha256After, r.sha256Before); // evidence unchanged
    }
}

QTEST_GUILESS_MAIN(TestIntegration)
#include "test_integration.moc"
