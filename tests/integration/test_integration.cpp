/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 *
 * OPTIONAL real-tool integration test. It exercises the actual hashcat, John
 * the Ripper, bkcrack and *2john binaries against a known corpus. It SKIPS
 * cleanly when those tools or the corpus are absent, so it never breaks normal
 * unit-test builds.
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
    QVector<BkcrackFixtureSpec> m_bkcrackCorpus;

private slots:
    void initTestCase();
    void fullChain_data();
    void fullChain();
    void johnChain_data();
    void johnChain();
    void bkcrackChain_data();
    void bkcrackChain();
};

void TestIntegration::initTestCase()
{
    m_env = IntegrationEnv::detect();
    // The corpus underpins every row here; individual engines are checked per
    // test so an absent John/bkcrack skips only its own rows, not hashcat's.
    if (!m_env.corpusAvailable())
        QSKIP("corpus not available (set CASEKEY_CORPUS) - integration test skipped");
    m_corpus = loadCorpus(m_env.corpusDir);
    m_bkcrackCorpus = loadBkcrackCorpus(m_env.corpusDir);
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
    if (!m_env.hashcatAvailable())
        QSKIP("hashcat not available (set CASEKEY_HASHCAT) - hashcat chain skipped");
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

void TestIntegration::johnChain_data()
{
    QTest::addColumn<int>("index");
    for (int i = 0; i < m_corpus.size(); ++i) {
        const FixtureSpec &fx = m_corpus.at(i);
        // John cracks the extracted hash directly, so it only makes sense for
        // encrypted fixtures whose extractor is present.
        if (!fx.encrypted)
            continue;
        if (!m_env.extractors.value(extractorForType(fx.expectedType)).available)
            continue;
        QTest::newRow(qPrintable(QFileInfo(fx.path).fileName())) << i;
    }
}

void TestIntegration::johnChain()
{
    if (!m_env.johnAvailable())
        QSKIP("john not available (set CASEKEY_JOHN) - John dictionary chain skipped");
    QFETCH(int, index);
    const FixtureSpec fx = m_corpus.at(index);
    if (!QFileInfo::exists(fx.path))
        QSKIP("fixture file missing");

    QTemporaryDir caseParent;
    const ChainResult r = runChain(m_env, caseParent.path(), fx,
                                   extractorForType(fx.expectedType),
                                   QStringLiteral("john"));
    QVERIFY2(r.ok, qPrintable(QStringLiteral("[stage=%1] %2").arg(r.stage, r.message)));
    QCOMPARE(r.recovered, fx.expectedPassword);
    QCOMPARE(r.sha256After, r.sha256Before); // evidence unchanged
}

void TestIntegration::bkcrackChain_data()
{
    QTest::addColumn<int>("index");
    for (int i = 0; i < m_bkcrackCorpus.size(); ++i)
        QTest::newRow(qPrintable(QFileInfo(m_bkcrackCorpus.at(i).zipPath).fileName())) << i;
}

void TestIntegration::bkcrackChain()
{
    if (m_bkcrackCorpus.isEmpty())
        QSKIP("no bkcrack fixtures in corpus manifest - ZipCrypto chain skipped");
    if (!m_env.bkcrackAvailable())
        QSKIP("bkcrack not available (set CASEKEY_BKCRACK) - ZipCrypto chain skipped");
    QFETCH(int, index);
    const BkcrackFixtureSpec fx = m_bkcrackCorpus.at(index);
    if (!QFileInfo::exists(fx.zipPath) || !QFileInfo::exists(fx.plainFile))
        QSKIP("bkcrack fixture file missing");

    QTemporaryDir caseParent;
    const ChainResult r = runBkcrackChain(m_env, caseParent.path(), fx);
    QVERIFY2(r.ok, qPrintable(QStringLiteral("[stage=%1] %2").arg(r.stage, r.message)));
    QVERIFY2(!r.recovered.isEmpty(), "bkcrack produced no internal key");
    QCOMPARE(r.sha256After, r.sha256Before); // evidence unchanged
}

QTEST_GUILESS_MAIN(TestIntegration)
#include "test_integration.moc"
