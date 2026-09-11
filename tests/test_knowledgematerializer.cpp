/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#include "forensic/planner/knowledgematerializer.h"

#include <QTemporaryDir>
#include <QtTest>

using namespace forensic;

class TestKnowledgeMaterializer : public QObject
{
    Q_OBJECT

private slots:
    void seedWordsDedupAndEmail();
    void maskFromPrefixSuffixAndClasses();
    void maskNeedsStructure();
    void maskKnownPositions();
    void rulesContainYearsAndCasing();
    void maskKeyspaceMath();
    void keyspaceForStraightAndHybrid();
};

void TestKnowledgeMaterializer::seedWordsDedupAndEmail()
{
    CaseKnowledge k;
    k.baseWords = {"summer", "Summer"};       // case-sensitive distinct
    k.names = {"summer"};                      // duplicate of baseWords[0]
    k.emails = {"jdoe@example.com"};
    const QStringList w = KnowledgeMaterializer::seedWords(k);
    QVERIFY(w.contains("summer"));
    QVERIFY(w.contains("Summer"));
    QVERIFY(w.contains("jdoe"));               // email local-part mined
    QCOMPARE(w.count("summer"), 1);            // de-duplicated
}

void TestKnowledgeMaterializer::maskFromPrefixSuffixAndClasses()
{
    CaseKnowledge k;
    k.knownPrefix = "Ab";
    k.knownSuffix = "!";
    k.maxLength = 6;                            // Ab + 3 unknown + !
    k.requiredClasses = CharClass::Lower;
    const MaskResult m = KnowledgeMaterializer::buildMask(k);
    QVERIFY2(m.ok, qPrintable(m.reason));
    QCOMPARE(m.mask, QStringLiteral("Ab?l?l?l!"));
}

void TestKnowledgeMaterializer::maskNeedsStructure()
{
    CaseKnowledge k; // nothing set
    const MaskResult m = KnowledgeMaterializer::buildMask(k);
    QVERIFY(!m.ok);
    QVERIFY(!m.reason.isEmpty());
}

void TestKnowledgeMaterializer::maskKnownPositions()
{
    CaseKnowledge k;
    k.maxLength = 4;
    k.knownPositions.insert(0, QChar('P'));
    k.requiredClasses = CharClass::Digit;
    const MaskResult m = KnowledgeMaterializer::buildMask(k);
    QVERIFY(m.ok);
    QCOMPARE(m.mask, QStringLiteral("P?d?d?d"));
}

void TestKnowledgeMaterializer::rulesContainYearsAndCasing()
{
    CaseKnowledge k;
    k.yearFrom = 2020; k.yearTo = 2021;
    const QStringList rules = KnowledgeMaterializer::generateRules(k);
    QVERIFY(rules.contains(":"));
    QVERIFY(rules.contains("c"));
    QVERIFY(rules.contains("$2$0$2$0")); // 2020 appended
    QVERIFY(rules.contains("$2$0$2$1")); // 2021 appended
}

void TestKnowledgeMaterializer::maskKeyspaceMath()
{
    QCOMPARE(KnowledgeMaterializer::maskKeyspace("?l?l?l"), qint64(26 * 26 * 26));
    QCOMPARE(KnowledgeMaterializer::maskKeyspace("A?d"), qint64(10)); // literal + digit
    QCOMPARE(KnowledgeMaterializer::maskKeyspace("?1?1", "?l?d"), qint64(36 * 36));
    QCOMPARE(KnowledgeMaterializer::maskKeyspace("????"), qint64(1)); // literal '?' x2
}

void TestKnowledgeMaterializer::keyspaceForStraightAndHybrid()
{
    QTemporaryDir dir;
    // 3-line wordlist.
    CaseKnowledge k; k.baseWords = {"a", "b", "c"};
    const QString wl = dir.filePath("wl.txt");
    QVERIFY(KnowledgeMaterializer::writeWordlist(k, wl));

    AttackJobSpec straight; straight.attackMode = 0; straight.wordlists = {wl};
    QCOMPARE(KnowledgeMaterializer::estimateKeyspace(straight), qint64(3));

    AttackJobSpec hybrid; hybrid.attackMode = 6; hybrid.wordlists = {wl}; hybrid.mask = "?d?d";
    QCOMPARE(KnowledgeMaterializer::estimateKeyspace(hybrid), qint64(3 * 100));
}

QTEST_GUILESS_MAIN(TestKnowledgeMaterializer)
#include "test_knowledgematerializer.moc"
