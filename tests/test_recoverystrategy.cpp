/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "forensic/recovery/recoverystrategy.h"

#include <QSet>
#include <QtTest>

using namespace forensic;

class TestRecoveryStrategy : public QObject
{
    Q_OBJECT
private slots:
    void dictionaryIsFirstAndRecommended();
    void defaultRequiresNoCaseKnowledge();
    void inputFlagsAreConsistent();
    void idsAreStableAndUnique();
};

void TestRecoveryStrategy::dictionaryIsFirstAndRecommended()
{
    const QList<StrategyInfo> all = recoveryStrategies();
    QVERIFY(all.size() >= 3);
    QCOMPARE(all.first().strategy, RecoveryStrategy::Dictionary);
    QVERIFY(all.first().recommended);
    QVERIFY(all.first().usesDictionary);
    QVERIFY(!all.first().requiresCaseKnowledge);
}

void TestRecoveryStrategy::defaultRequiresNoCaseKnowledge()
{
    // The default the primary workflow picks must be usable with nothing known
    // about the case.
    const RecoveryStrategy def = defaultRecoveryStrategy();
    QCOMPARE(def, RecoveryStrategy::Dictionary);
    QVERIFY(!strategyInfo(def).requiresCaseKnowledge);
}

void TestRecoveryStrategy::inputFlagsAreConsistent()
{
    // Mask uses a mask field and no dictionary; Guided uses neither inline input
    // (it opens the advanced planner) and is the only one needing case knowledge.
    const StrategyInfo mask = strategyInfo(RecoveryStrategy::Mask);
    QVERIFY(mask.usesMask);
    QVERIFY(!mask.usesDictionary);
    QVERIFY(!mask.requiresCaseKnowledge);

    const StrategyInfo guided = strategyInfo(RecoveryStrategy::GuidedAdvanced);
    QVERIFY(guided.requiresCaseKnowledge);
    QVERIFY(!guided.usesDictionary);
    QVERIFY(!guided.usesMask);
}

void TestRecoveryStrategy::idsAreStableAndUnique()
{
    QSet<QString> ids;
    for (const StrategyInfo &s : recoveryStrategies()) {
        QVERIFY(!s.id.isEmpty());
        QVERIFY(!ids.contains(s.id));
        ids.insert(s.id);
        QCOMPARE(recoveryStrategyId(s.strategy), s.id);
    }
    QCOMPARE(strategyInfo(RecoveryStrategy::Dictionary).id, QStringLiteral("dictionary"));
}

QTEST_GUILESS_MAIN(TestRecoveryStrategy)
#include "test_recoverystrategy.moc"
