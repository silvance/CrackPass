/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "forensic/planner/johncommandbuilder.h"
#include "forensic/planner/attackjobspec.h"

#include <QtTest>

using namespace forensic;

class TestJohnCommandBuilder : public QObject
{
    Q_OBJECT
private slots:
    void wordlistAttack();
    void wordlistRefusesZeroOrMany();
    void maskAttack();
    void maskWithIncrementMapsToLengthBounds();
    void bareIncrementalAttack();
    void bruteForceWithoutMaskOrIncrementRefused();
    void ruleFilesRefused();
    void customCharsetsRefused();
    void extraArgsRefused();
    void combinationRefused();
    void hybridRefused();
    void hashFileIsTrailingPositional();
};

static AttackJobSpec base(int attackMode)
{
    AttackJobSpec spec;
    spec.hashMode = 9600;
    spec.attackMode = attackMode;
    spec.hashFile = QStringLiteral("hash.txt");
    return spec;
}

void TestJohnCommandBuilder::wordlistAttack()
{
    AttackJobSpec spec = base(AttackModeNum::Straight);
    spec.wordlists = {QStringLiteral("/wl/rockyou.txt")};
    const JohnBuildResult r = JohnCommandBuilder::build(spec);
    QVERIFY(r.supported);
    QVERIFY(r.error.isEmpty());
    QCOMPARE(r.args, (QStringList{QStringLiteral("--wordlist=/wl/rockyou.txt"),
                                  QStringLiteral("hash.txt")}));
}

void TestJohnCommandBuilder::wordlistRefusesZeroOrMany()
{
    AttackJobSpec none = base(AttackModeNum::Straight); // no wordlist
    QVERIFY(!JohnCommandBuilder::build(none).supported);

    AttackJobSpec many = base(AttackModeNum::Straight);
    many.wordlists = {QStringLiteral("a.txt"), QStringLiteral("b.txt")};
    const JohnBuildResult r = JohnCommandBuilder::build(many);
    QVERIFY(!r.supported);
    QVERIFY(r.args.isEmpty());
    QVERIFY(!r.error.isEmpty());
}

void TestJohnCommandBuilder::maskAttack()
{
    AttackJobSpec spec = base(AttackModeNum::BruteForceMask);
    spec.mask = QStringLiteral("?u?l?l?l?d?d");
    const JohnBuildResult r = JohnCommandBuilder::build(spec);
    QVERIFY(r.supported);
    QCOMPARE(r.args, (QStringList{QStringLiteral("--mask=?u?l?l?l?d?d"),
                                  QStringLiteral("hash.txt")}));
}

void TestJohnCommandBuilder::maskWithIncrementMapsToLengthBounds()
{
    AttackJobSpec spec = base(AttackModeNum::BruteForceMask);
    spec.mask = QStringLiteral("?a?a?a?a?a?a?a?a");
    spec.increment = true;
    spec.incrementMin = 4;
    spec.incrementMax = 8;
    const JohnBuildResult r = JohnCommandBuilder::build(spec);
    QVERIFY(r.supported);
    QCOMPARE(r.args, (QStringList{QStringLiteral("--mask=?a?a?a?a?a?a?a?a"),
                                  QStringLiteral("--min-length=4"),
                                  QStringLiteral("--max-length=8"),
                                  QStringLiteral("hash.txt")}));
}

void TestJohnCommandBuilder::bareIncrementalAttack()
{
    AttackJobSpec spec = base(AttackModeNum::BruteForceMask);
    spec.increment = true; // no mask -> John incremental mode
    const JohnBuildResult r = JohnCommandBuilder::build(spec);
    QVERIFY(r.supported);
    QCOMPARE(r.args, (QStringList{QStringLiteral("--incremental"),
                                  QStringLiteral("hash.txt")}));
}

void TestJohnCommandBuilder::bruteForceWithoutMaskOrIncrementRefused()
{
    AttackJobSpec spec = base(AttackModeNum::BruteForceMask); // neither mask nor increment
    const JohnBuildResult r = JohnCommandBuilder::build(spec);
    QVERIFY(!r.supported);
    QVERIFY(!r.error.isEmpty());
}

void TestJohnCommandBuilder::ruleFilesRefused()
{
    AttackJobSpec spec = base(AttackModeNum::Straight);
    spec.wordlists = {QStringLiteral("wl.txt")};
    spec.rules = {QStringLiteral("best64.rule")};
    const JohnBuildResult r = JohnCommandBuilder::build(spec);
    QVERIFY(!r.supported);
    QVERIFY(r.error.contains(QStringLiteral("Rule files")));
}

void TestJohnCommandBuilder::customCharsetsRefused()
{
    AttackJobSpec spec = base(AttackModeNum::BruteForceMask);
    spec.mask = QStringLiteral("?1?1?1?1");
    spec.customCharset1 = QStringLiteral("?l?d");
    const JohnBuildResult r = JohnCommandBuilder::build(spec);
    QVERIFY(!r.supported);
    QVERIFY(r.error.contains(QStringLiteral("Custom charsets")));
}

void TestJohnCommandBuilder::extraArgsRefused()
{
    AttackJobSpec spec = base(AttackModeNum::Straight);
    spec.wordlists = {QStringLiteral("wl.txt")};
    spec.extraArgs = {QStringLiteral("--loopback")};
    const JohnBuildResult r = JohnCommandBuilder::build(spec);
    QVERIFY(!r.supported);
    QVERIFY(!r.error.isEmpty());
}

void TestJohnCommandBuilder::combinationRefused()
{
    AttackJobSpec spec = base(AttackModeNum::Combination);
    spec.wordlists = {QStringLiteral("a.txt"), QStringLiteral("b.txt")};
    QVERIFY(!JohnCommandBuilder::build(spec).supported);
}

void TestJohnCommandBuilder::hybridRefused()
{
    AttackJobSpec wm = base(AttackModeNum::HybridWordMask);
    wm.wordlists = {QStringLiteral("wl.txt")};
    wm.mask = QStringLiteral("?d?d");
    QVERIFY(!JohnCommandBuilder::build(wm).supported);

    AttackJobSpec mw = base(AttackModeNum::HybridMaskWord);
    mw.wordlists = {QStringLiteral("wl.txt")};
    mw.mask = QStringLiteral("?d?d");
    QVERIFY(!JohnCommandBuilder::build(mw).supported);
}

void TestJohnCommandBuilder::hashFileIsTrailingPositional()
{
    AttackJobSpec spec = base(AttackModeNum::Straight);
    spec.wordlists = {QStringLiteral("wl.txt")};
    const JohnBuildResult r = JohnCommandBuilder::build(spec);
    QVERIFY(r.supported);
    QCOMPARE(r.args.last(), QStringLiteral("hash.txt")); // hash file trails the options
}

QTEST_GUILESS_MAIN(TestJohnCommandBuilder)
#include "test_johncommandbuilder.moc"
