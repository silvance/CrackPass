/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "forensic/recovery/recoveryengineregistry.h"
#include "forensic/planner/attackjobspec.h"

#include <QtTest>

using namespace forensic;

// A trivial extra engine to prove registration/lookup and buildArgs dispatch.
class FakeEngine : public RecoveryEngine
{
public:
    QString id() const override { return QStringLiteral("fake"); }
    QString displayName() const override { return QStringLiteral("Fake Engine"); }
    QStringList buildArgs(const AttackJobSpec &) const override { return {QStringLiteral("--fake")}; }
};

class TestRecoveryEngineRegistry : public QObject
{
    Q_OBJECT
private slots:
    void builtinsHaveHashcatAsDefault();
    void findReturnsNullForUnknown();
    void registerAndBuildArgsDispatch();
    void johnIsBuiltInAndReportsUnsupported();
    void hashcatSupportsEverythingByDefault();
    void selectForSpecPrefersHashcat();
    void selectForSpecFallsBackWhenHashcatAbsent();
    void selectForSpecReturnsNullWhenNoEngineExpresses();
};

void TestRecoveryEngineRegistry::builtinsHaveHashcatAsDefault()
{
    const RecoveryEngineRegistry reg = RecoveryEngineRegistry::withBuiltins();
    QCOMPARE(RecoveryEngineRegistry::defaultEngineId(), QStringLiteral("hashcat"));
    const RecoveryEngine *hc = reg.find(QStringLiteral("hashcat"));
    QVERIFY(hc != nullptr);
    QCOMPARE(hc->id(), QStringLiteral("hashcat"));

    AttackJobSpec spec;
    spec.hashMode = 13400;
    spec.attackMode = AttackModeNum::Straight;
    spec.hashFile = QStringLiteral("h.txt");
    spec.wordlists = {QStringLiteral("wl.txt")};
    QVERIFY(!hc->buildArgs(spec).isEmpty()); // hashcat argv comes from the command builder
}

void TestRecoveryEngineRegistry::findReturnsNullForUnknown()
{
    const RecoveryEngineRegistry reg = RecoveryEngineRegistry::withBuiltins();
    QVERIFY(reg.find(QStringLiteral("nope")) == nullptr);
}

void TestRecoveryEngineRegistry::registerAndBuildArgsDispatch()
{
    RecoveryEngineRegistry reg = RecoveryEngineRegistry::withBuiltins();
    reg.registerEngine(std::make_shared<FakeEngine>());
    const RecoveryEngine *fake = reg.find(QStringLiteral("fake"));
    QVERIFY(fake != nullptr);
    QCOMPARE(fake->buildArgs(AttackJobSpec{}), (QStringList{QStringLiteral("--fake")}));
    QVERIFY(reg.engines().size() >= 2); // hashcat + fake
}

void TestRecoveryEngineRegistry::johnIsBuiltInAndReportsUnsupported()
{
    const RecoveryEngineRegistry reg = RecoveryEngineRegistry::withBuiltins();
    const RecoveryEngine *john = reg.find(QStringLiteral("john"));
    QVERIFY(john != nullptr);
    QCOMPARE(john->id(), QStringLiteral("john"));

    // A clean wordlist attack is expressible.
    AttackJobSpec ok;
    ok.attackMode = AttackModeNum::Straight;
    ok.hashFile = QStringLiteral("h.txt");
    ok.wordlists = {QStringLiteral("wl.txt")};
    QVERIFY(john->unsupportedReason(ok).isEmpty());
    QVERIFY(!john->buildArgs(ok).isEmpty());

    // A rule-file attack is not: John refuses it with a reason.
    AttackJobSpec ruled = ok;
    ruled.rules = {QStringLiteral("best64.rule")};
    QVERIFY(!john->unsupportedReason(ruled).isEmpty());
}

void TestRecoveryEngineRegistry::hashcatSupportsEverythingByDefault()
{
    const RecoveryEngineRegistry reg = RecoveryEngineRegistry::withBuiltins();
    const RecoveryEngine *hc = reg.find(QStringLiteral("hashcat"));
    QVERIFY(hc != nullptr);
    // hashcat expresses everything the planner produces (default seam behaviour).
    AttackJobSpec ruled;
    ruled.attackMode = AttackModeNum::Straight;
    ruled.hashFile = QStringLiteral("h.txt");
    ruled.wordlists = {QStringLiteral("wl.txt")};
    ruled.rules = {QStringLiteral("best64.rule")};
    QVERIFY(hc->unsupportedReason(ruled).isEmpty());
}

void TestRecoveryEngineRegistry::selectForSpecPrefersHashcat()
{
    const RecoveryEngineRegistry reg = RecoveryEngineRegistry::withBuiltins();
    // A rule attack: only hashcat can express it, and it is preferred anyway.
    AttackJobSpec ruled;
    ruled.attackMode = AttackModeNum::Straight;
    ruled.hashFile = QStringLiteral("h.txt");
    ruled.wordlists = {QStringLiteral("wl.txt")};
    ruled.rules = {QStringLiteral("best64.rule")};
    const RecoveryEngine *chosen = reg.selectForSpec(ruled);
    QVERIFY(chosen != nullptr);
    QCOMPARE(chosen->id(), QStringLiteral("hashcat"));

    // A plain wordlist attack both engines express -> hashcat still wins.
    AttackJobSpec plain;
    plain.attackMode = AttackModeNum::Straight;
    plain.hashFile = QStringLiteral("h.txt");
    plain.wordlists = {QStringLiteral("wl.txt")};
    QCOMPARE(reg.selectForSpec(plain)->id(), QStringLiteral("hashcat"));
}

void TestRecoveryEngineRegistry::selectForSpecFallsBackWhenHashcatAbsent()
{
    // A registry with only John: a spec John can express selects John.
    RecoveryEngineRegistry reg;
    reg.registerEngine(std::make_shared<FakeEngine>()); // expresses everything
    AttackJobSpec plain;
    plain.attackMode = AttackModeNum::Straight;
    plain.hashFile = QStringLiteral("h.txt");
    plain.wordlists = {QStringLiteral("wl.txt")};
    const RecoveryEngine *chosen = reg.selectForSpec(plain);
    QVERIFY(chosen != nullptr);
    QCOMPARE(chosen->id(), QStringLiteral("fake"));
}

void TestRecoveryEngineRegistry::selectForSpecReturnsNullWhenNoEngineExpresses()
{
    // A registry with only an always-refusing engine (no hashcat): selection
    // returns nullptr and reports that engine's reason.
    struct RefusingEngine : RecoveryEngine {
        QString id() const override { return QStringLiteral("refuse"); }
        QString displayName() const override { return QStringLiteral("Refusing"); }
        QStringList buildArgs(const AttackJobSpec &) const override { return {}; }
        QString unsupportedReason(const AttackJobSpec &) const override
        {
            return QStringLiteral("cannot express this attack");
        }
    };
    RecoveryEngineRegistry only;
    only.registerEngine(std::make_shared<RefusingEngine>());
    QString reason;
    QVERIFY(only.selectForSpec(AttackJobSpec{}, &reason) == nullptr);
    QCOMPARE(reason, QStringLiteral("cannot express this attack"));
}

QTEST_GUILESS_MAIN(TestRecoveryEngineRegistry)
#include "test_recoveryengineregistry.moc"
