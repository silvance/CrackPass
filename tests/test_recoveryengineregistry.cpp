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

QTEST_GUILESS_MAIN(TestRecoveryEngineRegistry)
#include "test_recoveryengineregistry.moc"
