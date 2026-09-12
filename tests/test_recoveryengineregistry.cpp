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

QTEST_GUILESS_MAIN(TestRecoveryEngineRegistry)
#include "test_recoveryengineregistry.moc"
