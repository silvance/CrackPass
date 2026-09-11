/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#include "forensic/planner/attackplanner.h"

#include <QFile>
#include <QTemporaryDir>
#include <QtTest>

using namespace forensic;

class TestAttackPlanner : public QObject
{
    Q_OBJECT

private:
    PlannerContext ctx(QTemporaryDir &dir) const
    {
        PlannerContext c;
        c.hashMode = 13400;
        c.hashTypeName = "KeePass";
        c.hashFile = dir.filePath("hash.txt");
        c.planDir = dir.filePath("plan");
        c.devices = {"#1 NVIDIA RTX 4090"};
        return c;
    }

private slots:
    void caseWordlistMaterializesFile();
    void maskTemplateProducesMaskAttack();
    void commonPasswordsRequiresWordlist();
    void wordlistRulesGeneratesBoth();
    void previewHasAllRequiredFields();
    void customAdvancedPassThrough();
};

void TestAttackPlanner::caseWordlistMaterializesFile()
{
    QTemporaryDir dir;
    CaseKnowledge k; k.baseWords = {"falcon", "raptor"};
    AttackPlanner planner;
    const PlanResult r = planner.plan(AttackTemplate::CaseWordlist, k, ctx(dir));
    QVERIFY2(r.ok, qPrintable(r.error));
    QCOMPARE(r.spec.attackMode, 0);
    QCOMPARE(r.spec.wordlists.size(), 1);
    QVERIFY(QFile::exists(r.spec.wordlists.first()));
    QCOMPARE(r.generatedFiles.size(), 1);
    QCOMPARE(r.preview.estimatedKeyspace, qint64(2)); // two words
}

void TestAttackPlanner::maskTemplateProducesMaskAttack()
{
    QTemporaryDir dir;
    CaseKnowledge k; k.knownPrefix = "Q"; k.maxLength = 5; k.requiredClasses = CharClass::Digit;
    AttackPlanner planner;
    const PlanResult r = planner.plan(AttackTemplate::MaskAttack, k, ctx(dir));
    QVERIFY2(r.ok, qPrintable(r.error));
    QCOMPARE(r.spec.attackMode, 3);
    QCOMPARE(r.spec.mask, QStringLiteral("Q?d?d?d?d"));
    QCOMPARE(r.preview.estimatedKeyspace, qint64(10000));
}

void TestAttackPlanner::commonPasswordsRequiresWordlist()
{
    QTemporaryDir dir;
    AttackPlanner planner;
    PlanResult r = planner.plan(AttackTemplate::CommonPasswords, CaseKnowledge{}, ctx(dir));
    QVERIFY(!r.ok); // no common wordlist configured
    QVERIFY(!r.error.isEmpty());

    PlannerContext c = ctx(dir);
    const QString common = dir.filePath("common.txt");
    QFile f(common); f.open(QIODevice::WriteOnly); f.write("password\n123456\n"); f.close();
    c.commonWordlist = common;
    r = planner.plan(AttackTemplate::CommonPasswords, CaseKnowledge{}, c);
    QVERIFY(r.ok);
    QCOMPARE(r.spec.wordlists, QStringList{common});
}

void TestAttackPlanner::wordlistRulesGeneratesBoth()
{
    QTemporaryDir dir;
    CaseKnowledge k; k.baseWords = {"company"}; k.yearFrom = 2019; k.yearTo = 2020;
    AttackPlanner planner;
    const PlanResult r = planner.plan(AttackTemplate::WordlistRules, k, ctx(dir));
    QVERIFY2(r.ok, qPrintable(r.error));
    QCOMPARE(r.spec.attackMode, 0);
    QVERIFY(!r.spec.rules.isEmpty());
    QVERIFY(QFile::exists(r.spec.rules.first()));
}

void TestAttackPlanner::previewHasAllRequiredFields()
{
    QTemporaryDir dir;
    CaseKnowledge k; k.baseWords = {"alpha"};
    AttackPlanner planner;
    const PlanResult r = planner.plan(AttackTemplate::CaseWordlist, k, ctx(dir));
    QVERIFY(r.ok);
    const AttackPreview &p = r.preview;
    QCOMPARE(p.hashMode, 13400u);
    QCOMPARE(p.hashTypeName, QStringLiteral("KeePass"));
    QCOMPARE(p.attackMode, 0);
    QVERIFY(!p.attackModeName.isEmpty());
    QVERIFY(!p.wordlists.isEmpty());
    QVERIFY(!p.devices.isEmpty());
    QVERIFY(p.command.contains("-m") && p.command.contains("13400"));
    QVERIFY(p.command.first() == QStringLiteral("hashcat"));
}

void TestAttackPlanner::customAdvancedPassThrough()
{
    QTemporaryDir dir;
    PlannerContext c = ctx(dir);
    c.customArgs = {"-a", "3", "?a?a?a"};
    AttackPlanner planner;
    const PlanResult r = planner.plan(AttackTemplate::CustomAdvanced, CaseKnowledge{}, c);
    QVERIFY(r.ok);
    QVERIFY(r.spec.extraArgs.contains("?a?a?a"));
    QVERIFY(r.preview.command.contains("?a?a?a"));
}

QTEST_GUILESS_MAIN(TestAttackPlanner)
#include "test_attackplanner.moc"
