/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "forensic/planner/attackcommandbuilder.h"

#include <QtTest>

using namespace forensic;

class TestAttackCommandBuilder : public QObject
{
    Q_OBJECT

private slots:
    void straightWithRules();
    void maskWithCustomCharsetAndIncrement();
    void hybridWordlistThenMask();
    void hybridMaskThenWord();
    void customExtraArgsAppended();
};

void TestAttackCommandBuilder::straightWithRules()
{
    AttackJobSpec s;
    s.hashMode = 13400;
    s.attackMode = 0;
    s.hashFile = "hash.txt";
    s.wordlists = {"rockyou.txt"};
    s.rules = {"best64.rule"};
    QCOMPARE(AttackCommandBuilder::buildArgs(s),
             (QStringList{"-m","13400","-a","0","-r","best64.rule","hash.txt","rockyou.txt"}));
}

void TestAttackCommandBuilder::maskWithCustomCharsetAndIncrement()
{
    AttackJobSpec s;
    s.hashMode = 9600;
    s.attackMode = 3;
    s.hashFile = "h.txt";
    s.mask = "?1?1?1?1";
    s.customCharset1 = "?l?d";
    s.increment = true;
    s.incrementMin = 4;
    s.incrementMax = 8;
    QCOMPARE(AttackCommandBuilder::buildArgs(s),
             (QStringList{"-m","9600","-a","3","-1","?l?d",
                          "--increment","--increment-min","4","--increment-max","8",
                          "h.txt","?1?1?1?1"}));
}

void TestAttackCommandBuilder::hybridWordlistThenMask()
{
    AttackJobSpec s;
    s.hashMode = 10500; s.attackMode = 6; s.hashFile = "h";
    s.wordlists = {"words.txt"}; s.mask = "?d?d?d?d";
    QCOMPARE(AttackCommandBuilder::buildArgs(s),
             (QStringList{"-m","10500","-a","6","h","words.txt","?d?d?d?d"}));
}

void TestAttackCommandBuilder::hybridMaskThenWord()
{
    AttackJobSpec s;
    s.hashMode = 10500; s.attackMode = 7; s.hashFile = "h";
    s.wordlists = {"words.txt"}; s.mask = "?d?d";
    QCOMPARE(AttackCommandBuilder::buildArgs(s),
             (QStringList{"-m","10500","-a","7","h","?d?d","words.txt"}));
}

void TestAttackCommandBuilder::customExtraArgsAppended()
{
    AttackJobSpec s;
    s.hashMode = 0; s.attackMode = 0; s.hashFile = "h";
    s.wordlists = {"w"};
    s.extraArgs = {"--loopback", "-w", "3"};
    const QStringList args = AttackCommandBuilder::buildArgs(s);
    QCOMPARE(args.mid(args.size() - 3), (QStringList{"--loopback", "-w", "3"}));
}

QTEST_GUILESS_MAIN(TestAttackCommandBuilder)
#include "test_attackcommandbuilder.moc"
