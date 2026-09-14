/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "recoverystrategy.h"

namespace forensic {

QList<StrategyInfo> recoveryStrategies()
{
    QList<StrategyInfo> out;

    StrategyInfo dict;
    dict.strategy = RecoveryStrategy::Dictionary;
    dict.id = QStringLiteral("dictionary");
    dict.label = QStringLiteral("Dictionary");
    dict.description = QStringLiteral(
        "Try a list of likely passwords. The simplest starting point and needs "
        "nothing known about the case.");
    dict.recommended = true;
    dict.requiresCaseKnowledge = false;
    dict.usesDictionary = true;
    dict.usesMask = false;
    out << dict;

    StrategyInfo mask;
    mask.strategy = RecoveryStrategy::Mask;
    mask.id = QStringLiteral("mask");
    mask.label = QStringLiteral("Pattern");
    mask.description = QStringLiteral(
        "Try every candidate that matches a character pattern (a mask), for "
        "example six digits or a word followed by a year.");
    mask.recommended = false;
    mask.requiresCaseKnowledge = false;
    mask.usesDictionary = false;
    mask.usesMask = true;
    out << mask;

    StrategyInfo guided;
    guided.strategy = RecoveryStrategy::GuidedAdvanced;
    guided.id = QStringLiteral("guided");
    guided.label = QStringLiteral("Guided / advanced");
    guided.description = QStringLiteral(
        "Use what is known about the subject (names, dates, base words) and the "
        "full set of attack templates. Opens the advanced planner.");
    guided.recommended = false;
    guided.requiresCaseKnowledge = true;
    guided.usesDictionary = false;
    guided.usesMask = false;
    out << guided;

    return out;
}

StrategyInfo strategyInfo(RecoveryStrategy strategy)
{
    for (const StrategyInfo &s : recoveryStrategies())
        if (s.strategy == strategy)
            return s;
    return recoveryStrategies().first();
}

RecoveryStrategy defaultRecoveryStrategy()
{
    // The recommended strategy that requires no case knowledge.
    for (const StrategyInfo &s : recoveryStrategies())
        if (s.recommended && !s.requiresCaseKnowledge)
            return s.strategy;
    return RecoveryStrategy::Dictionary;
}

QString recoveryStrategyId(RecoveryStrategy strategy)
{
    return strategyInfo(strategy).id;
}

} // namespace forensic
