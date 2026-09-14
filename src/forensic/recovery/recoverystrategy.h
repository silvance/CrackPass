/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef FORENSIC_RECOVERYSTRATEGY_H
#define FORENSIC_RECOVERYSTRATEGY_H

#include <QList>
#include <QString>

namespace forensic {

/*
 * The examiner-facing recovery strategies offered by the primary "Recover
 * Password" workflow, in order of increasing effort/knowledge. This is a plain,
 * headless description (label, one-line explanation, and what inputs each needs)
 * so the UI and its tests agree on the choices and on which one is the simplest
 * default. It says nothing about engines, hashcat modes, or argv -- those are
 * chosen automatically downstream.
 */
enum class RecoveryStrategy {
    Dictionary,     // try a wordlist of likely passwords (simplest; no case knowledge)
    Mask,           // try every candidate matching a character pattern
    GuidedAdvanced, // use case knowledge and the full set of attack templates
};

struct StrategyInfo
{
    RecoveryStrategy strategy;
    QString id;          // stable identifier ("dictionary", "mask", "guided")
    QString label;       // short menu label
    QString description; // one-line plain-language explanation

    bool recommended = false;          // the suggested default
    bool requiresCaseKnowledge = false; // does the examiner need to know case facts?
    bool usesDictionary = false;        // shows the dictionary picker
    bool usesMask = false;              // shows the mask field
};

// All strategies in display order (Dictionary first).
QList<StrategyInfo> recoveryStrategies();

// The info for one strategy.
StrategyInfo strategyInfo(RecoveryStrategy strategy);

// The default strategy the workflow selects: the simplest one that requires no
// case knowledge (Dictionary).
RecoveryStrategy defaultRecoveryStrategy();

QString recoveryStrategyId(RecoveryStrategy strategy);

} // namespace forensic

#endif // FORENSIC_RECOVERYSTRATEGY_H
