/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#ifndef FORENSIC_ATTACKPLANNER_H
#define FORENSIC_ATTACKPLANNER_H

#include "attackjobspec.h"
#include "attackpreview.h"
#include "attacktemplate.h"
#include "caseknowledge.h"
#include <QString>
#include <QStringList>

namespace forensic {

// Fixed inputs the planner needs that are not case knowledge.
struct PlannerContext
{
    quint32 hashMode = 0;
    QString hashTypeName;
    QString hashFile;         // extracted-hash file to attack
    QString planDir;          // where generated wordlists/rules are written
    QString commonWordlist;   // optional path to a bundled common-passwords list
    QStringList devices;      // human-readable selected devices (may be empty)
    QStringList customArgs;   // used by the Custom/Advanced template
};

// Outcome of planning one template.
struct PlanResult
{
    bool ok = false;
    QString error;
    AttackJobSpec spec;
    AttackPreview preview;
    QStringList generatedFiles; // files materialized from case knowledge
};

/*
 * Turns an examiner-friendly template + case knowledge into a concrete,
 * inspectable AttackJobSpec and a full preview. It materializes case knowledge
 * into explicit wordlist/rule/mask artifacts. It never launches an attack.
 */
class AttackPlanner
{
public:
    PlanResult plan(AttackTemplate templ, const CaseKnowledge &knowledge,
                    const PlannerContext &ctx) const;

private:
    AttackPreview buildPreview(AttackTemplate templ, const AttackJobSpec &spec,
                               const PlannerContext &ctx) const;
};

} // namespace forensic

#endif // FORENSIC_ATTACKPLANNER_H
