/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#ifndef FORENSIC_ATTACKCOMMANDBUILDER_H
#define FORENSIC_ATTACKCOMMANDBUILDER_H

#include "attackjobspec.h"
#include <QStringList>

namespace forensic {

/*
 * Translates an AttackJobSpec into a hashcat argument vector.
 *
 * The flag semantics intentionally mirror the existing hashcat-gui command
 * generation (HelperUtils::parameterMap) so the Advanced view and the planner
 * agree; kept here (rather than linked from the UI layer) so the planner stays
 * UI-free and unit-testable. Actual execution reuses the existing hashcat
 * process management.
 */
class AttackCommandBuilder
{
public:
    // Argument vector WITHOUT the program name (e.g. {"-m","13400","-a","0",...}).
    static QStringList buildArgs(const AttackJobSpec &spec);

    // Full preview command line including the program name.
    static QStringList buildCommand(const AttackJobSpec &spec,
                                    const QString &program = QStringLiteral("hashcat"));
};

} // namespace forensic

#endif // FORENSIC_ATTACKCOMMANDBUILDER_H
