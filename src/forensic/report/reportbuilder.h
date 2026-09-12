/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef FORENSIC_REPORTBUILDER_H
#define FORENSIC_REPORTBUILDER_H

#include "recoveryreport.h"
#include "forensic/crackingjob.h"
#include <QString>

namespace forensic {

class CaseWorkspace;

/*
 * Assembles a RecoveryReport for one job by gathering the case, the source
 * artifact, its extraction, the hashcat environment/parameters and any
 * recovered credential from the case workspace.
 */
class ReportBuilder
{
public:
    // includePlaintext=false redacts the recovered password in the report
    // (both HTML and JSON), while retaining the fact of recovery.
    static RecoveryReport build(const CaseWorkspace &ws, const CrackingJob &job,
                                const QString &applicationVersion, bool includePlaintext = true);
};

} // namespace forensic

#endif // FORENSIC_REPORTBUILDER_H
