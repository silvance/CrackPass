/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#ifndef FORENSIC_REPORTRENDERER_H
#define FORENSIC_REPORTRENDERER_H

#include "recoveryreport.h"
#include <QByteArray>
#include <QString>

namespace forensic {

/*
 * Serializes a RecoveryReport to the two supported formats, both fully offline:
 *   - machine-readable JSON
 *   - human-readable, self-contained HTML
 */
class ReportRenderer
{
public:
    static QByteArray toJson(const RecoveryReport &report);
    static QString toHtml(const RecoveryReport &report);
};

} // namespace forensic

#endif // FORENSIC_REPORTRENDERER_H
