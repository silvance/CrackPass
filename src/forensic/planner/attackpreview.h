/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#ifndef FORENSIC_ATTACKPREVIEW_H
#define FORENSIC_ATTACKPREVIEW_H

#include <QString>
#include <QStringList>

namespace forensic {

/*
 * Everything the examiner must see BEFORE running an attack. Populated by the
 * planner; nothing is executed to produce it.
 */
struct AttackPreview
{
    QString templateName;

    QString hashTypeName;
    quint32 hashMode = 0;

    QString attackModeName;
    int attackMode = 0;

    QStringList wordlists;
    QStringList rules;
    QString mask;

    qint64 estimatedKeyspace = -1;   // -1 = unknown/not applicable
    QStringList devices;

    QStringList command;             // full generated hashcat command line
};

} // namespace forensic

#endif // FORENSIC_ATTACKPREVIEW_H
