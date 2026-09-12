/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef FORENSIC_CASEINFO_H
#define FORENSIC_CASEINFO_H

#include <QDateTime>
#include <QJsonObject>
#include <QString>

namespace forensic {

// Identifying metadata for a case (persisted as case.json).
struct CaseInfo
{
    QString id;             // uuid string
    QString name;
    QString examiner;
    QDateTime createdUtc;
    QString notes;
    int schemaVersion = 1;

    QJsonObject toJson() const;
    static CaseInfo fromJson(const QJsonObject &obj);
};

} // namespace forensic

#endif // FORENSIC_CASEINFO_H
