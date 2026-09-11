/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#ifndef FORENSIC_RECOVEREDCREDENTIAL_H
#define FORENSIC_RECOVEREDCREDENTIAL_H

#include <QDateTime>
#include <QJsonObject>
#include <QString>
#include <QUuid>

namespace forensic {

/*
 * A recovered password, kept explicitly associated with the job that found it,
 * the source artifact it belongs to, and the case. (Plaintext is sensitive;
 * it lives only inside the examiner-controlled case workspace.)
 */
struct RecoveredCredential
{
    QUuid id;
    QString caseId;
    QUuid jobId;
    QUuid evidenceId;

    QString hash;       // the cracked hash line
    QString plaintext;  // the recovered password
    QDateTime recoveredUtc;

    QJsonObject toJson() const;
    static RecoveredCredential fromJson(const QJsonObject &obj);
};

} // namespace forensic

#endif // FORENSIC_RECOVEREDCREDENTIAL_H
