/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef FORENSIC_RECOVEREDCREDENTIAL_H
#define FORENSIC_RECOVEREDCREDENTIAL_H

#include <QByteArray>
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

    // The recovered password. `rawPlaintext` holds the EXACT bytes (the forensic
    // ground truth, preserved even when they are not valid UTF-8). `plaintext`
    // is a best-effort display form: the decoded text when the bytes are valid
    // UTF-8, otherwise the canonical, reversible $HEX[..] notation. `encoding`
    // ("utf-8" or "raw") records which case applies.
    QString plaintext;
    QByteArray rawPlaintext;
    QString encoding;
    QDateTime recoveredUtc;

    QJsonObject toJson() const;
    static RecoveredCredential fromJson(const QJsonObject &obj);
};

} // namespace forensic

#endif // FORENSIC_RECOVEREDCREDENTIAL_H
