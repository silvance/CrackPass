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

// What kind of secret a recovery produced. Not every engine recovers a
// password: bkcrack recovers the ZipCrypto internal key triple, and other
// engines may recover encryption or recovery keys. The kind drives how the
// value is labelled and copied in the UI and described in reports.
enum class ResultKind {
    Password,      // a recovered password / passphrase
    EncryptionKey, // a data-encryption key
    InternalKey,   // an internal cipher key (e.g. bkcrack's ZipCrypto X/Y/Z)
    RecoveryKey,   // a recovery/escrow key
    Other,
};

QString resultKindToString(ResultKind kind);
ResultKind resultKindFromString(const QString &s);
// A human-readable noun for the value ("password", "key material", ...).
QString resultKindNoun(ResultKind kind);
// The default result kind for an engine's output (bkcrack -> InternalKey,
// everything else -> Password). Central so the queue does not hardcode it.
ResultKind resultKindForEngine(const QString &engineId);

/*
 * A recovered secret, kept explicitly associated with the job that found it,
 * the source artifact it belongs to, and the case. (The value is sensitive; it
 * lives only inside the examiner-controlled case workspace.)
 *
 * Despite the historical name, this represents any recovery result -- a
 * password OR key material -- distinguished by `kind`. Existing records load as
 * kind = Password.
 */
struct RecoveredCredential
{
    QUuid id;
    QString caseId;
    QUuid jobId;
    QUuid evidenceId;

    QString engineId;         // engine that produced this result (provenance)
    ResultKind kind = ResultKind::Password;

    QString hash;       // the target: the cracked hash line, or a bkcrack target label

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
