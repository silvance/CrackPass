/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "recoveredcredential.h"
#include "jsonutil.h"

namespace forensic {

QString resultKindToString(ResultKind kind)
{
    switch (kind) {
    case ResultKind::Password:      return QStringLiteral("password");
    case ResultKind::EncryptionKey: return QStringLiteral("encryption-key");
    case ResultKind::InternalKey:   return QStringLiteral("internal-key");
    case ResultKind::RecoveryKey:   return QStringLiteral("recovery-key");
    case ResultKind::Other:         return QStringLiteral("other");
    }
    return QStringLiteral("password");
}

ResultKind resultKindFromString(const QString &s)
{
    if (s == QStringLiteral("encryption-key")) return ResultKind::EncryptionKey;
    if (s == QStringLiteral("internal-key"))   return ResultKind::InternalKey;
    if (s == QStringLiteral("recovery-key"))   return ResultKind::RecoveryKey;
    if (s == QStringLiteral("other"))          return ResultKind::Other;
    return ResultKind::Password; // default / legacy
}

QString resultKindNoun(ResultKind kind)
{
    switch (kind) {
    case ResultKind::Password:      return QStringLiteral("password");
    case ResultKind::EncryptionKey: return QStringLiteral("encryption key");
    case ResultKind::InternalKey:   return QStringLiteral("key material");
    case ResultKind::RecoveryKey:   return QStringLiteral("recovery key");
    case ResultKind::Other:         return QStringLiteral("secret");
    }
    return QStringLiteral("password");
}

ResultKind resultKindForEngine(const QString &engineId)
{
    // bkcrack recovers the ZipCrypto internal key triple, not a password.
    if (engineId == QStringLiteral("bkcrack"))
        return ResultKind::InternalKey;
    return ResultKind::Password;
}

QJsonObject RecoveredCredential::toJson() const
{
    QJsonObject obj;
    obj[QStringLiteral("id")] = id.toString(QUuid::WithoutBraces);
    obj[QStringLiteral("caseId")] = caseId;
    obj[QStringLiteral("jobId")] = jobId.toString(QUuid::WithoutBraces);
    obj[QStringLiteral("evidenceId")] = evidenceId.toString(QUuid::WithoutBraces);
    obj[QStringLiteral("engineId")] = engineId;
    obj[QStringLiteral("kind")] = resultKindToString(kind);
    obj[QStringLiteral("hash")] = hash;
    obj[QStringLiteral("plaintext")] = plaintext;
    // Store the exact recovered bytes as hex so no fidelity is lost through JSON
    // (which cannot represent arbitrary bytes as a string).
    if (!rawPlaintext.isEmpty())
        obj[QStringLiteral("rawHex")] = QString::fromLatin1(rawPlaintext.toHex());
    if (!encoding.isEmpty())
        obj[QStringLiteral("encoding")] = encoding;
    obj[QStringLiteral("recoveredUtc")] = jsonutil::fromDateTime(recoveredUtc);
    return obj;
}

RecoveredCredential RecoveredCredential::fromJson(const QJsonObject &obj)
{
    RecoveredCredential c;
    c.id = QUuid::fromString(obj.value(QStringLiteral("id")).toString());
    c.caseId = obj.value(QStringLiteral("caseId")).toString();
    c.jobId = QUuid::fromString(obj.value(QStringLiteral("jobId")).toString());
    c.evidenceId = QUuid::fromString(obj.value(QStringLiteral("evidenceId")).toString());
    c.engineId = obj.value(QStringLiteral("engineId")).toString();
    // Records written before result kinds existed are recovered passwords.
    c.kind = obj.contains(QStringLiteral("kind"))
        ? resultKindFromString(obj.value(QStringLiteral("kind")).toString())
        : ResultKind::Password;
    c.hash = obj.value(QStringLiteral("hash")).toString();
    c.plaintext = obj.value(QStringLiteral("plaintext")).toString();
    if (obj.contains(QStringLiteral("rawHex")))
        c.rawPlaintext = QByteArray::fromHex(obj.value(QStringLiteral("rawHex")).toString().toLatin1());
    else
        c.rawPlaintext = c.plaintext.toUtf8(); // legacy records: display was the password
    c.encoding = obj.value(QStringLiteral("encoding")).toString();
    if (c.encoding.isEmpty())
        c.encoding = QStringLiteral("utf-8");
    c.recoveredUtc = jsonutil::toDateTime(obj.value(QStringLiteral("recoveredUtc")).toString());
    return c;
}

} // namespace forensic
