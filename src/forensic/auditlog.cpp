/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "auditlog.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QFile>
#include <QJsonDocument>
#include <QTextStream>
#include <QUuid>

namespace forensic {

QJsonObject AuditEvent::payload() const
{
    // Only the semantic fields participate in the hash. QJsonObject serializes
    // keys in a stable (sorted) order, so the compact form is deterministic.
    QJsonObject obj;
    obj[QStringLiteral("id")] = id;
    obj[QStringLiteral("timestampUtc")] = timestampUtc;
    obj[QStringLiteral("actor")] = actor;
    obj[QStringLiteral("action")] = action;
    obj[QStringLiteral("entityType")] = entityType;
    obj[QStringLiteral("entityId")] = entityId;
    obj[QStringLiteral("details")] = details;
    return obj;
}

QJsonObject AuditEvent::toJson() const
{
    QJsonObject obj = payload();
    obj[QStringLiteral("prevHash")] = prevHash;
    obj[QStringLiteral("hash")] = hash;
    return obj;
}

AuditEvent AuditEvent::fromJson(const QJsonObject &obj)
{
    AuditEvent e;
    e.id = obj.value(QStringLiteral("id")).toString();
    e.timestampUtc = obj.value(QStringLiteral("timestampUtc")).toString();
    e.actor = obj.value(QStringLiteral("actor")).toString();
    e.action = obj.value(QStringLiteral("action")).toString();
    e.entityType = obj.value(QStringLiteral("entityType")).toString();
    e.entityId = obj.value(QStringLiteral("entityId")).toString();
    e.details = obj.value(QStringLiteral("details")).toObject();
    e.prevHash = obj.value(QStringLiteral("prevHash")).toString();
    e.hash = obj.value(QStringLiteral("hash")).toString();
    return e;
}

AuditLog::AuditLog(QString filePath)
    : m_filePath(std::move(filePath))
{
}

QString AuditLog::computeHash(const QString &prevHash, const AuditEvent &event)
{
    const QByteArray payload = QJsonDocument(event.payload()).toJson(QJsonDocument::Compact);
    QByteArray data = prevHash.toUtf8();
    data.append('\n');
    data.append(payload);
    return QString::fromLatin1(QCryptographicHash::hash(data, QCryptographicHash::Sha256).toHex());
}

bool AuditLog::load(QString *error)
{
    m_events.clear();
    m_headHash.clear();

    QFile file(m_filePath);
    if (!file.exists())
        return true; // empty log is valid

    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        if (error)
            *error = QStringLiteral("Cannot open audit log '%1': %2").arg(m_filePath, file.errorString());
        return false;
    }

    QTextStream in(&file);
    while (!in.atEnd()) {
        const QString line = in.readLine().trimmed();
        if (line.isEmpty())
            continue;
        QJsonParseError perr;
        const QJsonDocument doc = QJsonDocument::fromJson(line.toUtf8(), &perr);
        if (perr.error != QJsonParseError::NoError || !doc.isObject()) {
            if (error)
                *error = QStringLiteral("Corrupt audit log line: %1").arg(perr.errorString());
            return false;
        }
        AuditEvent e = AuditEvent::fromJson(doc.object());
        m_events.append(e);
        m_headHash = e.hash;
    }

    // A modified/truncated audit log must never open as if it were valid.
    QString verr;
    if (!verify(&verr)) {
        m_lastError = verr;
        if (error) *error = QStringLiteral("Audit log integrity check failed: %1").arg(verr);
        return false;
    }
    return true;
}

bool AuditLog::append(const QString &actor, const QString &action,
                      const QString &entityType, const QString &entityId,
                      const QJsonObject &details)
{
    m_lastError.clear();

    AuditEvent e;
    e.id = QUuid::createUuid().toString(QUuid::WithoutBraces);
    e.timestampUtc = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
    e.actor = actor;
    e.action = action;
    e.entityType = entityType;
    e.entityId = entityId;
    e.details = details;
    e.prevHash = m_headHash;
    e.hash = computeHash(m_headHash, e);

    const QByteArray line = QJsonDocument(e.toJson()).toJson(QJsonDocument::Compact) + '\n';

    QFile file(m_filePath);
    if (!file.open(QIODevice::Append | QIODevice::Text)) {
        m_lastError = QStringLiteral("Cannot open audit log for append: %1").arg(file.errorString());
        return false; // do NOT advance the in-memory chain
    }
    if (file.write(line) != line.size() || !file.flush()) {
        m_lastError = QStringLiteral("Failed to write audit event: %1").arg(file.errorString());
        return false; // do NOT advance the in-memory chain
    }
    file.close();

    // Only now that the event is durably written do we advance the chain.
    m_events.append(e);
    m_headHash = e.hash;
    return true;
}

bool AuditLog::verify(QString *error) const
{
    QString prev;
    for (int i = 0; i < m_events.size(); ++i) {
        const AuditEvent &e = m_events.at(i);
        if (e.prevHash != prev) {
            if (error)
                *error = QStringLiteral("Audit chain broken at event %1: prevHash mismatch.").arg(i);
            return false;
        }
        const QString expected = computeHash(prev, e);
        if (expected != e.hash) {
            if (error)
                *error = QStringLiteral("Audit chain broken at event %1: hash mismatch (tampered).").arg(i);
            return false;
        }
        prev = e.hash;
    }
    return true;
}

} // namespace forensic
