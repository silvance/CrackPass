/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 *
 * A small commit coordinator for the JSON case store. Every forensic mutation
 * is a pair: a change to case state (one or more whole-file writes) AND the
 * audit-log entry that records it. Those two must not drift apart -- persisting
 * state without recording it in the audit trail silently breaks auditability,
 * which is the property the whole tool exists to guarantee.
 *
 * CaseTransaction makes a mutation atomic-or-refuse for the common (non-crash)
 * failure modes: a failed state write or a failed audit append. Staged file
 * writes and the audit entry commit together, or every staged write is rolled
 * back to its prior contents and the audit entry is not left dangling, and the
 * call reports failure so the in-memory model is never advanced.
 *
 * This is NOT a crash-proof journal -- a power loss in the narrow window
 * between the state write and the audit append can still leave them out of
 * step. Closing that window entirely needs a real transactional store (SQLite),
 * which is deliberately deferred. What this buys today is that ordinary
 * runtime failures (disk full, permission denied, a bad path) can never leave
 * committed state with no audit record.
 */
#ifndef FORENSIC_CASETRANSACTION_H
#define FORENSIC_CASETRANSACTION_H

#include <QByteArray>
#include <QJsonObject>
#include <QString>
#include <QVector>

namespace forensic {

class AuditLog;

class CaseTransaction
{
public:
    // `audit` may be null, in which case staged audit entries are ignored and
    // commit() performs the file writes only (still atomic-or-refuse across the
    // staged files). `actor` is the audit actor recorded for a staged entry.
    CaseTransaction(AuditLog *audit, QString actor);

    // Stage an atomic whole-file write, executed in order at commit().
    CaseTransaction &write(const QString &path, const QByteArray &data);

    // Stage the single audit entry appended after the file writes succeed.
    // Calling this more than once replaces the previously staged entry.
    CaseTransaction &audit(const QString &action, const QString &entityType,
                           const QString &entityId, const QJsonObject &details);

    // Perform the staged writes, then (if staged) append the audit entry. On any
    // failure every staged write is rolled back to its prior contents and the
    // audit file is restored to its prior length, so nothing is half-applied.
    // Returns false and sets *error on failure.
    bool commit(QString *error = nullptr);

private:
    struct FileWrite {
        QString path;
        QByteArray data;
    };
    struct Snapshot {
        QString path;
        bool existed = false;
        QByteArray previous; // valid only when existed
    };

    bool restore(const QVector<Snapshot> &snaps, QString *error) const;

    AuditLog *m_audit = nullptr;
    QString m_actor;
    QVector<FileWrite> m_writes;

    bool m_hasAudit = false;
    QString m_action;
    QString m_entityType;
    QString m_entityId;
    QJsonObject m_details;
};

} // namespace forensic

#endif // FORENSIC_CASETRANSACTION_H
