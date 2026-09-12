/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "casetransaction.h"

#include "atomicwrite.h"
#include "auditlog.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>

namespace forensic {

CaseTransaction::CaseTransaction(AuditLog *audit, QString actor)
    : m_audit(audit)
    , m_actor(std::move(actor))
{
}

CaseTransaction &CaseTransaction::write(const QString &path, const QByteArray &data)
{
    m_writes.append(FileWrite{path, data});
    return *this;
}

CaseTransaction &CaseTransaction::audit(const QString &action, const QString &entityType,
                                        const QString &entityId, const QJsonObject &details)
{
    m_hasAudit = true;
    m_action = action;
    m_entityType = entityType;
    m_entityId = entityId;
    m_details = details;
    return *this;
}

bool CaseTransaction::restore(const QVector<Snapshot> &snaps, QString *error) const
{
    // Best-effort: attempt every restore even if one fails, and report the first
    // error. Restoring in reverse of the write order keeps behaviour predictable
    // when the same path was (accidentally) staged twice.
    bool ok = true;
    for (int i = snaps.size() - 1; i >= 0; --i) {
        const Snapshot &s = snaps.at(i);
        if (s.existed) {
            QString werr;
            if (!writeFileAtomic(s.path, s.previous, &werr)) {
                if (ok && error) *error = werr;
                ok = false;
            }
        } else {
            // The file did not exist before the transaction; remove what we wrote.
            if (QFile::exists(s.path) && !QFile::remove(s.path)) {
                if (ok && error) *error = QStringLiteral("Cannot roll back %1").arg(s.path);
                ok = false;
            }
        }
    }
    return ok;
}

bool CaseTransaction::commit(QString *error)
{
    const bool auditStaged = m_hasAudit && m_audit != nullptr;

    // Record the audit file's current length so a failed append (which may leave
    // a partial trailing line on disk) can be rolled back precisely.
    const QString auditPath = auditStaged ? m_audit->filePath() : QString();
    const qint64 auditSizeBefore = (auditStaged && QFile::exists(auditPath))
                                        ? QFileInfo(auditPath).size()
                                        : 0;

    QVector<Snapshot> done; // writes actually performed, for rollback
    done.reserve(m_writes.size());

    for (const FileWrite &w : m_writes) {
        // Ensure the parent directory exists so QSaveFile can create its temp.
        const QString parent = QFileInfo(w.path).absolutePath();
        if (!parent.isEmpty() && !QDir().mkpath(parent)) {
            if (error) *error = QStringLiteral("Cannot create directory for %1").arg(w.path);
            restore(done, nullptr);
            return false;
        }

        Snapshot snap;
        snap.path = w.path;
        snap.existed = QFile::exists(w.path);
        if (snap.existed) {
            QFile f(w.path);
            if (!f.open(QIODevice::ReadOnly)) {
                if (error) *error = QStringLiteral("Cannot snapshot %1 before writing").arg(w.path);
                restore(done, nullptr);
                return false;
            }
            snap.previous = f.readAll();
        }

        QString werr;
        if (!writeFileAtomic(w.path, w.data, &werr)) {
            if (error) *error = werr;
            restore(done, nullptr);
            return false;
        }
        done.append(snap);
    }

    if (auditStaged) {
        if (!m_audit->append(m_actor, m_action, m_entityType, m_entityId, m_details)) {
            const QString aerr = m_audit->lastError();
            // Drop any partial line the failed append may have written, then roll
            // back the state writes so the mutation leaves no trace.
            if (QFile::exists(auditPath)) {
                QFile f(auditPath);
                if (f.open(QIODevice::ReadWrite))
                    f.resize(auditSizeBefore);
            }
            restore(done, nullptr);
            if (error) *error = QStringLiteral("Audit write failed: %1").arg(aerr);
            return false;
        }
    }

    return true;
}

} // namespace forensic
