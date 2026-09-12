/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef FORENSIC_AUDITLOG_H
#define FORENSIC_AUDITLOG_H

#include <QJsonObject>
#include <QList>
#include <QString>

namespace forensic {

/*
 * A single structured audit record. Events form a tamper-evident hash chain:
 * each event's `hash` is SHA-256 over (prevHash + canonical payload), so any
 * later modification or deletion is detectable by re-verifying the chain.
 */
struct AuditEvent
{
    QString id;
    QString timestampUtc;   // ISO-8601
    QString actor;          // examiner / component
    QString action;         // e.g. "case_created", "evidence_added"
    QString entityType;     // e.g. "case", "evidence"
    QString entityId;
    QJsonObject details;
    QString prevHash;
    QString hash;

    // Canonical payload used for hashing (excludes prevHash/hash).
    QJsonObject payload() const;
    QJsonObject toJson() const;
    static AuditEvent fromJson(const QJsonObject &obj);
};

/*
 * Append-only audit log persisted as JSON-lines. Not a QObject so it is fully
 * usable and testable outside the UI.
 *
 * The chain hash makes in-place tampering and mid-log deletion detectable, but
 * a chain that has simply had entries dropped from the END stays internally
 * consistent. To detect that, the log keeps a small sidecar "anchor" file next
 * to it recording the expected head hash and event count; load() compares the
 * log against the anchor and fails on any mismatch (tail truncation or whole-log
 * deletion). The anchor defends against accidental truncation and naive
 * tampering -- an adversary who rewrites BOTH files consistently can still
 * shorten history undetectably, which requires an off-box anchor (out of scope).
 */
class AuditLog
{
public:
    explicit AuditLog(QString filePath);

    // Load an existing log (rebuilds the in-memory chain + head hash).
    bool load(QString *error = nullptr);

    // Append a new event; computes its hash, links it to the current head,
    // writes it to disk, and returns the stored event.
    // Appends an event. Returns false WITHOUT advancing the in-memory chain if
    // the event could not be persisted; the error is available via lastError().
    bool append(const QString &actor, const QString &action,
                const QString &entityType, const QString &entityId,
                const QJsonObject &details);

    // Recompute the whole chain and confirm hashes + linkage are intact.
    bool verify(QString *error = nullptr) const;

    QList<AuditEvent> events() const { return m_events; }
    QString headHash() const { return m_headHash; }
    QString lastError() const { return m_lastError; }
    QString filePath() const { return m_filePath; }

    // Exposed so tests and verify() agree on the hashing scheme.
    static QString computeHash(const QString &prevHash, const AuditEvent &event);

    // Sidecar file recording the expected head hash + event count.
    QString anchorPath() const { return m_filePath + QStringLiteral(".anchor"); }

private:
    // Persists the current head hash + event count to the anchor sidecar.
    bool writeAnchor(QString *error) const;

    QString m_filePath;
    QList<AuditEvent> m_events;
    QString m_headHash;
    QString m_lastError;
};

} // namespace forensic

#endif // FORENSIC_AUDITLOG_H
