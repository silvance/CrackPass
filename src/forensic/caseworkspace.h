/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef FORENSIC_CASEWORKSPACE_H
#define FORENSIC_CASEWORKSPACE_H

#include "artifactanalyzerregistry.h"
#include "auditlog.h"
#include "caseinfo.h"
#include "evidenceintake.h"
#include "evidenceitem.h"
#include "extractorregistry.h"
#include "extraction/extraction.h"
#include "extraction/encryptionprobe.h"
#include "crackingjob.h"
#include "recoveredcredential.h"

#include <QList>
#include <QString>
#include <memory>

namespace forensic {

/*
 * An opened case on disk. Owns the directory scaffold, the case manifest, the
 * audit log, and the in-memory list of evidence. Persistence in this
 * foundation stage is JSON-on-disk (case.json + per-evidence metadata.json +
 * append-only audit.log.jsonl); the layout mirrors the design so a SQLite
 * store can replace it behind this same class later without touching callers.
 *
 * The analyzer and extractor registries default to the built-ins but can be
 * injected for testing.
 */
class CaseWorkspace
{
public:
    // Creates <parentDir>/<sanitized name>__<short id>/ with the scaffold and a
    // "case_created" audit event. Returns nullptr on failure (with *error).
    static std::unique_ptr<CaseWorkspace> create(const QString &parentDir, const CaseInfo &info,
                                                  QString *error = nullptr);

    // Opens an existing case directory (must contain case.json).
    static std::unique_ptr<CaseWorkspace> open(const QString &caseDir, QString *error = nullptr);

    const CaseInfo &info() const { return m_info; }
    QString rootPath() const { return m_rootPath; }

    // Intake + persist + audit. Never modifies the source file. With
    // EvidenceStorageMode::WorkingCopy an immutable copy is imported into the
    // case and used for all later reads.
    IntakeResult addEvidence(const QString &sourcePath,
                             EvidenceStorageMode mode = EvidenceStorageMode::Referenced);

    // Absolute path CaseKey reads for this artifact (working copy if imported,
    // else the referenced original).
    QString evidenceReadPath(const EvidenceItem &item) const;

    struct IntegrityResult {
        bool ok = false;          // current bytes still match the intake SHA-256
        bool checked = false;     // false => could not read the artifact at all
        QString recordedSha256;
        QString currentSha256;
        QString error;
    };

    // Recomputes the artifact SHA-256 and compares it to the value recorded at
    // intake. On mismatch or unreadable source it fails loudly (audited); it
    // never silently continues.
    IntegrityResult verifyEvidenceIntegrity(const QUuid &evidenceId);
    QList<EvidenceItem> evidence() const { return m_evidence; }
    EvidenceItem *evidenceById(const QUuid &id);

    // Content-based check of whether an evidence item appears encrypted.
    EncryptionState probeEncryption(const QUuid &evidenceId) const;

    struct ExtractionOutcome {
        bool ok = false;              // orchestration succeeded (a record was produced)
        Extraction record;
        ExtractionResult result;      // full result incl. captured output + candidate modes
        QString error;                // set when orchestration could not run at all
    };

    // Runs the appropriate extractor for the evidence item WITHOUT modifying the
    // evidence, persists an Extraction record (+ hash/stdout/stderr files), and
    // audits it. If exactly one hashcat mode is possible it is auto-selected;
    // otherwise selectedMode stays 0 and the examiner must choose.
    ExtractionOutcome extractHash(const QUuid &evidenceId, const ExtractionContext &ctx);

    // Records the examiner's mode choice for an ambiguous extraction (persist + audit).
    bool selectExtractionMode(const QUuid &extractionId, quint32 mode, QString *error = nullptr);

    QList<Extraction> extractions() const { return m_extractions; }

    // Jobs: persist a cracking job record and list them (loaded on open).
    bool saveJob(const CrackingJob &job, QString *error = nullptr);
    QList<CrackingJob> jobs() const { return m_jobs; }
    QString jobDir(const QUuid &jobId) const;

    // Recovered credentials: recorded against job/artifact/case, timestamped,
    // and always readable (no gating). Persisted + audited.
    bool addRecoveredCredential(const RecoveredCredential &cred, QString *error = nullptr);
    QList<RecoveredCredential> recoveredCredentials() const { return m_credentials; }

    AuditLog &audit() { return *m_audit; }
    const ArtifactAnalyzerRegistry &analyzers() const { return m_analyzers; }
    ExtractorRegistry &extractors() { return m_extractors; }

    // Directory helpers.
    QString evidenceDir() const;
    QString jobsDir() const;
    QString extractionsDir() const;
    QString reportsDir() const;
    QString logsDir() const;

    // For dependency injection in tests (call before create/open effects rely
    // on them). Defaults are the built-in registries.
    void setAnalyzers(ArtifactAnalyzerRegistry analyzers) { m_analyzers = std::move(analyzers); }
    void setExtractors(ExtractorRegistry extractors) { m_extractors = std::move(extractors); }

private:
    CaseWorkspace() = default;
    // Actor recorded on audit events (examiner name, or "system" when unset).
    QString auditActor() const;
    bool appendAudit(const QString &action, const QString &entityType,
                     const QString &entityId, const QJsonObject &details, QString *error = nullptr);
    bool loadEvidence(QString *error);
    QString evidenceMetaPath(const QUuid &evidenceId) const;
    QString extractionMetaPath(const QUuid &extractionId) const;
    bool loadExtractions(QString *error);
    bool loadJobs(QString *error);
    bool loadCredentials(QString *error);

    QString m_rootPath;
    CaseInfo m_info;
    QList<EvidenceItem> m_evidence;
    QList<Extraction> m_extractions;
    QList<CrackingJob> m_jobs;
    QList<RecoveredCredential> m_credentials;
    std::unique_ptr<AuditLog> m_audit;
    ArtifactAnalyzerRegistry m_analyzers = ArtifactAnalyzerRegistry::withBuiltins();
    ExtractorRegistry m_extractors = ExtractorRegistry::withBuiltins();
};

} // namespace forensic

#endif // FORENSIC_CASEWORKSPACE_H
