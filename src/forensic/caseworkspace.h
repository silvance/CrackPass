/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
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

    // Intake + persist + audit. Never modifies the source file.
    IntakeResult addEvidence(const QString &sourcePath);
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
    bool writeCaseManifest(QString *error) const;
    bool loadEvidence(QString *error);
    bool persistEvidence(const EvidenceItem &item, QString *error) const;
    bool persistExtraction(const Extraction &e, QString *error) const;
    bool loadExtractions(QString *error);

    QString m_rootPath;
    CaseInfo m_info;
    QList<EvidenceItem> m_evidence;
    QList<Extraction> m_extractions;
    std::unique_ptr<AuditLog> m_audit;
    ArtifactAnalyzerRegistry m_analyzers = ArtifactAnalyzerRegistry::withBuiltins();
    ExtractorRegistry m_extractors = ExtractorRegistry::withBuiltins();
};

} // namespace forensic

#endif // FORENSIC_CASEWORKSPACE_H
