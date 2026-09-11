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

    QString m_rootPath;
    CaseInfo m_info;
    QList<EvidenceItem> m_evidence;
    std::unique_ptr<AuditLog> m_audit;
    ArtifactAnalyzerRegistry m_analyzers = ArtifactAnalyzerRegistry::withBuiltins();
    ExtractorRegistry m_extractors = ExtractorRegistry::withBuiltins();
};

} // namespace forensic

#endif // FORENSIC_CASEWORKSPACE_H
