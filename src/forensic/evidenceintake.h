/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef FORENSIC_EVIDENCEINTAKE_H
#define FORENSIC_EVIDENCEINTAKE_H

#include "artifactanalyzerregistry.h"
#include "evidenceitem.h"
#include <QString>

namespace forensic {

struct IntakeResult
{
    bool ok = false;
    EvidenceItem item;
    QString error;
};

/*
 * Builds an EvidenceItem from a source file: collects filesystem metadata,
 * computes a read-only SHA-256, and identifies the artifact type. It does not
 * copy or modify the source, and does not persist anything (CaseWorkspace owns
 * persistence) -- keeping intake pure and unit-testable.
 */
class EvidenceIntake
{
public:
    explicit EvidenceIntake(const ArtifactAnalyzerRegistry &analyzers);

    IntakeResult import(const QString &caseId, const QString &sourcePath) const;

private:
    const ArtifactAnalyzerRegistry &m_analyzers;
};

} // namespace forensic

#endif // FORENSIC_EVIDENCEINTAKE_H
