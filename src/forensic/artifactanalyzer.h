/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef FORENSIC_ARTIFACTANALYZER_H
#define FORENSIC_ARTIFACTANALYZER_H

#include "artifacttype.h"
#include <QString>

namespace forensic {

/*
 * Generic interface for identifying a submitted artifact.
 *
 * Implementations inspect a file READ-ONLY and return an ArtifactType. They
 * must not modify the file. Returning ArtifactType::unknown() means "this
 * analyzer does not recognize the artifact".
 */
class ArtifactAnalyzer
{
public:
    virtual ~ArtifactAnalyzer() = default;

    // Stable identifier of the analyzer implementation (for audit records).
    virtual QString id() const = 0;

    // Inspect the file and return the recognized type, or unknown().
    virtual ArtifactType analyze(const QString &filePath) const = 0;
};

} // namespace forensic

#endif // FORENSIC_ARTIFACTANALYZER_H
