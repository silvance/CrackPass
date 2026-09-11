/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#ifndef FORENSIC_ARTIFACTANALYZERREGISTRY_H
#define FORENSIC_ARTIFACTANALYZERREGISTRY_H

#include "artifactanalyzer.h"
#include <QList>
#include <memory>

namespace forensic {

/*
 * Holds the available ArtifactAnalyzer implementations and runs them against a
 * file, returning the highest-confidence recognized type.
 */
class ArtifactAnalyzerRegistry
{
public:
    void registerAnalyzer(std::shared_ptr<ArtifactAnalyzer> analyzer);

    // Runs all analyzers; returns the best (highest confidence) match, or
    // ArtifactType::unknown() if none recognize the file.
    ArtifactType identify(const QString &filePath) const;

    int count() const { return static_cast<int>(m_analyzers.size()); }

    // Registry pre-populated with the built-in analyzers.
    static ArtifactAnalyzerRegistry withBuiltins();

private:
    QList<std::shared_ptr<ArtifactAnalyzer>> m_analyzers;
};

} // namespace forensic

#endif // FORENSIC_ARTIFACTANALYZERREGISTRY_H
