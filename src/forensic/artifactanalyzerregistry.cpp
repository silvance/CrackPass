/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "artifactanalyzerregistry.h"
#include "magicbyteanalyzer.h"

namespace forensic {

void ArtifactAnalyzerRegistry::registerAnalyzer(std::shared_ptr<ArtifactAnalyzer> analyzer)
{
    if (analyzer)
        m_analyzers.append(std::move(analyzer));
}

ArtifactType ArtifactAnalyzerRegistry::identify(const QString &filePath) const
{
    ArtifactType best = ArtifactType::unknown();
    for (const auto &analyzer : m_analyzers) {
        const ArtifactType t = analyzer->analyze(filePath);
        if (!t.isUnknown() && t.confidence > best.confidence)
            best = t;
    }
    return best;
}

ArtifactAnalyzerRegistry ArtifactAnalyzerRegistry::withBuiltins()
{
    ArtifactAnalyzerRegistry registry;
    registry.registerAnalyzer(std::make_shared<MagicByteAnalyzer>());
    return registry;
}

} // namespace forensic
