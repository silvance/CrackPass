/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#include "extractorregistry.h"
#include "builtinextractors.h"

namespace forensic {

void ExtractorRegistry::registerExtractor(std::shared_ptr<HashExtractor> extractor)
{
    if (extractor)
        m_extractors.append(std::move(extractor));
}

HashExtractor *ExtractorRegistry::extractorFor(const ArtifactType &type) const
{
    if (type.isUnknown())
        return nullptr;
    for (const auto &e : m_extractors) {
        if (e->supports(type))
            return e.get();
    }
    return nullptr;
}

bool ExtractorRegistry::hasExtractorFor(const ArtifactType &type) const
{
    return extractorFor(type) != nullptr;
}

ExtractorRegistry ExtractorRegistry::withBuiltins()
{
    ExtractorRegistry registry;
    // Declared extractors: types they will handle + target hashcat mode.
    // extract() is not implemented yet; these exist so the UI and planner can
    // reason about coverage.
    registry.registerExtractor(std::make_shared<DeclaredHashExtractor>(
        QStringLiteral("pdf-extractor"), QStringLiteral("PDF (office/pdf2hashcat)"),
        QSet<QString>{QStringLiteral("pdf")}, 10500));
    registry.registerExtractor(std::make_shared<DeclaredHashExtractor>(
        QStringLiteral("keepass-extractor"), QStringLiteral("KeePass (keepass2hashcat)"),
        QSet<QString>{QStringLiteral("keepass-kdbx")}, 13400));
    registry.registerExtractor(std::make_shared<DeclaredHashExtractor>(
        QStringLiteral("sevenzip-extractor"), QStringLiteral("7-Zip (7z2hashcat)"),
        QSet<QString>{QStringLiteral("7z")}, 11600));
    return registry;
}

} // namespace forensic
