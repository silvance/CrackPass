/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#include "extractorregistry.h"
#include "extraction/johnextractors.h"

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
    // One adapter per supported artifact/extractor type. New formats are added
    // here (or via registerExtractor) with no change to the extraction workflow.
    registry.registerExtractor(std::make_shared<OfficeHashExtractor>());
    registry.registerExtractor(std::make_shared<PdfHashExtractor>());
    registry.registerExtractor(std::make_shared<ZipHashExtractor>());
    registry.registerExtractor(std::make_shared<RarHashExtractor>());
    registry.registerExtractor(std::make_shared<SevenZipHashExtractor>());
    registry.registerExtractor(std::make_shared<KeePassHashExtractor>());
    return registry;
}

} // namespace forensic
