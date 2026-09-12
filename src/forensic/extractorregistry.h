/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef FORENSIC_EXTRACTORREGISTRY_H
#define FORENSIC_EXTRACTORREGISTRY_H

#include "hashextractor.h"
#include <QList>
#include <memory>

namespace forensic {

/*
 * Holds the available HashExtractor implementations and resolves which one (if
 * any) handles a given artifact type.
 */
class ExtractorRegistry
{
public:
    void registerExtractor(std::shared_ptr<HashExtractor> extractor);

    // First extractor that supports the type, or nullptr.
    HashExtractor *extractorFor(const ArtifactType &type) const;
    bool hasExtractorFor(const ArtifactType &type) const;

    QList<std::shared_ptr<HashExtractor>> all() const { return m_extractors; }
    int count() const { return static_cast<int>(m_extractors.size()); }

    // Registry pre-populated with the built-in (declared) extractors.
    static ExtractorRegistry withBuiltins();

private:
    QList<std::shared_ptr<HashExtractor>> m_extractors;
};

} // namespace forensic

#endif // FORENSIC_EXTRACTORREGISTRY_H
