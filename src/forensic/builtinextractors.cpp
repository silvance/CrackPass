/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#include "builtinextractors.h"

namespace forensic {

DeclaredHashExtractor::DeclaredHashExtractor(QString id, QString displayName,
                                             QSet<QString> supportedTypeIds, quint32 hashMode)
    : m_id(std::move(id))
    , m_displayName(std::move(displayName))
    , m_supportedTypeIds(std::move(supportedTypeIds))
    , m_hashMode(hashMode)
{
}

bool DeclaredHashExtractor::supports(const ArtifactType &type) const
{
    return m_supportedTypeIds.contains(type.id);
}

ExtractionResult DeclaredHashExtractor::extract(const EvidenceItem &) const
{
    ExtractionResult r;
    r.status = ExtractionStatus::NotImplemented;
    r.extractorId = m_id;
    r.hashMode = m_hashMode;
    r.message = QStringLiteral("Hash extraction is not implemented yet (foundation stage).");
    return r;
}

} // namespace forensic
