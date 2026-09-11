/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#ifndef FORENSIC_BUILTINEXTRACTORS_H
#define FORENSIC_BUILTINEXTRACTORS_H

#include "hashextractor.h"
#include <QSet>

namespace forensic {

/*
 * A declarative placeholder extractor: it advertises the artifact types it
 * will eventually handle and the hashcat mode it targets, but extraction is
 * not yet implemented. This lets the UI answer "is there an extractor for this
 * artifact type?" before any attack logic exists.
 */
class DeclaredHashExtractor : public HashExtractor
{
public:
    DeclaredHashExtractor(QString id, QString displayName,
                          QSet<QString> supportedTypeIds, quint32 hashMode);

    QString id() const override { return m_id; }
    QString displayName() const override { return m_displayName; }
    bool supports(const ArtifactType &type) const override;
    quint32 defaultHashMode() const override { return m_hashMode; }
    ExtractionResult extract(const EvidenceItem &item) const override;

private:
    QString m_id;
    QString m_displayName;
    QSet<QString> m_supportedTypeIds;
    quint32 m_hashMode;
};

} // namespace forensic

#endif // FORENSIC_BUILTINEXTRACTORS_H
