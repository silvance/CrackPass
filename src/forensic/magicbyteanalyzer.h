/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#ifndef FORENSIC_MAGICBYTEANALYZER_H
#define FORENSIC_MAGICBYTEANALYZER_H

#include "artifactanalyzer.h"
#include <QByteArray>
#include <QList>

namespace forensic {

/*
 * A signature-based analyzer that recognizes a small, offline table of common
 * container/document formats by their magic bytes. This is intentionally
 * minimal for the foundation stage; richer structural probing (e.g. OOXML vs
 * plain ZIP) can be added as further analyzers behind the same interface.
 */
class MagicByteAnalyzer : public ArtifactAnalyzer
{
public:
    MagicByteAnalyzer();

    QString id() const override { return QStringLiteral("magic-byte-analyzer"); }
    ArtifactType analyze(const QString &filePath) const override;

private:
    struct Signature {
        qint64 offset;
        QByteArray magic;
        QString typeId;
        QString displayName;
        double confidence;
    };
    QList<Signature> m_signatures;
};

} // namespace forensic

#endif // FORENSIC_MAGICBYTEANALYZER_H
