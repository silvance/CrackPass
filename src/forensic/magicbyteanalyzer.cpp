/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#include "magicbyteanalyzer.h"

#include <QFile>

namespace forensic {

MagicByteAnalyzer::MagicByteAnalyzer()
{
    // Offline signature table. Ordered roughly by specificity.
    m_signatures = {
        {0, QByteArray("\x25\x50\x44\x46", 4),                 QStringLiteral("pdf"),
         QStringLiteral("PDF document"),                        0.95},
        {0, QByteArray("\x03\xd9\xa2\x9a", 4),                 QStringLiteral("keepass-kdbx"),
         QStringLiteral("KeePass 2 database (kdbx)"),           0.98},
        {0, QByteArray("\x37\x7a\xbc\xaf\x27\x1c", 6),         QStringLiteral("7z"),
         QStringLiteral("7-Zip archive"),                       0.95},
        {0, QByteArray("\x52\x61\x72\x21\x1a\x07", 6),         QStringLiteral("rar"),
         QStringLiteral("RAR archive"),                         0.95},
        // ZIP is the least specific (OOXML/ODF/JAR/etc. are ZIP containers),
        // so it comes last and carries lower confidence.
        {0, QByteArray("\x50\x4b\x03\x04", 4),                 QStringLiteral("zip"),
         QStringLiteral("ZIP container (may be Office/ODF/etc.)"), 0.60},
    };
}

ArtifactType MagicByteAnalyzer::analyze(const QString &filePath) const
{
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly))
        return ArtifactType::unknown();

    // Read enough for the longest signature + offset.
    const QByteArray header = file.read(64);

    for (const Signature &sig : m_signatures) {
        if (header.size() < sig.offset + sig.magic.size())
            continue;
        if (header.mid(sig.offset, sig.magic.size()) == sig.magic)
            return ArtifactType{sig.typeId, sig.displayName, sig.confidence};
    }

    return ArtifactType::unknown();
}

} // namespace forensic
