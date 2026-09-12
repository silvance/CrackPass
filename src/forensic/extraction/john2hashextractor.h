/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef FORENSIC_JOHN2HASHEXTRACTOR_H
#define FORENSIC_JOHN2HASHEXTRACTOR_H

#include "forensic/hashextractor.h"
#include "hashcatmodes.h"

#include <QString>
#include <QStringList>

namespace forensic {

/*
 * Base for extractors that wrap a John the Ripper Jumbo "*2john" utility.
 *
 * The tool is invoked read-only on the ORIGINAL evidence path and prints
 * "<name>:<hash>" to stdout. This base handles: tool resolution, running via
 * the injected ProcessRunner, capturing stdout/stderr/exit, and normalizing
 * the "<name>:<hash>" line into a bare hash. Subclasses provide the tool id,
 * supported types, display name, and the hash->mode mapping.
 */
class John2HashExtractor : public HashExtractor
{
public:
    ExtractionResult extract(const EvidenceItem &item, const ExtractionContext &ctx) const override;

    // Extracts the bare hash from a "<name>:<hash>" *2john output line.
    // Returns empty if no hash (line without a '$'-prefixed payload).
    static QString normalizeHashLine(const QString &stdOut);

protected:
    // Map a normalized hash to candidate hashcat modes (empty = unrecognized).
    virtual QVector<HashcatModeOption> resolveModes(const QString &hash) const = 0;

    // How the input path is passed to the tool. Most *2john utilities take the
    // file positionally; some (e.g. bitlocker2john) require a flag like "-i".
    virtual QStringList inputArgs(const QString &inputPath) const { return {inputPath}; }
};

} // namespace forensic

#endif // FORENSIC_JOHN2HASHEXTRACTOR_H
