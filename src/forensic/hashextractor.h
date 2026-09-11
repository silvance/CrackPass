/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#ifndef FORENSIC_HASHEXTRACTOR_H
#define FORENSIC_HASHEXTRACTOR_H

#include "artifacttype.h"
#include "evidenceitem.h"
#include <QString>

namespace forensic {

enum class ExtractionStatus {
    Success,
    Failed,
    NotImplemented,
};

/*
 * Outcome of a hash-extraction attempt. The extracted hash is kept here,
 * separate from the evidence model, and is later persisted to its own file in
 * the case workspace.
 */
struct ExtractionResult
{
    ExtractionStatus status = ExtractionStatus::NotImplemented;
    QString hash;          // hashcat-compatible hash line(s)
    quint32 hashMode = 0;  // hashcat -m mode
    QString message;
    QString stdOut;        // preserved for troubleshooting
    QString stdErr;
    QString extractorId;
    QString extractorVersion;
};

/*
 * Generic interface for turning an encrypted artifact into a hashcat-ready
 * hash. Implementations wrap established offline extraction tools.
 *
 * NOTE (foundation stage): concrete extractors declare which artifact types
 * they support and their default hashcat mode, but extract() intentionally
 * returns NotImplemented. No password attacks are performed yet.
 */
class HashExtractor
{
public:
    virtual ~HashExtractor() = default;

    virtual QString id() const = 0;
    virtual QString displayName() const = 0;

    // True if this extractor can handle the given artifact type.
    virtual bool supports(const ArtifactType &type) const = 0;

    // The hashcat -m mode this extractor's output feeds into.
    virtual quint32 defaultHashMode() const = 0;

    virtual ExtractionResult extract(const EvidenceItem &item) const = 0;
};

} // namespace forensic

#endif // FORENSIC_HASHEXTRACTOR_H
