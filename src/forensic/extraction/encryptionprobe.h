/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef FORENSIC_ENCRYPTIONPROBE_H
#define FORENSIC_ENCRYPTIONPROBE_H

#include "forensic/artifacttype.h"
#include <QString>

namespace forensic {

enum class EncryptionState {
    Encrypted,
    NotEncrypted,
    Unknown,   // could not determine cheaply/offline
};

/*
 * Best-effort, content-based check for whether an artifact is actually
 * password-protected -- WITHOUT running the heavy extractor. Only implemented
 * where it is practical to determine from structure (ZIP general-purpose bit,
 * PDF /Encrypt, KeePass which is always encrypted). Everything else returns
 * Unknown, and the examiner/extractor decides.
 */
class EncryptionProbe
{
public:
    static EncryptionState probe(const ArtifactType &type, const QString &filePath);

    // Exposed for testing.
    static EncryptionState probeZip(const QString &filePath);
    static EncryptionState probePdf(const QString &filePath);
};

} // namespace forensic

#endif // FORENSIC_ENCRYPTIONPROBE_H
