/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "encryptionprobe.h"

#include <QFile>

namespace forensic {

EncryptionState EncryptionProbe::probe(const ArtifactType &type, const QString &filePath)
{
    if (type.id == QStringLiteral("zip"))
        return probeZip(filePath);
    if (type.id == QStringLiteral("pdf"))
        return probePdf(filePath);
    if (type.id == QStringLiteral("keepass-kdbx"))
        return EncryptionState::Encrypted; // a KeePass database is always encrypted
    return EncryptionState::Unknown;
}

// The ZIP local file header general-purpose bit flag bit 0 marks an encrypted
// entry. We scan local file headers (signature PK\x03\x04) and report Encrypted
// if any entry has the flag set.
EncryptionState EncryptionProbe::probeZip(const QString &filePath)
{
    QFile f(filePath);
    if (!f.open(QIODevice::ReadOnly))
        return EncryptionState::Unknown;

    const QByteArray data = f.read(4 * 1024 * 1024); // scan first few MiB
    const char sig[4] = {'P', 'K', '\x03', '\x04'};
    bool sawEntry = false;
    for (int i = 0; i + 8 <= data.size(); ++i) {
        if (data[i] == sig[0] && data[i + 1] == sig[1] && data[i + 2] == sig[2] && data[i + 3] == sig[3]) {
            sawEntry = true;
            // general purpose bit flag is 2 bytes at offset +6 (little-endian)
            const quint16 flag = static_cast<quint8>(data[i + 6]) | (static_cast<quint8>(data[i + 7]) << 8);
            if (flag & 0x0001)
                return EncryptionState::Encrypted;
        }
    }
    return sawEntry ? EncryptionState::NotEncrypted : EncryptionState::Unknown;
}

// A PDF is encrypted iff its trailer references an /Encrypt dictionary.
EncryptionState EncryptionProbe::probePdf(const QString &filePath)
{
    QFile f(filePath);
    if (!f.open(QIODevice::ReadOnly))
        return EncryptionState::Unknown;
    const QByteArray data = f.readAll();
    if (!data.startsWith("%PDF"))
        return EncryptionState::Unknown;
    return data.contains("/Encrypt") ? EncryptionState::Encrypted : EncryptionState::NotEncrypted;
}

} // namespace forensic
