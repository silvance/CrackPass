/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 *
 * Classifies how a ZIP archive's entries are encrypted. This is the
 * applicability gate for the bkcrack (ZipCrypto known-plaintext) attack: bkcrack
 * works ONLY on the legacy PKWARE "ZipCrypto" stream cipher, never on WinZip
 * AES. An encrypted entry (general-purpose bit-flag bit 0 set) is AES when its
 * compression method is 99 (0x63) or it carries the AES extra field (header id
 * 0x9901); otherwise the encryption is traditional ZipCrypto.
 *
 * The classifier is pure (a byte buffer in, a verdict out) so it is unit-tested
 * without real archives, and it never guesses: an entry it cannot parse is
 * reported as Unknown, not silently treated as attackable.
 */
#ifndef FORENSIC_ZIPCIPHER_H
#define FORENSIC_ZIPCIPHER_H

#include <QByteArray>
#include <QList>
#include <QString>
#include <QStringList>

namespace forensic {

enum class ZipEntryCipher {
    None,      // not encrypted
    ZipCrypto, // legacy PKWARE stream cipher (bkcrack applies)
    Aes,       // WinZip AES (bkcrack does NOT apply)
    Unknown,   // encrypted, but the scheme could not be determined
};

struct ZipEntryInfo {
    QString name;
    ZipEntryCipher cipher = ZipEntryCipher::None;
    quint16 compressionMethod = 0;
    quint64 compressedSize = 0;
};

struct ZipCipherScan {
    bool isZip = false; // at least one ZIP record (central-dir or local) was found
    QList<ZipEntryInfo> entries;

    bool anyEncrypted() const;
    bool hasZipCrypto() const;
    bool hasAes() const;

    // Names of the ZipCrypto entries -- the candidate targets for a bkcrack
    // known-plaintext attack.
    QStringList zipCryptoEntryNames() const;
};

class ZipCipherClassifier
{
public:
    // Scan up to maxBytes of the file at filePath.
    static ZipCipherScan scan(const QString &filePath, qint64 maxBytes = 64LL * 1024 * 1024);

    // Pure core: classify from an in-memory buffer (the whole archive, or as
    // much of it as was read). Prefers the central directory (authoritative);
    // falls back to local file headers when no central directory is present.
    static ZipCipherScan scanData(const QByteArray &data);
};

} // namespace forensic

#endif // FORENSIC_ZIPCIPHER_H
