/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "zipcipher.h"

#include <QFile>

namespace forensic {

namespace {

// Little-endian readers with bounds checks (return 0 when out of range; callers
// validate the record fits before trusting a value).
quint16 readU16(const QByteArray &d, int off)
{
    if (off < 0 || off + 2 > d.size())
        return 0;
    return static_cast<quint8>(d[off]) | (static_cast<quint16>(static_cast<quint8>(d[off + 1])) << 8);
}

quint32 readU32(const QByteArray &d, int off)
{
    if (off < 0 || off + 4 > d.size())
        return 0;
    return static_cast<quint32>(static_cast<quint8>(d[off]))
           | (static_cast<quint32>(static_cast<quint8>(d[off + 1])) << 8)
           | (static_cast<quint32>(static_cast<quint8>(d[off + 2])) << 16)
           | (static_cast<quint32>(static_cast<quint8>(d[off + 3])) << 24);
}

bool sigAt(const QByteArray &d, int off, char b2, char b3)
{
    return off + 4 <= d.size() && d[off] == 'P' && d[off + 1] == 'K'
           && d[off + 2] == b2 && d[off + 3] == b3;
}

// True if the extra field [start, start+len) contains the WinZip AES header id
// (0x9901). Extra fields are a sequence of (id:u16, size:u16, data[size]).
bool hasAesExtraField(const QByteArray &d, int start, int len)
{
    int p = start;
    const int end = qMin(start + len, d.size());
    while (p + 4 <= end) {
        const quint16 id = readU16(d, p);
        const quint16 sz = readU16(d, p + 2);
        if (id == 0x9901)
            return true;
        p += 4 + sz;
    }
    return false;
}

ZipEntryCipher classify(bool encrypted, quint16 method, bool aesExtra)
{
    if (!encrypted)
        return ZipEntryCipher::None;
    if (method == 99 || aesExtra)
        return ZipEntryCipher::Aes;
    return ZipEntryCipher::ZipCrypto;
}

// Parse central directory file headers (PK\x01\x02) -- the authoritative entry
// list. Returns the entries found (possibly empty).
QList<ZipEntryInfo> parseCentralDirectory(const QByteArray &d)
{
    QList<ZipEntryInfo> out;
    for (int i = 0; i + 46 <= d.size(); ++i) {
        if (!sigAt(d, i, '\x01', '\x02'))
            continue;
        const quint16 flag = readU16(d, i + 8);
        const quint16 method = readU16(d, i + 10);
        const quint32 compSize = readU32(d, i + 20);
        const quint16 nameLen = readU16(d, i + 28);
        const quint16 extraLen = readU16(d, i + 30);
        const quint16 commentLen = readU16(d, i + 32);
        const int nameOff = i + 46;
        if (nameOff + nameLen > d.size())
            break; // truncated record: stop rather than misread
        const int extraOff = nameOff + nameLen;

        ZipEntryInfo e;
        e.name = QString::fromUtf8(d.mid(nameOff, nameLen));
        e.compressionMethod = method;
        e.compressedSize = compSize;
        const bool encrypted = (flag & 0x0001) != 0;
        e.cipher = classify(encrypted, method, hasAesExtraField(d, extraOff, extraLen));
        out.append(e);

        // Advance past this record to the next.
        i = extraOff + extraLen + commentLen - 1; // -1: loop ++i
    }
    return out;
}

// Fallback: parse local file headers (PK\x03\x04) when no central directory is
// present (e.g. a truncated or streamed archive). Less authoritative -- a data
// descriptor means sizes may be zero here -- but enough to classify the cipher.
QList<ZipEntryInfo> parseLocalHeaders(const QByteArray &d)
{
    QList<ZipEntryInfo> out;
    for (int i = 0; i + 30 <= d.size(); ++i) {
        if (!sigAt(d, i, '\x03', '\x04'))
            continue;
        const quint16 flag = readU16(d, i + 6);
        const quint16 method = readU16(d, i + 8);
        const quint32 compSize = readU32(d, i + 18);
        const quint16 nameLen = readU16(d, i + 26);
        const quint16 extraLen = readU16(d, i + 28);
        const int nameOff = i + 30;
        if (nameOff + nameLen > d.size())
            break;
        const int extraOff = nameOff + nameLen;

        ZipEntryInfo e;
        e.name = QString::fromUtf8(d.mid(nameOff, nameLen));
        e.compressionMethod = method;
        e.compressedSize = compSize;
        const bool encrypted = (flag & 0x0001) != 0;
        e.cipher = classify(encrypted, method, hasAesExtraField(d, extraOff, extraLen));
        out.append(e);

        i = extraOff + extraLen - 1; // -1: loop ++i (entry data is scanned over)
    }
    return out;
}

} // namespace

bool ZipCipherScan::anyEncrypted() const
{
    for (const ZipEntryInfo &e : entries)
        if (e.cipher != ZipEntryCipher::None)
            return true;
    return false;
}

bool ZipCipherScan::hasZipCrypto() const
{
    for (const ZipEntryInfo &e : entries)
        if (e.cipher == ZipEntryCipher::ZipCrypto)
            return true;
    return false;
}

bool ZipCipherScan::hasAes() const
{
    for (const ZipEntryInfo &e : entries)
        if (e.cipher == ZipEntryCipher::Aes)
            return true;
    return false;
}

QStringList ZipCipherScan::zipCryptoEntryNames() const
{
    QStringList out;
    for (const ZipEntryInfo &e : entries)
        if (e.cipher == ZipEntryCipher::ZipCrypto)
            out << e.name;
    return out;
}

ZipCipherScan ZipCipherClassifier::scanData(const QByteArray &data)
{
    ZipCipherScan scan;
    // Prefer the central directory: it is authoritative and compact. Only if it
    // is absent do we fall back to local file headers.
    scan.entries = parseCentralDirectory(data);
    if (scan.entries.isEmpty())
        scan.entries = parseLocalHeaders(data);
    // isZip is true if we saw any ZIP record signature at all (even one we could
    // not fully parse into an entry).
    scan.isZip = !scan.entries.isEmpty();
    for (int i = 0; !scan.isZip && i + 4 <= data.size(); ++i) {
        if (sigAt(data, i, '\x03', '\x04') || sigAt(data, i, '\x01', '\x02')
            || sigAt(data, i, '\x05', '\x06')) {
            scan.isZip = true;
        }
    }
    return scan;
}

ZipCipherScan ZipCipherClassifier::scan(const QString &filePath, qint64 maxBytes)
{
    QFile f(filePath);
    if (!f.open(QIODevice::ReadOnly))
        return ZipCipherScan{};
    const QByteArray data = f.read(maxBytes);
    return scanData(data);
}

} // namespace forensic
