/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "moderesolution.h"

namespace forensic {
namespace modes {

namespace {
HashcatModeOption opt(quint32 m, const char *name) { return HashcatModeOption{m, QString::fromLatin1(name)}; }
} // namespace

QVector<HashcatModeOption> forOffice(const QString &hash)
{
    if (hash.startsWith(QStringLiteral("$office$"))) {
        if (hash.contains(QStringLiteral("*2007*"))) return {opt(9400, "MS Office 2007")};
        if (hash.contains(QStringLiteral("*2010*"))) return {opt(9500, "MS Office 2010")};
        if (hash.contains(QStringLiteral("*2013*"))) return {opt(9600, "MS Office 2013+")};
        return {}; // recognized container but unknown version -> do not guess
    }
    if (hash.startsWith(QStringLiteral("$oldoffice$"))) {
        // $oldoffice$<0|1|3|4>*...  0/1 = MD5+RC4, 3/4 = SHA1+RC4.
        const QChar variant = hash.size() > 11 ? hash.at(11) : QChar();
        if (variant == QLatin1Char('0') || variant == QLatin1Char('1')) {
            return {opt(9700, "MS Office <= 2003 (MD5 + RC4)"),
                    opt(9710, "MS Office <= 2003 (MD5 + RC4, collider #1)"),
                    opt(9720, "MS Office <= 2003 (MD5 + RC4, collider #2)")};
        }
        if (variant == QLatin1Char('3') || variant == QLatin1Char('4')) {
            return {opt(9800, "MS Office <= 2003 (SHA1 + RC4)"),
                    opt(9810, "MS Office <= 2003 (SHA1 + RC4, collider #1)"),
                    opt(9820, "MS Office <= 2003 (SHA1 + RC4, collider #2)")};
        }
    }
    return {};
}

QVector<HashcatModeOption> forPdf(const QString &hash)
{
    if (!hash.startsWith(QStringLiteral("$pdf$")))
        return {};
    const QString rest = hash.mid(5);
    const QStringList fields = rest.split(QLatin1Char('*'));
    if (fields.size() >= 2) {
        bool ok = false;
        const int r = fields.at(1).toInt(&ok);
        if (ok) {
            switch (r) {
            case 2: return {opt(10400, "PDF 1.1-1.3 (Acrobat 2-4)")};
            case 3:
            case 4: return {opt(10500, "PDF 1.4-1.6 (Acrobat 5-8)")};
            case 5: return {opt(10600, "PDF 1.7 Level 3 (Acrobat 9)")};
            case 6: return {opt(10700, "PDF 1.7 Level 8 (Acrobat 10-11)")};
            default: break;
            }
        }
    }
    // Recognized as PDF but revision undetermined -> present all, do not guess.
    return {opt(10400, "PDF 1.1-1.3 (Acrobat 2-4)"),
            opt(10500, "PDF 1.4-1.6 (Acrobat 5-8)"),
            opt(10600, "PDF 1.7 Level 3 (Acrobat 9)"),
            opt(10700, "PDF 1.7 Level 8 (Acrobat 10-11)")};
}

QVector<HashcatModeOption> forZip(const QString &hash)
{
    if (hash.startsWith(QStringLiteral("$zip2$")))
        return {opt(13600, "WinZip (AES)")};
    if (hash.startsWith(QStringLiteral("$pkzip2$")) || hash.startsWith(QStringLiteral("$pkzip$"))) {
        // Legacy ZipCrypto: hashcat has several PKZIP variants; the exact one
        // depends on compression/file layout, which we do not infer here.
        return {opt(17200, "PKZIP (Compressed)"),
                opt(17210, "PKZIP (Uncompressed)"),
                opt(17220, "PKZIP (Compressed Multi-File)"),
                opt(17225, "PKZIP (Mixed Multi-File)")};
    }
    return {};
}

QVector<HashcatModeOption> forRar(const QString &hash)
{
    if (hash.startsWith(QStringLiteral("$rar5$")))
        return {opt(13000, "RAR5")};
    if (hash.startsWith(QStringLiteral("$RAR3$"))) {
        const QString rest = hash.mid(6); // after "$RAR3$"
        if (rest.startsWith(QStringLiteral("*0*")))
            return {opt(12500, "RAR3-hp (header encrypted)")};
        if (rest.startsWith(QStringLiteral("*1*"))) {
            return {opt(23700, "RAR3-p (Uncompressed)"),
                    opt(23800, "RAR3-p (Compressed)")};
        }
        return {}; // RAR3 but mode field unrecognized
    }
    return {};
}

QVector<HashcatModeOption> forSevenZip(const QString &hash)
{
    if (hash.startsWith(QStringLiteral("$7z$")))
        return {opt(11600, "7-Zip")};
    return {};
}

QVector<HashcatModeOption> forKeePass(const QString &hash)
{
    if (hash.startsWith(QStringLiteral("$keepass$")))
        return {opt(13400, "KeePass 1/2 (AES/Twofish/ChaCha20)")};
    return {};
}

QVector<HashcatModeOption> forBitLocker(const QString &hash)
{
    // bitlocker2john emits several $bitlocker$<type>$... lines (user password,
    // recovery password, etc.); hashcat mode 22100 covers them all.
    if (hash.startsWith(QStringLiteral("$bitlocker$")))
        return {opt(22100, "BitLocker")};
    return {};
}

} // namespace modes
} // namespace forensic
