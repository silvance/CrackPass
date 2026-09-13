/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "bkcrackcommandbuilder.h"

#include <cctype>

namespace forensic {

namespace {

BkcrackBuildResult refuse(const QString &why)
{
    BkcrackBuildResult r;
    r.valid = false;
    r.error = why;
    return r;
}

// Strip ASCII whitespace so "de ad be ef" and "deadbeef" are both accepted.
QString stripWhitespace(const QString &s)
{
    QString out;
    out.reserve(s.size());
    for (const QChar c : s)
        if (!c.isSpace())
            out.append(c);
    return out;
}

bool isHex(const QString &s)
{
    if (s.isEmpty() || (s.size() % 2) != 0)
        return false;
    for (const QChar c : s)
        if (!isxdigit(static_cast<unsigned char>(c.toLatin1())))
            return false;
    return true;
}

} // namespace

BkcrackBuildResult BkcrackCommandBuilder::build(const BkcrackAttackSpec &spec)
{
    if (spec.zipPath.isEmpty())
        return refuse(QStringLiteral("No encrypted ZIP archive specified."));
    if (spec.targetEntry.isEmpty())
        return refuse(QStringLiteral("No target entry specified. Choose the ZipCrypto entry to attack."));

    const bool hasFile = !spec.plainFile.isEmpty();
    const bool hasHex = !spec.plainHex.isEmpty();
    if (!hasFile && !hasHex)
        return refuse(QStringLiteral(
            "No known plaintext provided. bkcrack needs either a known plaintext "
            "file or a run of known bytes at an offset."));
    if (hasFile && hasHex)
        return refuse(QStringLiteral(
            "Provide either a known plaintext file or bytes-at-offset, not both."));

    QStringList args;
    args << QStringLiteral("-C") << spec.zipPath;
    args << QStringLiteral("-c") << spec.targetEntry;

    if (hasFile) {
        args << QStringLiteral("-p") << spec.plainFile;
        // Only a non-zero plaintext offset needs to be stated (bkcrack -o).
        if (spec.plainOffset != 0)
            args << QStringLiteral("-o") << QString::number(spec.plainOffset);
    } else {
        const QString hex = stripWhitespace(spec.plainHex);
        if (!isHex(hex))
            return refuse(QStringLiteral(
                "Known bytes must be valid hexadecimal (an even number of hex digits)."));
        if (hex.size() / 2 < kMinPlaintextBytes)
            return refuse(QStringLiteral(
                "Known plaintext is too short: bkcrack needs at least %1 contiguous "
                "bytes (%2 given).")
                              .arg(kMinPlaintextBytes)
                              .arg(hex.size() / 2));
        // -x takes the offset and the hex bytes as two separate arguments.
        args << QStringLiteral("-x") << QString::number(spec.plainOffset) << hex.toLower();
    }

    args << spec.extraArgs;

    BkcrackBuildResult r;
    r.valid = true;
    r.args = args;
    return r;
}

} // namespace forensic
