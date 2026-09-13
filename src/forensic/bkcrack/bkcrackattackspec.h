/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 *
 * A fully explicit description of one bkcrack (ZipCrypto known-plaintext) run.
 *
 * bkcrack is a known-plaintext cryptanalysis, not a password guess, so this
 * spec is deliberately NOT the hashcat-shaped AttackJobSpec: it carries the
 * encrypted archive, the target entry inside it, and the known plaintext the
 * examiner supplies -- either a plaintext file or a run of bytes at a known
 * offset. Exactly one plaintext source is used. Nothing is implicit; what you
 * see is what bkcrack is told (see docs/BKCRACK_DESIGN.md).
 */
#ifndef FORENSIC_BKCRACKATTACKSPEC_H
#define FORENSIC_BKCRACKATTACKSPEC_H

#include <QString>
#include <QStringList>

namespace forensic {

struct BkcrackAttackSpec
{
    QString zipPath;      // the encrypted ZIP archive (bkcrack -C)
    QString targetEntry;  // the ZipCrypto entry to attack, by name (bkcrack -c)

    // Known-plaintext source -- exactly one of these is provided:
    QString plainFile;    // path to a known plaintext file/prefix (bkcrack -p)
    QString plainHex;     // known bytes as hex (bkcrack -x <offset> <hex>)

    // Offset of the known plaintext. For plainHex it is the -x offset; for
    // plainFile it is the -o plaintext offset (omitted when 0).
    qint64 plainOffset = 0;

    // Escape hatch for advanced bkcrack flags.
    QStringList extraArgs;
};

} // namespace forensic

#endif // FORENSIC_BKCRACKATTACKSPEC_H
