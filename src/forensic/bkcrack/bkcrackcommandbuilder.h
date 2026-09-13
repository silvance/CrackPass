/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 *
 * Turns a BkcrackAttackSpec into a bkcrack command line. Pure and unit-testable;
 * process plumbing is added later by BkcrackExecutionBackend.
 *
 * Like JohnCommandBuilder, it refuses rather than approximates: an incomplete or
 * invalid spec (no archive, no target entry, no known plaintext, both plaintext
 * sources at once, or malformed/too-short hex) yields a specific reason instead
 * of a command that cannot work.
 */
#ifndef FORENSIC_BKCRACKCOMMANDBUILDER_H
#define FORENSIC_BKCRACKCOMMANDBUILDER_H

#include "bkcrackattackspec.h"

#include <QString>
#include <QStringList>

namespace forensic {

struct BkcrackBuildResult
{
    bool valid = false; // false => the spec cannot be turned into a bkcrack run
    QString error;      // human-readable reason when !valid
    QStringList args;   // the bkcrack argv when valid
};

class BkcrackCommandBuilder
{
public:
    // bkcrack's known-plaintext attack needs a minimum run of contiguous known
    // plaintext bytes; this is that documented floor, applied to the -x hex.
    static constexpr int kMinPlaintextBytes = 12;

    static BkcrackBuildResult build(const BkcrackAttackSpec &spec);
};

} // namespace forensic

#endif // FORENSIC_BKCRACKCOMMANDBUILDER_H
