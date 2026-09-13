/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 *
 * Turns a planned AttackJobSpec into a John the Ripper command line.
 *
 * The AttackJobSpec is hashcat-shaped (mode numbers, rule files, hybrid attack
 * modes, custom charsets). John expresses only a subset of that cleanly:
 * dictionary (wordlist), mask, and incremental (Markov) attacks. Rather than
 * silently approximate a spec John cannot express -- which would produce a run
 * that does NOT match what the examiner planned -- the builder REFUSES it and
 * reports why. The forensic contract is "what you see is what runs": an
 * approximate John run for a rule-heavy hashcat template would break that.
 *
 * The builder is pure and unit-testable; process plumbing (--session, --pot,
 * status) is added later by JohnExecutionBackend.
 */
#ifndef FORENSIC_JOHNCOMMANDBUILDER_H
#define FORENSIC_JOHNCOMMANDBUILDER_H

#include "attackjobspec.h"

#include <QString>
#include <QStringList>

namespace forensic {

struct JohnBuildResult
{
    bool supported = false; // false => John cannot express this attack exactly
    QString error;          // human-readable reason when !supported
    QStringList args;       // the john argv (attack + hash file) when supported
};

class JohnCommandBuilder
{
public:
    // Build the john argv for `spec`, or report why John cannot express it.
    static JohnBuildResult build(const AttackJobSpec &spec);
};

} // namespace forensic

#endif // FORENSIC_JOHNCOMMANDBUILDER_H
