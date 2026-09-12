/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef FORENSIC_CASEKNOWLEDGE_H
#define FORENSIC_CASEKNOWLEDGE_H

#include <QFlags>
#include <QHash>
#include <QString>
#include <QStringList>

namespace forensic {

// Character classes the examiner can require in the password.
enum class CharClass {
    None    = 0x0,
    Lower   = 0x1,
    Upper   = 0x2,
    Digit   = 0x4,
    Special = 0x8,
};
Q_DECLARE_FLAGS(CharClasses, CharClass)

/*
 * Structured case knowledge an examiner can supply. These inputs are turned
 * into EXPLICIT wordlists, masks and rules by the planner -- never opaque
 * behavior. Every field is optional; unset numeric fields use -1.
 */
struct CaseKnowledge
{
    int minLength = -1;
    int maxLength = -1;

    QString knownPrefix;
    QString knownSuffix;

    // 0-based absolute position -> known literal character.
    QHash<int, QChar> knownPositions;

    CharClasses requiredClasses;

    QStringList baseWords;      // suspected base words
    QStringList names;          // people/pet/org names
    QStringList usernames;
    QStringList emails;         // local-parts are also mined as words

    int yearFrom = -1;          // inclusive year range for date-based guesses
    int yearTo = -1;

    QStringList previousPasswords; // previously recovered passwords (this subject/case)

    bool hasAnyWordSeed() const
    {
        return !baseWords.isEmpty() || !names.isEmpty() || !usernames.isEmpty()
               || !emails.isEmpty() || !previousPasswords.isEmpty();
    }
};

} // namespace forensic

Q_DECLARE_OPERATORS_FOR_FLAGS(forensic::CharClasses)

#endif // FORENSIC_CASEKNOWLEDGE_H
