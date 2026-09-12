/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#ifndef FORENSIC_KNOWLEDGEMATERIALIZER_H
#define FORENSIC_KNOWLEDGEMATERIALIZER_H

#include "attackjobspec.h"
#include "caseknowledge.h"
#include <QHash>
#include <QString>
#include <QStringList>

namespace forensic {

// The result of turning case knowledge into a mask.
struct MaskResult
{
    bool ok = false;
    QString mask;
    QString customCharset1; // set when required classes need a combined charset
    QString reason;         // why building failed (shown to the examiner)
};

/*
 * Converts CaseKnowledge into explicit hashcat inputs: a seed wordlist, a rule
 * set, and a mask. Also estimates keyspace. All outputs are inspectable files
 * or strings -- there is no hidden behavior.
 */
class KnowledgeMaterializer
{
public:
    // Distinct candidate seed words mined from base words, names, usernames,
    // email local-parts and previously recovered passwords.
    static QStringList seedWords(const CaseKnowledge &k);

    // Writes seedWords() to `path`, one per line. Returns false (with *error)
    // if nothing could be written.
    static bool writeWordlist(const CaseKnowledge &k, const QString &path, QString *error = nullptr);

    // hashcat rules covering casing, leetspeak, and appended digits/years
    // derived from the case knowledge.
    static QStringList generateRules(const CaseKnowledge &k);
    static bool writeRules(const CaseKnowledge &k, const QString &path, QString *error = nullptr);

    // Builds a mask from known prefix/suffix/positions/length/required classes.
    static MaskResult buildMask(const CaseKnowledge &k);

    // Keyspace of a mask given custom charsets (-1 = unknown/overflow).
    static qint64 maskKeyspace(const QString &mask, const QString &cs1 = {}, const QString &cs2 = {},
                               const QString &cs3 = {}, const QString &cs4 = {});

    // Lines in a file (0 if unreadable).
    static qint64 countLines(const QString &path);

    // Estimated total keyspace for a spec (-1 when not determinable).
    static qint64 estimateKeyspace(const AttackJobSpec &spec);

    // Escapes a literal string for use inside a hashcat mask ('?' -> '??').
    static QString escapeMaskLiteral(const QString &literal);

    // Parses an examiner "position:char" specification (0-based, absolute over
    // the whole password) into a knownPositions map. Accepts pairs separated by
    // comma/semicolon/whitespace, e.g. "0:P, 3:!, 5:a". Malformed pairs and
    // out-of-range/duplicate positions are ignored (last wins).
    static QHash<int, QChar> parseKnownPositions(const QString &spec);
};

} // namespace forensic

#endif // FORENSIC_KNOWLEDGEMATERIALIZER_H
