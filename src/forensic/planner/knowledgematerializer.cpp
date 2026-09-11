/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#include "knowledgematerializer.h"

#include <QFile>
#include <QSet>
#include <QTextStream>

namespace forensic {

namespace {

void appendUnique(QStringList &out, QSet<QString> &seen, const QString &word)
{
    const QString w = word.trimmed();
    if (w.isEmpty() || seen.contains(w))
        return;
    seen.insert(w);
    out << w;
}

// Size of a built-in mask class token (?l etc.); 0 if not a built-in class.
int builtinClassSize(QChar token)
{
    switch (token.unicode()) {
    case 'l': return 26;
    case 'u': return 26;
    case 'd': return 10;
    case 's': return 33;
    case 'a': return 95;
    case 'b': return 256;
    case 'h': return 16;
    case 'H': return 16;
    default:  return 0;
    }
}

// Number of distinct characters a custom-charset string represents. A charset
// may embed built-in class tokens (e.g. "?l?d" -> 26 + 10 = 36); other bytes
// count as one character each ('??' is a literal '?').
int charsetSize(const QString &cs)
{
    int size = 0;
    int i = 0;
    while (i < cs.size()) {
        if (cs.at(i) == QLatin1Char('?') && i + 1 < cs.size()) {
            const int cls = builtinClassSize(cs.at(i + 1));
            size += (cls > 0) ? cls : 1; // '??' -> literal '?'
            i += 2;
        } else {
            size += 1;
            i += 1;
        }
    }
    return size;
}

// Size of a single mask token (?l etc.), custom charset (?1..?4), or literal.
int tokenSize(QChar token, const QString &cs1, const QString &cs2, const QString &cs3, const QString &cs4)
{
    const int cls = builtinClassSize(token);
    if (cls > 0)
        return cls;
    switch (token.unicode()) {
    case '1': return charsetSize(cs1);
    case '2': return charsetSize(cs2);
    case '3': return charsetSize(cs3);
    case '4': return charsetSize(cs4);
    default:  return 1; // '??' literal question mark
    }
}

} // namespace

QString KnowledgeMaterializer::escapeMaskLiteral(const QString &literal)
{
    QString out;
    out.reserve(literal.size());
    for (const QChar c : literal)
        out += (c == QLatin1Char('?')) ? QStringLiteral("??") : QString(c);
    return out;
}

QStringList KnowledgeMaterializer::seedWords(const CaseKnowledge &k)
{
    QStringList out;
    QSet<QString> seen;
    const auto add = [&](const QStringList &src) {
        for (const QString &w : src)
            appendUnique(out, seen, w);
    };
    add(k.baseWords);
    add(k.names);
    add(k.usernames);
    add(k.previousPasswords);
    // Email local-parts (before '@') are useful base words.
    for (const QString &email : k.emails) {
        const int at = email.indexOf(QLatin1Char('@'));
        appendUnique(out, seen, at > 0 ? email.left(at) : email);
    }
    return out;
}

bool KnowledgeMaterializer::writeWordlist(const CaseKnowledge &k, const QString &path, QString *error)
{
    const QStringList words = seedWords(k);
    if (words.isEmpty()) {
        if (error) *error = QStringLiteral("No case words available to build a wordlist.");
        return false;
    }
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
        if (error) *error = QStringLiteral("Cannot write wordlist: %1").arg(f.errorString());
        return false;
    }
    QTextStream out(&f);
    for (const QString &w : words)
        out << w << '\n';
    return true;
}

QStringList KnowledgeMaterializer::generateRules(const CaseKnowledge &k)
{
    QStringList rules;
    QSet<QString> seen;
    const auto add = [&](const QString &r) {
        if (!seen.contains(r)) { seen.insert(r); rules << r; }
    };

    // Casing / identity.
    add(QStringLiteral(":"));   // as-is
    add(QStringLiteral("c"));   // Capitalize
    add(QStringLiteral("u"));   // UPPER
    add(QStringLiteral("l"));   // lower
    add(QStringLiteral("t"));   // toggle case

    // Common leetspeak substitutions.
    add(QStringLiteral("so0"));
    add(QStringLiteral("sa@"));
    add(QStringLiteral("se3"));
    add(QStringLiteral("si1"));
    add(QStringLiteral("ss$"));

    // Common appended digits/specials.
    add(QStringLiteral("$1"));
    add(QStringLiteral("$1$2$3"));
    add(QStringLiteral("$1$2$3$4"));
    add(QStringLiteral("$!"));
    add(QStringLiteral("c $!"));

    // Append each year in the range as digit-append rules (e.g. 2021 -> $2$0$2$1).
    if (k.yearFrom > 0 && k.yearTo >= k.yearFrom && (k.yearTo - k.yearFrom) <= 200) {
        for (int y = k.yearFrom; y <= k.yearTo; ++y) {
            const QString ys = QString::number(y);
            QString rule;
            for (const QChar d : ys)
                rule += QLatin1Char('$') + QString(d);
            add(rule);
            add(QStringLiteral("c ") + rule); // Capitalized + year
        }
    }
    return rules;
}

bool KnowledgeMaterializer::writeRules(const CaseKnowledge &k, const QString &path, QString *error)
{
    const QStringList rules = generateRules(k);
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
        if (error) *error = QStringLiteral("Cannot write rules: %1").arg(f.errorString());
        return false;
    }
    QTextStream out(&f);
    for (const QString &r : rules)
        out << r << '\n';
    return true;
}

MaskResult KnowledgeMaterializer::buildMask(const CaseKnowledge &k)
{
    MaskResult result;

    // Choose the wildcard token for unknown positions from required classes.
    QString wildcard;
    QString cs1;
    const bool lower = k.requiredClasses.testFlag(CharClass::Lower);
    const bool upper = k.requiredClasses.testFlag(CharClass::Upper);
    const bool digit = k.requiredClasses.testFlag(CharClass::Digit);
    const bool special = k.requiredClasses.testFlag(CharClass::Special);
    const int classCount = (lower ? 1 : 0) + (upper ? 1 : 0) + (digit ? 1 : 0) + (special ? 1 : 0);

    if (classCount == 0) {
        wildcard = QStringLiteral("?a"); // all printable
    } else if (classCount == 1) {
        if (lower) wildcard = QStringLiteral("?l");
        else if (upper) wildcard = QStringLiteral("?u");
        else if (digit) wildcard = QStringLiteral("?d");
        else wildcard = QStringLiteral("?s");
    } else {
        // Combine required classes into custom charset 1.
        if (lower) cs1 += QStringLiteral("?l");
        if (upper) cs1 += QStringLiteral("?u");
        if (digit) cs1 += QStringLiteral("?d");
        if (special) cs1 += QStringLiteral("?s");
        wildcard = QStringLiteral("?1");
        result.customCharset1 = cs1;
    }

    const int prefixLen = k.knownPrefix.size();
    const int suffixLen = k.knownSuffix.size();

    // Determine total password length.
    int total = -1;
    if (k.maxLength > 0)
        total = k.maxLength;
    else if (!k.knownPositions.isEmpty()) {
        int maxPos = -1;
        for (auto it = k.knownPositions.constBegin(); it != k.knownPositions.constEnd(); ++it)
            maxPos = qMax(maxPos, it.key());
        total = qMax(maxPos + 1, prefixLen + suffixLen);
    } else if (k.minLength > 0) {
        total = k.minLength;
    }

    if (total < 0) {
        result.reason = QStringLiteral(
            "Not enough structure to build a mask. Provide a length (min/max) or "
            "known character positions.");
        return result;
    }
    if (total < prefixLen + suffixLen) {
        result.reason = QStringLiteral("Known prefix and suffix are longer than the password length.");
        return result;
    }

    QString mask = escapeMaskLiteral(k.knownPrefix);
    for (int pos = prefixLen; pos < total - suffixLen; ++pos) {
        if (k.knownPositions.contains(pos))
            mask += escapeMaskLiteral(QString(k.knownPositions.value(pos)));
        else
            mask += wildcard;
    }
    mask += escapeMaskLiteral(k.knownSuffix);

    result.ok = true;
    result.mask = mask;
    return result;
}

qint64 KnowledgeMaterializer::maskKeyspace(const QString &mask, const QString &cs1, const QString &cs2,
                                           const QString &cs3, const QString &cs4)
{
    if (mask.isEmpty())
        return -1;
    const qint64 kOverflowCap = 1000000000000000000LL; // 1e18
    qint64 product = 1;
    int i = 0;
    while (i < mask.size()) {
        int size = 1;
        if (mask.at(i) == QLatin1Char('?') && i + 1 < mask.size()) {
            size = tokenSize(mask.at(i + 1), cs1, cs2, cs3, cs4);
            i += 2;
        } else {
            i += 1; // literal
        }
        if (size <= 0)
            return -1;
        if (product > kOverflowCap / size)
            return -1; // would overflow / astronomically large
        product *= size;
    }
    return product;
}

qint64 KnowledgeMaterializer::countLines(const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
        return 0;
    qint64 lines = 0;
    QTextStream in(&f);
    while (!in.atEnd()) {
        const QString line = in.readLine();
        if (!line.isEmpty())
            ++lines;
    }
    return lines;
}

qint64 KnowledgeMaterializer::estimateKeyspace(const AttackJobSpec &spec)
{
    const auto wordlistLines = [&]() -> qint64 {
        qint64 total = 0;
        for (const QString &w : spec.wordlists)
            total += countLines(w);
        return total;
    };
    const auto ruleCount = [&]() -> qint64 {
        qint64 total = 0;
        for (const QString &r : spec.rules)
            total += countLines(r);
        return total;
    };

    switch (spec.attackMode) {
    case AttackModeNum::BruteForceMask:
        return maskKeyspace(spec.mask, spec.customCharset1, spec.customCharset2,
                            spec.customCharset3, spec.customCharset4);
    case AttackModeNum::Straight: {
        const qint64 wl = wordlistLines();
        if (wl <= 0)
            return -1;
        const qint64 rc = qMax<qint64>(1, ruleCount());
        return wl * rc;
    }
    case AttackModeNum::HybridWordMask:
    case AttackModeNum::HybridMaskWord: {
        const qint64 wl = wordlistLines();
        const qint64 ms = maskKeyspace(spec.mask, spec.customCharset1, spec.customCharset2,
                                       spec.customCharset3, spec.customCharset4);
        if (wl <= 0 || ms < 0)
            return -1;
        return wl * ms;
    }
    default:
        return -1;
    }
}

} // namespace forensic
