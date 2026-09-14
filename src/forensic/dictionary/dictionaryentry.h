/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef FORENSIC_DICTIONARYENTRY_H
#define FORENSIC_DICTIONARYENTRY_H

#include <QJsonObject>
#include <QString>

namespace forensic {

// Where a dictionary came from. Builtins are declared by the bundled manifest
// that ships with CaseKey; imported ones are added by the examiner at runtime
// and recorded in the writable library manifest.
enum class DictionaryOrigin {
    Builtin,
    Imported,
};

QString dictionaryOriginToString(DictionaryOrigin origin);
DictionaryOrigin dictionaryOriginFromString(const QString &s);

/*
 * One entry in the managed dictionary library: a named wordlist the examiner
 * can select for a Dictionary attack.
 *
 * The entry carries the provenance a report needs (stable id, display name,
 * source, license) plus the integrity fields used to detect drift
 * (recorded SHA-256, candidate count, size). The recorded fields describe the
 * file as it was when imported/declared; the on-disk file may be absent (a
 * builtin whose wordlist is supplied separately) or may have changed since,
 * which the library detects by recomputing and comparing.
 */
struct DictionaryEntry
{
    QString id;          // stable identifier, e.g. "casekey-common"
    QString displayName; // "CaseKey Common"
    QString description;

    // Absolute path to the wordlist file. It may not exist yet: builtin
    // wordlists are supplied separately, so a fresh checkout has the manifest
    // but not the file.
    QString absolutePath;

    // Recorded integrity/provenance. -1 / empty means "not recorded" (e.g. a
    // builtin declared before its file is available).
    qint64 candidateCount = -1; // non-empty candidate lines
    qint64 sizeBytes = -1;
    QString sha256; // lowercase hex, or empty when unknown

    QString source;  // provenance ("Where did this wordlist come from?")
    QString license; // license / attribution obligations

    DictionaryOrigin origin = DictionaryOrigin::Builtin;

    // For an imported entry: whether the examiner asked CaseKey to copy the
    // file into the library (true) or to reference the original in place
    // (false). Referenced originals are never modified or deleted by CaseKey.
    bool copiedIntoLibrary = false;

    bool isBuiltin() const { return origin == DictionaryOrigin::Builtin; }

    // True when the wordlist file is present on disk.
    bool fileExists() const;

    QJsonObject toJson() const;
    static DictionaryEntry fromJson(const QJsonObject &obj);
};

} // namespace forensic

#endif // FORENSIC_DICTIONARYENTRY_H
