/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef FORENSIC_DICTIONARYLIBRARY_H
#define FORENSIC_DICTIONARYLIBRARY_H

#include "dictionaryentry.h"

#include <QList>
#include <QString>

namespace forensic {

/*
 * A managed local library of wordlists ("dictionaries") the examiner can pick
 * for a Dictionary attack.
 *
 * Two tiers of entry:
 *   - Builtins are declared by a bundled, read-only manifest that ships with
 *     CaseKey (e.g. "CaseKey Common", "CaseKey Quick"). Their wordlist files
 *     are supplied separately, so a builtin may be present or absent on disk;
 *     the library reports which, and never fabricates password data.
 *   - Imported entries are added by the examiner at runtime and recorded in a
 *     writable manifest inside the library directory. On import the examiner
 *     chooses to copy the file into the library or to reference the original
 *     in place. Referenced originals are never modified or deleted.
 *
 * The library records each wordlist's provenance (stable id, display name,
 * source, license) and integrity fields (SHA-256, candidate count, size), so a
 * job/report can name exactly which dictionary was used and the library can
 * detect if a file has changed or gone missing since it was recorded.
 *
 * This class performs file I/O but holds no GUI dependency; it lives in the
 * forensic core so it can be unit-tested headless.
 */
class DictionaryLibrary
{
public:
    // Result of comparing a wordlist's on-disk content with what was recorded.
    enum class IntegrityStatus {
        Present,      // file present and its SHA-256 matches the recorded value
        Modified,     // file present but its SHA-256 differs from the recorded one
        Missing,      // file is not on disk
        Unverifiable, // file present but no SHA-256 was recorded to compare against
    };

    DictionaryLibrary() = default;

    // The bundled read-only manifest declaring the builtins. Entry file paths
    // in it are resolved relative to this manifest's directory.
    void setBuiltinManifest(const QString &builtinManifestPath);
    // The writable directory holding the imported-entry manifest
    // (<dir>/manifest.json) and any copied wordlists (<dir>/files/).
    void setLibraryDir(const QString &libraryDir);

    // (Re)read both manifests. Returns false only on a fatal user-manifest
    // read/parse error (a missing user manifest is not an error); a
    // missing/malformed builtin manifest simply yields no builtins.
    bool reload(QString *error = nullptr);

    QList<DictionaryEntry> entries() const { return m_entries; }
    // Only entries whose wordlist file currently exists on disk.
    QList<DictionaryEntry> presentEntries() const;

    bool contains(const QString &id) const;
    DictionaryEntry entry(const QString &id, bool *found = nullptr) const;

    // The dictionary a Dictionary attack should default to: "CaseKey Common"
    // when present, else the first present entry, else the first entry, else
    // empty. Deliberately requires no case knowledge from the examiner.
    QString defaultEntryId() const;

    // Import a wordlist into the library. Computes its SHA-256 and candidate
    // count, records the supplied provenance/license, and either copies the
    // file into the library (copyIntoLibrary=true) or references the original
    // in place. The source file is never modified. Returns the new entry's id,
    // or an empty string on failure (with *error set).
    QString importWordlist(const QString &sourcePath,
                           const QString &displayName,
                           const QString &description,
                           const QString &source,
                           const QString &license,
                           bool copyIntoLibrary,
                           QString *error = nullptr);

    // Remove an imported entry. Deletes a library-owned copy; never deletes a
    // referenced original. Refuses to remove a builtin (returns false).
    bool removeImported(const QString &id, QString *error = nullptr);

    // Recompute the entry's on-disk SHA-256 and compare it with the recorded
    // value. When provided, *currentSha256 receives the freshly computed digest
    // (empty if the file is missing).
    IntegrityStatus checkIntegrity(const QString &id, QString *currentSha256 = nullptr) const;

    // Recompute an entry's SHA-256, candidate count and size from the file on
    // disk and, for an IMPORTED entry, record them as the new baseline (so a
    // deliberately updated wordlist is trusted again). A builtin's baseline
    // lives in the read-only bundled manifest, so its recorded values are not
    // changed -- the freshly computed values are returned via the out-params for
    // display only. Returns false (with *error) when the file is missing/unreadable
    // or persisting an imported entry failed.
    bool revalidate(const QString &id, qint64 *candidateCountOut = nullptr,
                    QString *sha256Out = nullptr, QString *error = nullptr);

    // Number of candidate lines (non-empty lines) in a wordlist file. Streams
    // the file read-only. Returns -1 on error (with *error set).
    static qint64 countCandidates(const QString &path, QString *error = nullptr);

    static QString integrityStatusToString(IntegrityStatus s);

private:
    void loadBuiltins();
    bool loadImported(QString *error);
    bool saveImported(QString *error) const;
    QString makeUniqueId(const QString &displayName) const;
    QString userManifestPath() const;

    QString m_builtinManifestPath;
    QString m_libraryDir;
    QList<DictionaryEntry> m_entries; // builtins first, then imported
};

} // namespace forensic

#endif // FORENSIC_DICTIONARYLIBRARY_H
