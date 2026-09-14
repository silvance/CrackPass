/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "dictionarylibrary.h"

#include "forensic/atomicwrite.h"
#include "forensic/hashingservice.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

namespace forensic {

namespace {

// Turn a display name into a filesystem/id-safe slug ("CaseKey Common" ->
// "casekey-common"). Never empty (falls back to "dictionary").
QString slugify(const QString &name)
{
    QString s;
    s.reserve(name.size());
    bool lastDash = false;
    for (const QChar c : name) {
        if (c.isLetterOrNumber()) {
            s.append(c.toLower());
            lastDash = false;
        } else if (!lastDash && !s.isEmpty()) {
            s.append(QLatin1Char('-'));
            lastDash = true;
        }
    }
    while (s.endsWith(QLatin1Char('-')))
        s.chop(1);
    return s.isEmpty() ? QStringLiteral("dictionary") : s;
}

} // namespace

void DictionaryLibrary::setBuiltinManifest(const QString &builtinManifestPath)
{
    m_builtinManifestPath = builtinManifestPath;
}

void DictionaryLibrary::setLibraryDir(const QString &libraryDir)
{
    m_libraryDir = libraryDir;
}

QString DictionaryLibrary::userManifestPath() const
{
    return m_libraryDir.isEmpty() ? QString()
                                  : QDir(m_libraryDir).filePath(QStringLiteral("manifest.json"));
}

bool DictionaryLibrary::reload(QString *error)
{
    m_entries.clear();
    loadBuiltins();
    return loadImported(error);
}

void DictionaryLibrary::loadBuiltins()
{
    if (m_builtinManifestPath.isEmpty())
        return;
    QFile f(m_builtinManifestPath);
    if (!f.open(QIODevice::ReadOnly))
        return; // no builtins available; not fatal
    const QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
    f.close();
    if (!doc.isObject())
        return;

    const QDir base = QFileInfo(m_builtinManifestPath).absoluteDir();
    const QJsonArray arr = doc.object().value(QStringLiteral("dictionaries")).toArray();
    for (const QJsonValue &v : arr) {
        const QJsonObject o = v.toObject();
        DictionaryEntry e = DictionaryEntry::fromJson(o);
        e.origin = DictionaryOrigin::Builtin;
        // The bundled manifest stores a manifest-relative "path"; resolve it to
        // an absolute path (an absolutePath field, if present, wins).
        if (e.absolutePath.isEmpty()) {
            const QString rel = o.value(QStringLiteral("path")).toString();
            if (!rel.isEmpty())
                e.absolutePath = QDir::cleanPath(base.filePath(rel));
        }
        if (!e.id.isEmpty())
            m_entries.append(e);
    }
}

bool DictionaryLibrary::loadImported(QString *error)
{
    const QString path = userManifestPath();
    if (path.isEmpty())
        return true; // no library directory configured; imported tier is empty
    QFile f(path);
    if (!f.exists())
        return true; // nothing imported yet
    if (!f.open(QIODevice::ReadOnly)) {
        if (error) *error = QStringLiteral("Cannot read dictionary manifest %1: %2")
                                .arg(path, f.errorString());
        return false;
    }
    QJsonParseError perr;
    const QJsonDocument doc = QJsonDocument::fromJson(f.readAll(), &perr);
    f.close();
    if (perr.error != QJsonParseError::NoError || !doc.isObject()) {
        if (error) *error = QStringLiteral("Malformed dictionary manifest %1: %2")
                                .arg(path, perr.errorString());
        return false;
    }
    const QJsonArray arr = doc.object().value(QStringLiteral("dictionaries")).toArray();
    for (const QJsonValue &v : arr) {
        DictionaryEntry e = DictionaryEntry::fromJson(v.toObject());
        e.origin = DictionaryOrigin::Imported;
        if (!e.id.isEmpty())
            m_entries.append(e);
    }
    return true;
}

bool DictionaryLibrary::saveImported(QString *error) const
{
    const QString path = userManifestPath();
    if (path.isEmpty()) {
        if (error) *error = QStringLiteral("No dictionary library directory is configured.");
        return false;
    }
    if (!QDir().mkpath(m_libraryDir)) {
        if (error) *error = QStringLiteral("Cannot create dictionary library directory %1").arg(m_libraryDir);
        return false;
    }
    QJsonArray arr;
    for (const DictionaryEntry &e : m_entries)
        if (e.origin == DictionaryOrigin::Imported)
            arr.append(e.toJson());
    QJsonObject root;
    root["version"] = 1;
    root["dictionaries"] = arr;
    const QByteArray data = QJsonDocument(root).toJson(QJsonDocument::Indented);
    return writeFileAtomic(path, data, error);
}

QList<DictionaryEntry> DictionaryLibrary::presentEntries() const
{
    QList<DictionaryEntry> out;
    for (const DictionaryEntry &e : m_entries)
        if (e.fileExists())
            out.append(e);
    return out;
}

bool DictionaryLibrary::contains(const QString &id) const
{
    for (const DictionaryEntry &e : m_entries)
        if (e.id == id)
            return true;
    return false;
}

DictionaryEntry DictionaryLibrary::entry(const QString &id, bool *found) const
{
    for (const DictionaryEntry &e : m_entries) {
        if (e.id == id) {
            if (found) *found = true;
            return e;
        }
    }
    if (found) *found = false;
    return {};
}

QString DictionaryLibrary::defaultEntryId() const
{
    // Prefer "CaseKey Common" when its file is present.
    for (const DictionaryEntry &e : m_entries)
        if (e.id == QLatin1String("casekey-common") && e.fileExists())
            return e.id;
    // Else the first entry whose file exists.
    for (const DictionaryEntry &e : m_entries)
        if (e.fileExists())
            return e.id;
    // Else the first declared entry (so the UI can still show it and explain
    // that its file must be supplied), else nothing.
    return m_entries.isEmpty() ? QString() : m_entries.first().id;
}

QString DictionaryLibrary::makeUniqueId(const QString &displayName) const
{
    const QString base = slugify(displayName);
    QString candidate = base;
    int n = 2;
    while (contains(candidate)) {
        candidate = QStringLiteral("%1-%2").arg(base).arg(n);
        ++n;
    }
    return candidate;
}

QString DictionaryLibrary::importWordlist(const QString &sourcePath,
                                          const QString &displayName,
                                          const QString &description,
                                          const QString &source,
                                          const QString &license,
                                          bool copyIntoLibrary,
                                          QString *error)
{
    const QFileInfo srcInfo(sourcePath);
    if (!srcInfo.exists() || !srcInfo.isFile()) {
        if (error) *error = QStringLiteral("Wordlist file does not exist: %1").arg(sourcePath);
        return {};
    }
    if (userManifestPath().isEmpty()) {
        if (error) *error = QStringLiteral("No dictionary library directory is configured.");
        return {};
    }

    QString hashError;
    const QString sha = HashingService::sha256File(srcInfo.absoluteFilePath(), &hashError);
    if (sha.isEmpty()) {
        if (error) *error = QStringLiteral("Could not hash %1: %2").arg(sourcePath, hashError);
        return {};
    }
    const qint64 count = countCandidates(srcInfo.absoluteFilePath(), error);
    if (count < 0)
        return {}; // *error already set

    DictionaryEntry e;
    e.id = makeUniqueId(displayName.isEmpty() ? srcInfo.completeBaseName() : displayName);
    e.displayName = displayName.isEmpty() ? srcInfo.fileName() : displayName;
    e.description = description;
    e.source = source;
    e.license = license;
    e.sha256 = sha;
    e.candidateCount = count;
    e.sizeBytes = srcInfo.size();
    e.origin = DictionaryOrigin::Imported;
    e.copiedIntoLibrary = copyIntoLibrary;

    if (copyIntoLibrary) {
        const QDir filesDir(QDir(m_libraryDir).filePath(QStringLiteral("files")));
        if (!QDir().mkpath(filesDir.path())) {
            if (error) *error = QStringLiteral("Cannot create %1").arg(filesDir.path());
            return {};
        }
        QString suffix = srcInfo.suffix();
        if (!suffix.isEmpty())
            suffix.prepend(QLatin1Char('.'));
        const QString dest = filesDir.filePath(e.id + suffix);
        if (QFileInfo::exists(dest)) {
            if (error) *error = QStringLiteral("A library copy already exists at %1").arg(dest);
            return {};
        }
        // QFile::copy reads the source and writes a new file; it never modifies
        // the original.
        if (!QFile::copy(srcInfo.absoluteFilePath(), dest)) {
            if (error) *error = QStringLiteral("Could not copy wordlist into the library: %1").arg(dest);
            return {};
        }
        e.absolutePath = QFileInfo(dest).absoluteFilePath();
    } else {
        e.absolutePath = srcInfo.absoluteFilePath();
    }

    m_entries.append(e);
    if (!saveImported(error)) {
        // Roll back the in-memory add (and a copy we just made) so the library
        // state matches disk.
        if (copyIntoLibrary && !e.absolutePath.isEmpty()
            && QFileInfo(e.absolutePath).absoluteFilePath().startsWith(QDir(m_libraryDir).absolutePath()))
            QFile::remove(e.absolutePath);
        m_entries.removeLast();
        return {};
    }
    return e.id;
}

bool DictionaryLibrary::removeImported(const QString &id, QString *error)
{
    int idx = -1;
    for (int i = 0; i < m_entries.size(); ++i) {
        if (m_entries.at(i).id == id) {
            idx = i;
            break;
        }
    }
    if (idx < 0) {
        if (error) *error = QStringLiteral("No such dictionary: %1").arg(id);
        return false;
    }
    const DictionaryEntry e = m_entries.at(idx);
    if (e.origin == DictionaryOrigin::Builtin) {
        if (error) *error = QStringLiteral("Built-in dictionaries cannot be removed.");
        return false;
    }

    const QString copyPath = e.absolutePath;
    m_entries.removeAt(idx);
    if (!saveImported(error))
        return false;

    // Only delete a file the library owns (a copy under the library dir); a
    // referenced original is left untouched.
    if (e.copiedIntoLibrary && !copyPath.isEmpty()
        && QDir(m_libraryDir).exists()
        && QFileInfo(copyPath).absoluteFilePath().startsWith(QDir(m_libraryDir).absolutePath())) {
        QFile::remove(copyPath);
    }
    return true;
}

DictionaryLibrary::IntegrityStatus
DictionaryLibrary::checkIntegrity(const QString &id, QString *currentSha256) const
{
    if (currentSha256)
        currentSha256->clear();
    bool found = false;
    const DictionaryEntry e = entry(id, &found);
    if (!found || !e.fileExists())
        return IntegrityStatus::Missing;
    const QString current = HashingService::sha256File(e.absolutePath);
    if (currentSha256)
        *currentSha256 = current;
    if (e.sha256.isEmpty())
        return IntegrityStatus::Unverifiable;
    return current == e.sha256 ? IntegrityStatus::Present : IntegrityStatus::Modified;
}

qint64 DictionaryLibrary::countCandidates(const QString &path, QString *error)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        if (error) *error = QStringLiteral("Cannot read wordlist %1: %2").arg(path, f.errorString());
        return -1;
    }
    qint64 count = 0;
    bool lineHasContent = false;
    char buf[1 << 16];
    qint64 n;
    while ((n = f.read(buf, sizeof(buf))) > 0) {
        for (qint64 i = 0; i < n; ++i) {
            const char c = buf[i];
            if (c == '\n') {
                if (lineHasContent)
                    ++count;
                lineHasContent = false;
            } else if (c != '\r') {
                lineHasContent = true;
            }
        }
    }
    if (n < 0) {
        if (error) *error = QStringLiteral("Error reading wordlist %1: %2").arg(path, f.errorString());
        return -1;
    }
    if (lineHasContent) // last line without a trailing newline
        ++count;
    return count;
}

QString DictionaryLibrary::integrityStatusToString(IntegrityStatus s)
{
    switch (s) {
    case IntegrityStatus::Present:      return QStringLiteral("present");
    case IntegrityStatus::Modified:     return QStringLiteral("modified");
    case IntegrityStatus::Missing:      return QStringLiteral("missing");
    case IntegrityStatus::Unverifiable: return QStringLiteral("unverifiable");
    }
    return QStringLiteral("unverifiable");
}

} // namespace forensic
