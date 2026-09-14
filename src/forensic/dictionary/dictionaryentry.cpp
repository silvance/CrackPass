/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "dictionaryentry.h"

#include <QFileInfo>

namespace forensic {

QString dictionaryOriginToString(DictionaryOrigin origin)
{
    switch (origin) {
    case DictionaryOrigin::Builtin:  return QStringLiteral("builtin");
    case DictionaryOrigin::Imported: return QStringLiteral("imported");
    }
    return QStringLiteral("builtin");
}

DictionaryOrigin dictionaryOriginFromString(const QString &s)
{
    return s == QLatin1String("imported") ? DictionaryOrigin::Imported
                                          : DictionaryOrigin::Builtin;
}

bool DictionaryEntry::fileExists() const
{
    return !absolutePath.isEmpty() && QFileInfo::exists(absolutePath);
}

QJsonObject DictionaryEntry::toJson() const
{
    QJsonObject o;
    o["id"] = id;
    o["displayName"] = displayName;
    o["description"] = description;
    o["absolutePath"] = absolutePath;
    o["candidateCount"] = static_cast<double>(candidateCount);
    o["sizeBytes"] = static_cast<double>(sizeBytes);
    o["sha256"] = sha256;
    o["source"] = source;
    o["license"] = license;
    o["origin"] = dictionaryOriginToString(origin);
    o["copiedIntoLibrary"] = copiedIntoLibrary;
    return o;
}

DictionaryEntry DictionaryEntry::fromJson(const QJsonObject &obj)
{
    DictionaryEntry e;
    e.id = obj.value("id").toString();
    e.displayName = obj.value("displayName").toString();
    e.description = obj.value("description").toString();
    e.absolutePath = obj.value("absolutePath").toString();
    // "path" is the manifest-relative spelling used by the bundled builtin
    // manifest; the library resolves it to an absolute path on load.
    e.candidateCount = obj.contains("candidateCount")
        ? static_cast<qint64>(obj.value("candidateCount").toDouble(-1))
        : -1;
    e.sizeBytes = obj.contains("sizeBytes")
        ? static_cast<qint64>(obj.value("sizeBytes").toDouble(-1))
        : -1;
    e.sha256 = obj.value("sha256").toString();
    e.source = obj.value("source").toString();
    e.license = obj.value("license").toString();
    e.origin = dictionaryOriginFromString(obj.value("origin").toString());
    e.copiedIntoLibrary = obj.value("copiedIntoLibrary").toBool(false);
    return e;
}

} // namespace forensic
