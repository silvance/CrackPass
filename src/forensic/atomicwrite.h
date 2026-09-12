/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 *
 * Atomic whole-file writes for case state. A crash or power loss must not leave
 * case.json / job.json / extraction.json / recovered.json half-written, so
 * these use QSaveFile (write to a temp file, fsync, atomic rename).
 */
#ifndef FORENSIC_ATOMICWRITE_H
#define FORENSIC_ATOMICWRITE_H

#include <QByteArray>
#include <QSaveFile>
#include <QString>

namespace forensic {

// Atomically replaces `path` with `data`. Returns false (and, when provided,
// sets *error) without leaving a partial file behind.
inline bool writeFileAtomic(const QString &path, const QByteArray &data, QString *error = nullptr)
{
    QSaveFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        if (error) *error = QStringLiteral("Cannot open %1 for writing: %2").arg(path, f.errorString());
        return false;
    }
    if (f.write(data) != data.size()) {
        if (error) *error = QStringLiteral("Short write to %1: %2").arg(path, f.errorString());
        f.cancelWriting();
        return false;
    }
    if (!f.commit()) { // fsync + atomic rename
        if (error) *error = QStringLiteral("Could not commit %1: %2").arg(path, f.errorString());
        return false;
    }
    return true;
}

} // namespace forensic

#endif // FORENSIC_ATOMICWRITE_H
