/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#include "hashingservice.h"

#include <QCryptographicHash>
#include <QFile>

namespace forensic {

QString HashingService::sha256File(const QString &path, QString *error)
{
    QFile file(path);
    // ReadOnly only: we must never modify submitted evidence.
    if (!file.open(QIODevice::ReadOnly)) {
        if (error)
            *error = QStringLiteral("Cannot open '%1' for reading: %2").arg(path, file.errorString());
        return QString();
    }

    QCryptographicHash hash(QCryptographicHash::Sha256);
    while (!file.atEnd()) {
        const QByteArray chunk = file.read(ChunkSize);
        if (chunk.isEmpty() && file.error() != QFile::NoError) {
            if (error)
                *error = QStringLiteral("Read error on '%1': %2").arg(path, file.errorString());
            return QString();
        }
        hash.addData(chunk);
    }

    return QString::fromLatin1(hash.result().toHex());
}

} // namespace forensic
