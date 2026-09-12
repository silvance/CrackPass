/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#include "crackedplain.h"

#include <QByteArray>

namespace forensic {

QString decodeHashcatPlain(const QString &token)
{
    if (token.startsWith(QStringLiteral("$HEX[")) && token.endsWith(QLatin1Char(']'))) {
        const QString hex = token.mid(5, token.size() - 6);
        const QByteArray bytes = QByteArray::fromHex(hex.toLatin1());
        // hashcat $HEX payloads are the raw password bytes; decode as UTF-8.
        return QString::fromUtf8(bytes);
    }
    return token;
}

} // namespace forensic
