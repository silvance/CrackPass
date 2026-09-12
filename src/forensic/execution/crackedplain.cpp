/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "crackedplain.h"

namespace forensic {

DecodedPlain classifyPlainBytes(const QByteArray &raw)
{
    DecodedPlain d;
    d.raw = raw;

    // Decide validity by round-tripping: decode as UTF-8 (invalid bytes become
    // U+FFFD) then re-encode; if it reproduces the original bytes exactly the
    // input was valid UTF-8. A plain hasError() check is not enough because a
    // truncated trailing multibyte sequence leaves the stateful decoder waiting
    // for more input rather than flagging an error.
    const QString text = QString::fromUtf8(raw);
    if (text.toUtf8() == raw) {
        d.encoding = QStringLiteral("utf-8");
        d.display = text;
    } else {
        // Not valid UTF-8: keep the exact bytes and present them in hashcat's
        // canonical, reversible $HEX[..] notation rather than a lossy decode.
        d.encoding = QStringLiteral("raw");
        d.display = QStringLiteral("$HEX[") + QString::fromLatin1(raw.toHex()) + QLatin1Char(']');
    }
    return d;
}

DecodedPlain decodeHashcatPlain(const QString &token)
{
    if (token.startsWith(QStringLiteral("$HEX[")) && token.endsWith(QLatin1Char(']'))) {
        const QString hex = token.mid(5, token.size() - 6);
        return classifyPlainBytes(QByteArray::fromHex(hex.toLatin1()));
    }
    // A bare token is printable (hashcat hex-encodes anything else), so its
    // UTF-8 bytes are the password bytes.
    return classifyPlainBytes(token.toUtf8());
}

} // namespace forensic
