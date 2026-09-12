/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "hashcatstatusstream.h"
#include "hashcatstatusparser.h"

namespace forensic {

QVector<HashcatStatus> HashcatStatusStream::append(const QByteArray &chunk)
{
    QVector<HashcatStatus> out;
    m_buffer.append(chunk);

    int nl;
    // Only consume up to the last newline; the remainder is an incomplete line
    // that must wait for more bytes.
    while ((nl = m_buffer.indexOf('\n')) >= 0) {
        const QByteArray line = m_buffer.left(nl).trimmed();
        m_buffer.remove(0, nl + 1);
        if (line.isEmpty() || !line.startsWith('{'))
            continue;
        const HashcatStatus s = HashcatStatusParser::parse(line);
        if (s.valid)
            out.append(s);
    }
    return out;
}

} // namespace forensic
