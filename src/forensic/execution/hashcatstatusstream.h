/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#ifndef FORENSIC_HASHCATSTATUSSTREAM_H
#define FORENSIC_HASHCATSTATUSSTREAM_H

#include "hashcatstatus.h"
#include <QByteArray>
#include <QVector>

namespace forensic {

/*
 * Stateful reassembler for hashcat's --status-json output.
 *
 * QProcess stdout is a byte stream: a single JSON status record can be split
 * across several readyReadStandardOutput() deliveries, and multiple records can
 * arrive in one. This buffer retains any partial trailing line until its
 * terminating newline arrives, so no record is ever parsed half-formed and none
 * is lost across reads. hashcat prints one compact JSON object per line.
 */
class HashcatStatusStream
{
public:
    // Feed raw bytes; returns every complete, valid status object newly parsed.
    QVector<HashcatStatus> append(const QByteArray &chunk);

    // Bytes buffered but not yet terminated by a newline (for diagnostics/tests).
    int pendingBytes() const { return m_buffer.size(); }

private:
    QByteArray m_buffer;
};

} // namespace forensic

#endif // FORENSIC_HASHCATSTATUSSTREAM_H
