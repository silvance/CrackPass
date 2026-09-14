/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef FORENSIC_HASHCATSTATUSPARSER_H
#define FORENSIC_HASHCATSTATUSPARSER_H

#include "hashcatstatus.h"
#include <QByteArray>

namespace forensic {

/*
 * Parses one hashcat --status-json object into a RecoveryStatus. hashcat prints
 * one JSON object per status interval; feed it a single line/object.
 */
class HashcatStatusParser
{
public:
    static RecoveryStatus parse(const QByteArray &jsonObject);

    // Scans a chunk of stdout that may contain several JSON status lines and
    // returns the most recent valid one (invalid if none).
    static RecoveryStatus parseLatest(const QByteArray &stdoutChunk);
};

} // namespace forensic

#endif // FORENSIC_HASHCATSTATUSPARSER_H
