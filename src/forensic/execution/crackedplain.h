/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#ifndef FORENSIC_CRACKEDPLAIN_H
#define FORENSIC_CRACKEDPLAIN_H

#include <QString>

namespace forensic {

/*
 * Decodes one recovered-plaintext token as written by hashcat to an
 * outfile/potfile.
 *
 * We configure hashcat with a PLAIN outfile format (one plaintext per line), so
 * there is no fragile "hash:plain" split to get wrong when a password contains
 * colons or spaces. hashcat still hex-encodes any plaintext that contains the
 * separator or non-printable bytes as `$HEX[....]`; this reverses that encoding
 * and returns the literal password. Non-encoded tokens are returned unchanged.
 */
QString decodeHashcatPlain(const QString &token);

} // namespace forensic

#endif // FORENSIC_CRACKEDPLAIN_H
