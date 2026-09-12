/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef FORENSIC_CRACKEDPLAIN_H
#define FORENSIC_CRACKEDPLAIN_H

#include <QByteArray>
#include <QString>

namespace forensic {

/*
 * A recovered password decoded losslessly from hashcat output.
 *
 * A password is a sequence of bytes, and not every byte sequence is valid
 * UTF-8 (a Latin-1 or otherwise non-Unicode password is perfectly legal). A
 * forensic record must preserve the EXACT bytes so the examiner can reproduce
 * and verify the password, so we keep the raw bytes verbatim and derive a
 * best-effort display string separately -- never the other way around.
 */
struct DecodedPlain
{
    QByteArray raw;      // the exact recovered password bytes (lossless)
    QString display;     // UTF-8 text when the bytes are valid UTF-8, else the
                         // canonical, reversible $HEX[..] form
    QString encoding;    // "utf-8" when display is the decoded text, else "raw"
};

/*
 * Decodes one recovered-plaintext token as written by hashcat to an
 * outfile/potfile.
 *
 * We configure hashcat with a PLAIN outfile format (one plaintext per line), so
 * there is no fragile "hash:plain" split to get wrong when a password contains
 * colons or spaces. hashcat still hex-encodes any plaintext that contains the
 * separator or non-printable bytes as `$HEX[....]`; this reverses that encoding
 * to the raw bytes. A non-encoded token is taken as its literal bytes.
 */
DecodedPlain decodeHashcatPlain(const QString &token);

// Classifies raw password bytes into a display string + encoding tag, using the
// same rule as decodeHashcatPlain (valid UTF-8 -> text, otherwise $HEX[..]).
DecodedPlain classifyPlainBytes(const QByteArray &raw);

} // namespace forensic

#endif // FORENSIC_CRACKEDPLAIN_H
