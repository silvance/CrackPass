/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef FORENSIC_MODERESOLUTION_H
#define FORENSIC_MODERESOLUTION_H

#include "hashcatmodes.h"
#include <QString>
#include <QVector>

namespace forensic {
namespace modes {

/*
 * Map a normalized *2john-style hash string to candidate hashcat modes.
 *
 * These functions are the testable heart of mode determination: they inspect
 * the hash signature/fields and return one option (unambiguous) or several
 * (the examiner must choose). An empty result means "unrecognized signature".
 * They never fall back to a single arbitrary guess when the signature is
 * genuinely ambiguous.
 */
QVector<HashcatModeOption> forOffice(const QString &hash);
QVector<HashcatModeOption> forPdf(const QString &hash);
QVector<HashcatModeOption> forZip(const QString &hash);
QVector<HashcatModeOption> forRar(const QString &hash);
QVector<HashcatModeOption> forSevenZip(const QString &hash);
QVector<HashcatModeOption> forKeePass(const QString &hash);

} // namespace modes
} // namespace forensic

#endif // FORENSIC_MODERESOLUTION_H
