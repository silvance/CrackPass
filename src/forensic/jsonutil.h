/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 *
 * Small serialization helpers shared by the forensic data models.
 * Timestamps are always stored in UTC ISO-8601 (with milliseconds) so that
 * cases remain reproducible and comparable across machines and time zones.
 */
#ifndef FORENSIC_JSONUTIL_H
#define FORENSIC_JSONUTIL_H

#include <QDateTime>
#include <QString>

namespace forensic {
namespace jsonutil {

inline QString fromDateTime(const QDateTime &dt)
{
    return dt.toUTC().toString(Qt::ISODateWithMs);
}

inline QDateTime toDateTime(const QString &s)
{
    return QDateTime::fromString(s, Qt::ISODateWithMs).toUTC();
}

} // namespace jsonutil
} // namespace forensic

#endif // FORENSIC_JSONUTIL_H
