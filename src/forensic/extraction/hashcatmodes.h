/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#ifndef FORENSIC_HASHCATMODES_H
#define FORENSIC_HASHCATMODES_H

#include <QJsonObject>
#include <QString>

namespace forensic {

// One candidate hashcat mode (-m value) with a human label. Extractors return
// a list of these; a list of size 1 is unambiguous, >1 means the examiner must
// choose (we never silently guess).
struct HashcatModeOption
{
    quint32 mode = 0;
    QString name;

    QJsonObject toJson() const
    {
        QJsonObject o;
        o[QStringLiteral("mode")] = static_cast<double>(mode);
        o[QStringLiteral("name")] = name;
        return o;
    }
    static HashcatModeOption fromJson(const QJsonObject &o)
    {
        return HashcatModeOption{static_cast<quint32>(o.value(QStringLiteral("mode")).toDouble()),
                                 o.value(QStringLiteral("name")).toString()};
    }
    bool operator==(const HashcatModeOption &o) const { return mode == o.mode && name == o.name; }
};

} // namespace forensic

#endif // FORENSIC_HASHCATMODES_H
