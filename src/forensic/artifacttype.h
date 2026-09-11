/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#ifndef FORENSIC_ARTIFACTTYPE_H
#define FORENSIC_ARTIFACTTYPE_H

#include <QString>

namespace forensic {

/*
 * The result of identifying a submitted artifact. `id` is a stable, machine
 * readable token (e.g. "pdf", "zip", "keepass-kdbx"); `displayName` is for the
 * examiner. `confidence` is 0.0-1.0. An unidentified artifact is represented by
 * ArtifactType::unknown().
 */
struct ArtifactType
{
    QString id;
    QString displayName;
    double confidence = 0.0;

    bool isUnknown() const { return id.isEmpty() || id == QStringLiteral("unknown"); }

    static ArtifactType unknown()
    {
        return ArtifactType{QStringLiteral("unknown"), QStringLiteral("Unknown / unrecognized"), 0.0};
    }

    bool operator==(const ArtifactType &o) const
    {
        return id == o.id && displayName == o.displayName && qFuzzyCompare(confidence + 1.0, o.confidence + 1.0);
    }
};

} // namespace forensic

#endif // FORENSIC_ARTIFACTTYPE_H
