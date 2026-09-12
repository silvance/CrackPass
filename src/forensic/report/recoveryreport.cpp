/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "recoveryreport.h"

#include <QJsonArray>

namespace forensic {

QJsonObject RecoveryReport::toJson() const
{
    const auto arr = [](const QStringList &l) {
        QJsonArray a;
        for (const QString &s : l) a.append(s);
        return a;
    };

    QJsonObject artifact;
    artifact[QStringLiteral("filename")] = artifactFilename;
    artifact[QStringLiteral("path")] = artifactPath;
    artifact[QStringLiteral("size")] = static_cast<double>(artifactSize);
    artifact[QStringLiteral("sha256")] = artifactSha256;
    artifact[QStringLiteral("modifiedUtc")] = artifactModifiedUtc;
    artifact[QStringLiteral("createdUtc")] = artifactCreatedUtc;
    artifact[QStringLiteral("detectedType")] = detectedType;

    QJsonObject extraction;
    extraction[QStringLiteral("extractorId")] = extractorId;
    extraction[QStringLiteral("extractorVersion")] = extractorVersion;
    extraction[QStringLiteral("status")] = extractionStatus;

    QJsonObject attack;
    attack[QStringLiteral("hashMode")] = static_cast<double>(hashMode);
    attack[QStringLiteral("hashModeName")] = hashModeName;
    attack[QStringLiteral("attackMode")] = attackMode;
    attack[QStringLiteral("strategy")] = attackStrategy;
    attack[QStringLiteral("wordlists")] = arr(wordlists);
    attack[QStringLiteral("rules")] = arr(rules);
    attack[QStringLiteral("mask")] = mask;
    attack[QStringLiteral("hashcatArgs")] = arr(hashcatArgs);

    QJsonObject env;
    env[QStringLiteral("hashcatVersion")] = hashcatVersion;
    env[QStringLiteral("devices")] = arr(devices);

    QJsonObject outcome;
    outcome[QStringLiteral("startedUtc")] = startedUtc;
    outcome[QStringLiteral("endedUtc")] = endedUtc;
    outcome[QStringLiteral("runtimeMs")] = static_cast<double>(runtimeMs);
    outcome[QStringLiteral("finalStatus")] = finalStatus;

    QJsonObject credential;
    credential[QStringLiteral("recovered")] = recovered;
    if (recovered) {
        credential[QStringLiteral("plaintext")] = recoveredPlaintext;
        credential[QStringLiteral("encoding")] = recoveredEncoding;
        credential[QStringLiteral("hash")] = recoveredHash;
        credential[QStringLiteral("recoveredUtc")] = recoveredUtc;
    }

    QJsonObject root;
    root[QStringLiteral("applicationVersion")] = applicationVersion;
    root[QStringLiteral("generatedUtc")] = generatedUtc;
    root[QStringLiteral("caseId")] = caseId;
    root[QStringLiteral("caseName")] = caseName;
    root[QStringLiteral("examiner")] = examiner;
    root[QStringLiteral("artifact")] = artifact;
    root[QStringLiteral("extraction")] = extraction;
    root[QStringLiteral("hashcat")] = env;
    root[QStringLiteral("attack")] = attack;
    root[QStringLiteral("outcome")] = outcome;
    root[QStringLiteral("credential")] = credential;
    return root;
}

} // namespace forensic
