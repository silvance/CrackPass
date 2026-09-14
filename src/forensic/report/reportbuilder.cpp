/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "reportbuilder.h"

#include "forensic/caseworkspace.h"
#include "forensic/planner/attackjobspec.h"

#include <QDateTime>

namespace forensic {

RecoveryReport ReportBuilder::build(const CaseWorkspace &ws, const CrackingJob &job,
                                    const QString &applicationVersion, bool includePlaintext)
{
    RecoveryReport r;
    r.applicationVersion = applicationVersion;
    r.generatedUtc = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);

    r.caseId = ws.info().id;
    r.caseName = ws.info().name;
    r.examiner = ws.info().examiner;

    // Artifact
    for (const EvidenceItem &e : ws.evidence()) {
        if (e.id == job.evidenceId) {
            r.artifactFilename = e.filename;
            r.artifactPath = e.originalPath;
            r.artifactSize = e.size;
            r.artifactSha256 = e.sha256;
            r.artifactModifiedUtc = e.modifiedUtc.toString(Qt::ISODateWithMs);
            r.artifactCreatedUtc = e.createdUtc.toString(Qt::ISODateWithMs);
            r.detectedType = e.type.isUnknown() ? QStringLiteral("Unknown") : e.type.displayName;
            break;
        }
    }

    // Extraction (latest successful for this artifact) + resolved hash-mode name.
    for (const Extraction &ex : ws.extractions()) {
        if (ex.evidenceId != job.evidenceId)
            continue;
        r.extractorId = ex.extractorId;
        r.extractorVersion = ex.extractorVersion.isEmpty() ? QStringLiteral("(not recorded)")
                                                           : ex.extractorVersion;
        r.extractionStatus = ex.status;
        for (const HashcatModeOption &m : ex.candidateModes)
            if (m.mode == job.hashMode)
                r.hashModeName = m.name;
    }

    // Attack
    r.hashMode = job.hashMode;
    r.attackMode = job.attackMode;
    r.attackStrategy = attackModeName(job.attackMode);
    r.wordlists = job.wordlists;
    r.rules = job.rules;
    r.mask = job.mask;
    r.engineArgs = job.engineArgs;

    // Managed dictionary used (Dictionary attack only).
    if (job.dictionary.isSet()) {
        r.dictionaryId = job.dictionary.id;
        r.dictionaryName = job.dictionary.displayName;
        r.dictionaryPath = job.dictionary.path;
        r.dictionarySha256 = job.dictionary.sha256;
        r.dictionaryCandidateCount = job.dictionary.candidateCount;
    }

    // Recovery engine environment (engine-neutral: hashcat / John / bkcrack).
    r.engineId = job.engineId;
    r.engineDisplayName = job.engineDisplayName.isEmpty() ? job.engineId : job.engineDisplayName;
    r.engineVersion = job.engineVersion.isEmpty() ? QStringLiteral("(not recorded)")
                                                  : job.engineVersion;
    r.enginePath = job.enginePath;
    r.engineExeSha256 = job.engineExeSha256;
    for (const ComputeDevice &d : job.devices)
        r.devices << QStringLiteral("#%1 %2 (%3)").arg(d.id).arg(d.name, d.backend);
    if (r.devices.isEmpty())
        r.devices << QStringLiteral("(not recorded)");

    // Timing / outcome
    r.startedUtc = job.startedUtc.toString(Qt::ISODateWithMs);
    r.endedUtc = job.endedUtc.toString(Qt::ISODateWithMs);
    r.runtimeMs = job.runtimeMs();
    r.finalStatus = jobStateToString(job.state);

    // Recovered credential (last one for this job)
    for (const RecoveredCredential &c : ws.recoveredCredentials()) {
        if (c.jobId == job.id) {
            r.recovered = true;
            r.recoveredKind = resultKindNoun(c.kind);
            r.recoveredPlaintext = includePlaintext ? c.plaintext : QStringLiteral("[REDACTED]");
            r.recoveredEncoding = c.encoding;
            r.recoveredHash = c.hash;
            r.recoveredUtc = c.recoveredUtc.toString(Qt::ISODateWithMs);
        }
    }

    return r;
}

} // namespace forensic
