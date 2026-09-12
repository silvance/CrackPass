/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef FORENSIC_HASHEXTRACTOR_H
#define FORENSIC_HASHEXTRACTOR_H

#include "artifacttype.h"
#include "evidenceitem.h"
#include "extraction/hashcatmodes.h"
#include <QString>
#include <QStringList>
#include <QVector>

namespace forensic {

class ProcessRunner;
class ToolResolver;

enum class ExtractionStatus {
    Success,          // a hash was produced
    ToolUnavailable,  // the required extraction tool is not configured/found
    NotEncrypted,     // the artifact does not appear to be password protected
    NoHashProduced,   // tool ran but emitted no recognizable hash
    Failed,           // tool failed (non-zero exit, crash, timeout)
};

// Everything an extractor needs to do its work, injected so extraction is
// testable and never touches global state.
struct ExtractionContext
{
    ProcessRunner *runner = nullptr;
    ToolResolver *tools = nullptr;
    QString workingDir;       // scratch dir for tool output (never the evidence dir)
    int timeoutMs = 120000;
};

/*
 * Outcome of an extraction attempt. The extracted hash is kept separate from
 * the evidence. `candidateModes` lists the possible hashcat modes: exactly one
 * = unambiguous; more than one = the examiner must choose (we never guess).
 */
struct ExtractionResult
{
    ExtractionStatus status = ExtractionStatus::Failed;
    QString hash;                              // normalized hashcat-ready hash line
    QVector<HashcatModeOption> candidateModes;
    QString message;                           // examiner-facing summary/error

    // Captured for troubleshooting / reproducibility.
    QString stdOut;
    QString stdErr;
    int exitCode = -1;
    QString extractorId;
    QString toolProgram;
    QStringList argv;

    bool ok() const { return status == ExtractionStatus::Success; }
    bool modeAmbiguous() const { return candidateModes.size() != 1; }
};

/*
 * Generic interface for turning an encrypted artifact into a hashcat-ready
 * hash. One implementation per artifact/extractor type. Adding a new format is
 * a new HashExtractor registered in the ExtractorRegistry -- no change to the
 * orchestration/workflow.
 */
class HashExtractor
{
public:
    virtual ~HashExtractor() = default;

    virtual QString id() const = 0;
    virtual QString displayName() const = 0;
    virtual bool supports(const ArtifactType &type) const = 0;

    // Tool id this extractor needs resolved (for coverage/preflight checks).
    virtual QString toolId() const = 0;

    virtual ExtractionResult extract(const EvidenceItem &item, const ExtractionContext &ctx) const = 0;
};

} // namespace forensic

#endif // FORENSIC_HASHEXTRACTOR_H
