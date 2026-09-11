/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#include "john2hashextractor.h"

#include "processrunner.h"
#include "toolresolver.h"

namespace forensic {

QString John2HashExtractor::normalizeHashLine(const QString &stdOut)
{
    const QStringList lines = stdOut.split(QLatin1Char('\n'), Qt::SkipEmptyParts);
    for (const QString &raw : lines) {
        const QString line = raw.trimmed();
        // The target hashes all begin with '$...'. Take from the first '$' so
        // the leading "<filename>:" is stripped regardless of path contents.
        const int dollar = line.indexOf(QLatin1Char('$'));
        if (dollar >= 0)
            return line.mid(dollar);
    }
    return QString();
}

ExtractionResult John2HashExtractor::extract(const EvidenceItem &item, const ExtractionContext &ctx) const
{
    ExtractionResult result;
    result.extractorId = id();

    if (!ctx.runner || !ctx.tools) {
        result.status = ExtractionStatus::Failed;
        result.message = QStringLiteral("Extraction context is not configured.");
        return result;
    }

    const ResolvedTool tool = ctx.tools->resolve(toolId());
    if (!tool.found || tool.program.isEmpty()) {
        result.status = ExtractionStatus::ToolUnavailable;
        result.message = QStringLiteral(
            "The extraction tool '%1' is not configured. Set its path in settings "
            "(offline John the Ripper Jumbo utility).").arg(toolId());
        return result;
    }

    QStringList args = tool.prefixArgs;
    args << item.originalPath; // read-only input; the tool never writes to it

    result.toolProgram = tool.program;
    result.argv = args;

    const ProcessRunner::Result run = ctx.runner->run(tool.program, args, ctx.workingDir, ctx.timeoutMs);
    result.stdOut = run.stdOut;
    result.stdErr = run.stdErr;
    result.exitCode = run.exitCode;

    if (!run.started) {
        result.status = ExtractionStatus::Failed;
        result.message = run.error.isEmpty()
            ? QStringLiteral("Could not run extraction tool '%1'.").arg(tool.program)
            : run.error;
        return result;
    }

    const QString hash = normalizeHashLine(run.stdOut);
    if (hash.isEmpty()) {
        // No hash: either not encrypted, or the tool reported an error.
        result.status = ExtractionStatus::NoHashProduced;
        result.message = run.stdErr.trimmed().isEmpty()
            ? QStringLiteral("No hash was produced. The file may not be password protected.")
            : QStringLiteral("No hash was produced. Tool reported:\n%1").arg(run.stdErr.trimmed());
        return result;
    }

    result.hash = hash;
    result.candidateModes = resolveModes(hash);
    result.status = ExtractionStatus::Success;
    if (result.candidateModes.isEmpty()) {
        result.message = QStringLiteral(
            "A hash was extracted but its hashcat mode could not be determined "
            "automatically. Please select the mode manually.");
    } else if (result.modeAmbiguous()) {
        result.message = QStringLiteral(
            "A hash was extracted. Multiple hashcat modes are possible; please "
            "choose the correct one.");
    } else {
        result.message = QStringLiteral("Hash extracted successfully.");
    }
    return result;
}

} // namespace forensic
