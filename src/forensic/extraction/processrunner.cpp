/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#include "processrunner.h"

#include <QProcess>

namespace forensic {

ProcessRunner::Result QtProcessRunner::run(const QString &program, const QStringList &args,
                                           const QString &workingDir, int timeoutMs)
{
    Result result;
    QProcess proc;
    if (!workingDir.isEmpty())
        proc.setWorkingDirectory(workingDir);
    proc.setProgram(program);
    proc.setArguments(args);
    proc.start(QIODevice::ReadOnly);

    if (!proc.waitForStarted(timeoutMs)) {
        result.error = QStringLiteral("Failed to start '%1': %2").arg(program, proc.errorString());
        return result;
    }
    if (!proc.waitForFinished(timeoutMs)) {
        proc.kill();
        proc.waitForFinished(2000);
        result.timedOut = true;
        result.error = QStringLiteral("Tool '%1' timed out").arg(program);
        return result;
    }

    result.started = true;
    result.exitCode = proc.exitCode();
    result.stdOut = QString::fromUtf8(proc.readAllStandardOutput());
    result.stdErr = QString::fromUtf8(proc.readAllStandardError());
    return result;
}

} // namespace forensic
