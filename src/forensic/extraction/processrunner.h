/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef FORENSIC_PROCESSRUNNER_H
#define FORENSIC_PROCESSRUNNER_H

#include <QString>
#include <QStringList>

namespace forensic {

/*
 * Abstraction over launching an external, read-only extraction tool. Injected
 * so extractors can be unit-tested with a fake runner (no real tools, no
 * touching evidence).
 */
class ProcessRunner
{
public:
    struct Result {
        bool started = false;   // false => program could not be launched
        int exitCode = -1;
        QString stdOut;
        QString stdErr;
        QString error;          // launch/timeout error, when started == false
        bool timedOut = false;
    };

    virtual ~ProcessRunner() = default;

    virtual Result run(const QString &program, const QStringList &args,
                       const QString &workingDir, int timeoutMs) = 0;
};

// Real implementation backed by QProcess.
class QtProcessRunner : public ProcessRunner
{
public:
    Result run(const QString &program, const QStringList &args,
               const QString &workingDir, int timeoutMs) override;
};

} // namespace forensic

#endif // FORENSIC_PROCESSRUNNER_H
