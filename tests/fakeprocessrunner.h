/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 *
 * Test double for ProcessRunner: returns a preset result and records how it
 * was called. Never launches a process or touches the filesystem, so tests use
 * only synthetic inputs and never require the real *2john tools.
 */
#ifndef FORENSIC_TEST_FAKEPROCESSRUNNER_H
#define FORENSIC_TEST_FAKEPROCESSRUNNER_H

#include "forensic/extraction/processrunner.h"

class FakeProcessRunner : public forensic::ProcessRunner
{
public:
    Result nextResult;
    QString lastProgram;
    QStringList lastArgs;
    QString lastWorkingDir;
    int calls = 0;

    Result run(const QString &program, const QStringList &args,
               const QString &workingDir, int) override
    {
        ++calls;
        lastProgram = program;
        lastArgs = args;
        lastWorkingDir = workingDir;
        return nextResult;
    }

    static Result ok(const QString &stdOut, int exitCode = 0)
    {
        Result r;
        r.started = true;
        r.exitCode = exitCode;
        r.stdOut = stdOut;
        return r;
    }
};

#endif // FORENSIC_TEST_FAKEPROCESSRUNNER_H
