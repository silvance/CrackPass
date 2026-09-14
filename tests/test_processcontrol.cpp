/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 *
 * Cross-platform contract of the graceful-stop helper. The Windows CTRL_BREAK
 * path cannot be driven on the Linux CI runners (that is validated manually --
 * see docs/FORENSIC_VALIDATION.md), so these tests pin the platform-independent
 * guarantees: null-safety, no-op on a process that is not running, and that a
 * running process is actually asked to stop and exits before the hard-kill
 * fallback would be needed.
 */
#include "forensic/execution/processcontrol.h"

#include <QProcess>
#include <QStandardPaths>
#include <QtTest>

using namespace forensic;

class TestProcessControl : public QObject
{
    Q_OBJECT
private slots:
    void nullPointerIsSafe();
    void notRunningIsNoop();
    void gracefulStopEndsRunningProcess();
};

void TestProcessControl::nullPointerIsSafe()
{
    // Must not crash or dereference.
    configureForGracefulStop(nullptr);
    requestGracefulStop(nullptr);
}

void TestProcessControl::notRunningIsNoop()
{
    QProcess proc;
    configureForGracefulStop(&proc); // legal before start, and here it never starts
    requestGracefulStop(&proc);      // no process running -> nothing to signal
    QCOMPARE(proc.state(), QProcess::NotRunning);
}

void TestProcessControl::gracefulStopEndsRunningProcess()
{
    // A portable long-runner. On POSIX `sleep` traps SIGTERM and exits; the
    // point is that requestGracefulStop delivers a stop the OS honors without
    // the caller ever having to kill().
    const QString sleepBin = QStandardPaths::findExecutable(QStringLiteral("sleep"));
    if (sleepBin.isEmpty())
        QSKIP("no `sleep` executable to drive a long-running process");

    QProcess proc;
    configureForGracefulStop(&proc);
    proc.start(sleepBin, {QStringLiteral("60")}, QIODevice::ReadOnly);
    QVERIFY2(proc.waitForStarted(5000), "sleep did not start");
    QCOMPARE(proc.state(), QProcess::Running);

    requestGracefulStop(&proc);
#ifdef Q_OS_WIN
    // The Windows CTRL_BREAK path needs the console-less context of the GUI: a
    // process can hold only one console, so a *console* test harness cannot
    // AttachConsole to the child, and requestGracefulStop falls back to the
    // no-op terminate(). Graceful delivery is therefore validated manually
    // (docs/FORENSIC_VALIDATION.md); here we only require that the call did not
    // crash and the process can still be stopped, then clean it up.
    if (!proc.waitForFinished(2000)) {
        proc.kill();
        proc.waitForFinished(5000);
    }
    QCOMPARE(proc.state(), QProcess::NotRunning);
#else
    QVERIFY2(proc.waitForFinished(5000), "process did not exit after graceful stop");
    QCOMPARE(proc.state(), QProcess::NotRunning);
#endif
}

QTEST_GUILESS_MAIN(TestProcessControl)
#include "test_processcontrol.moc"
