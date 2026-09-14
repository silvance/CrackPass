/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "processcontrol.h"

#include <QProcess>

#ifdef Q_OS_WIN
#  include <qt_windows.h>
#endif

namespace forensic {

void configureForGracefulStop(QProcess *proc)
{
    if (!proc)
        return;
#ifdef Q_OS_WIN
    // Launch the engine as the leader of a NEW process group. A directed console
    // CTRL_BREAK (see requestGracefulStop) can then reach the engine's group by
    // its pid without also hitting the GUI. CREATE_NEW_PROCESS_GROUP disables
    // CTRL_C for the child by default, but CTRL_BREAK is still delivered -- which
    // is exactly what we send. We OR the flag in rather than replacing, so any
    // flags Qt already set are preserved.
    proc->setCreateProcessArgumentsModifier(
        [](QProcess::CreateProcessArguments *args) {
            args->flags |= CREATE_NEW_PROCESS_GROUP;
        });
#else
    Q_UNUSED(proc);
#endif
}

void requestGracefulStop(QProcess *proc)
{
    if (!proc || proc->state() == QProcess::NotRunning)
        return;

#ifdef Q_OS_WIN
    // QProcess::terminate() posts WM_CLOSE, useless for a console engine. Deliver
    // a console CTRL_BREAK to the engine's process group instead. This GUI has no
    // console of its own, so we temporarily attach to the engine's console,
    // ignore the event for ourselves while attached (so we do not get torn down),
    // signal the group, then detach. Every step is best-effort: if any fails we
    // fall back to terminate() and, ultimately, the caller's hard kill.
    const qint64 pid = proc->processId();
    if (pid > 0) {
        // Detach from any console we might hold, then attach to the child's.
        FreeConsole();
        if (AttachConsole(static_cast<DWORD>(pid))) {
            // Do not let the event we are about to raise terminate this GUI.
            SetConsoleCtrlHandler(nullptr, TRUE);
            const BOOL sent = GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT,
                                                       static_cast<DWORD>(pid));
            FreeConsole();
            SetConsoleCtrlHandler(nullptr, FALSE);
            if (sent)
                return; // graceful signal delivered; caller's timer still guards
        }
    }
    // Fallback if the console dance did not deliver the event.
    proc->terminate();
#else
    // POSIX: SIGTERM, which hashcat and John trap to save their session.
    proc->terminate();
#endif
}

} // namespace forensic
