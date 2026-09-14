/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 *
 * Cross-platform helpers for stopping a running recovery engine *gracefully* --
 * i.e. giving it the chance to flush its resumable checkpoint (hashcat's
 * .restore session, John's .rec session) before it exits, so a paused job can
 * later resume where it left off instead of restarting from zero.
 *
 * The graceful stop is inherently platform-specific and best-effort:
 *
 *   POSIX  -- QProcess::terminate() sends SIGTERM, which hashcat and John trap
 *             to save their session. This already worked; requestGracefulStop()
 *             simply calls terminate() here.
 *
 *   Windows -- QProcess::terminate() posts WM_CLOSE, which a *console* engine
 *             has no window to receive, so it is a no-op and the job would only
 *             ever be hard-killed -- losing the checkpoint. Instead we deliver a
 *             console CTRL_BREAK to the engine's own process group. hashcat and
 *             John install console-control handlers that checkpoint and exit on
 *             that event. For the signal to reach *only* the engine (never the
 *             GUI), the engine must have been started in a NEW process group;
 *             configureForGracefulStop() arranges that before launch.
 *
 * In BOTH cases the caller keeps a hard-kill fallback (QProcess::kill) on a
 * grace timer: if the engine does not exit in time it is killed and no
 * checkpoint is guaranteed. This helper only makes the *graceful* attempt; it
 * never blocks and never kills.
 *
 * This is deliberately not covered by the automated test suite: the Windows
 * path cannot be exercised on the Linux CI runners, and driving real console
 * control events is out of scope for the unit tests. It is validated manually
 * on Windows (see docs/FORENSIC_VALIDATION.md).
 */
#ifndef FORENSIC_PROCESSCONTROL_H
#define FORENSIC_PROCESSCONTROL_H

class QProcess;

namespace forensic {

// Call BEFORE QProcess::start(). On Windows, arranges for the child to run in
// its own process group so a directed console CTRL_BREAK reaches only it and
// its children. No-op on POSIX.
void configureForGracefulStop(QProcess *proc);

// Best-effort graceful stop of the running process so it can flush its
// resumable checkpoint. POSIX: SIGTERM. Windows: console CTRL_BREAK to the
// process group. Does not block, does not kill; the caller keeps the hard-kill
// fallback. Safe to call with a null or already-exited process.
void requestGracefulStop(QProcess *proc);

} // namespace forensic

#endif // FORENSIC_PROCESSCONTROL_H
