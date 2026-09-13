/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 *
 * A recovery engine is a named cracking tool (hashcat, John the Ripper, ...)
 * that turns a planned attack into a command line. It is the pure, testable
 * half of engine support: it knows its identity and how to build its argv from
 * an AttackJobSpec. Running the command (process management, progress, restore)
 * is the separate JobExecutionBackend for that engine; the two are paired by
 * engine id (CrackingJob::engineId) so what a job records is what runs it.
 */
#ifndef FORENSIC_RECOVERYENGINE_H
#define FORENSIC_RECOVERYENGINE_H

#include "forensic/planner/attackjobspec.h"

#include <QString>
#include <QStringList>

namespace forensic {

class RecoveryEngine
{
public:
    virtual ~RecoveryEngine() = default;

    // Stable identifier recorded on jobs and used to route to the backend.
    virtual QString id() const = 0;
    // Human-readable name for UI/reports.
    virtual QString displayName() const = 0;
    // The engine-specific argv for this attack (without per-job session/output
    // plumbing, which the backend adds). Only meaningful when the engine can
    // express the attack (unsupportedReason is empty).
    virtual QStringList buildArgs(const AttackJobSpec &spec) const = 0;

    // Empty when this engine can express `spec` exactly; otherwise a
    // human-readable reason it cannot. Engines refuse rather than approximate,
    // so the controller can decline the job with a clear message instead of
    // running something that does not match what was planned. The default is
    // "supported" -- an engine (like hashcat) that expresses everything the
    // planner produces need not override it.
    virtual QString unsupportedReason(const AttackJobSpec &spec) const
    {
        Q_UNUSED(spec);
        return QString();
    }
};

} // namespace forensic

#endif // FORENSIC_RECOVERYENGINE_H
