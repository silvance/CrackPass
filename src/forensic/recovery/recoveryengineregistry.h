/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef FORENSIC_RECOVERYENGINEREGISTRY_H
#define FORENSIC_RECOVERYENGINEREGISTRY_H

#include "recoveryengine.h"

#include <QList>
#include <QString>
#include <memory>

namespace forensic {

/*
 * The set of recovery engines the application knows about. New engines are
 * added here (or via registerEngine); callers look one up by id to build a
 * job's argv, and the UI can enumerate the available engines.
 */
class RecoveryEngineRegistry
{
public:
    void registerEngine(std::shared_ptr<RecoveryEngine> engine);

    // The engine with this id, or nullptr if none is registered.
    const RecoveryEngine *find(const QString &id) const;

    QList<const RecoveryEngine *> engines() const;

    // Automatic engine choice for an attack: the default engine (hashcat) when
    // it can express `spec`, otherwise the first registered engine that can.
    // Returns nullptr when no engine can express the attack exactly (with
    // *reasonIfNone set to why, taken from the default engine). Lets the UI
    // offer "Automatic" without the examiner reasoning about engines.
    const RecoveryEngine *selectForSpec(const AttackJobSpec &spec,
                                        QString *reasonIfNone = nullptr) const;

    // The built-in engines. hashcat is always present and is the default.
    static RecoveryEngineRegistry withBuiltins();
    static QString defaultEngineId() { return QStringLiteral("hashcat"); }

private:
    QList<std::shared_ptr<RecoveryEngine>> m_engines;
};

} // namespace forensic

#endif // FORENSIC_RECOVERYENGINEREGISTRY_H
