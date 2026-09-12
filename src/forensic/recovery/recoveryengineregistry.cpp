/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "recoveryengineregistry.h"

#include "forensic/planner/attackcommandbuilder.h"

namespace forensic {

namespace {

// The built-in hashcat engine: argv comes straight from the existing
// AttackCommandBuilder, so the hashcat path is behaviourally unchanged.
class HashcatEngine : public RecoveryEngine
{
public:
    QString id() const override { return QStringLiteral("hashcat"); }
    QString displayName() const override { return QStringLiteral("hashcat"); }
    QStringList buildArgs(const AttackJobSpec &spec) const override
    {
        return AttackCommandBuilder::buildArgs(spec);
    }
};

} // namespace

void RecoveryEngineRegistry::registerEngine(std::shared_ptr<RecoveryEngine> engine)
{
    if (engine)
        m_engines.append(std::move(engine));
}

const RecoveryEngine *RecoveryEngineRegistry::find(const QString &id) const
{
    for (const auto &e : m_engines) {
        if (e->id() == id)
            return e.get();
    }
    return nullptr;
}

QList<const RecoveryEngine *> RecoveryEngineRegistry::engines() const
{
    QList<const RecoveryEngine *> out;
    for (const auto &e : m_engines)
        out.append(e.get());
    return out;
}

RecoveryEngineRegistry RecoveryEngineRegistry::withBuiltins()
{
    RecoveryEngineRegistry registry;
    registry.registerEngine(std::make_shared<HashcatEngine>());
    return registry;
}

} // namespace forensic
