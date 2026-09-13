/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "recoveryengineregistry.h"

#include "forensic/planner/attackcommandbuilder.h"
#include "forensic/planner/johncommandbuilder.h"

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

// John the Ripper. It expresses only the subset of attacks JohnCommandBuilder
// accepts (wordlist / mask / incremental); anything else is refused via
// unsupportedReason rather than approximated, so the controller can decline it.
class JohnEngine : public RecoveryEngine
{
public:
    QString id() const override { return QStringLiteral("john"); }
    QString displayName() const override { return QStringLiteral("John the Ripper"); }
    QStringList buildArgs(const AttackJobSpec &spec) const override
    {
        return JohnCommandBuilder::build(spec).args;
    }
    QString unsupportedReason(const AttackJobSpec &spec) const override
    {
        return JohnCommandBuilder::build(spec).error; // empty when supported
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
    registry.registerEngine(std::make_shared<JohnEngine>());
    return registry;
}

} // namespace forensic
