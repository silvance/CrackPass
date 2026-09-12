/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "toolchainservice.h"

namespace forensic {

ToolchainService::ToolchainService(ProcessRunner *runner, QString appDir,
                                   DependencyProbe::SettingLookup settings)
    : m_runner(runner)
    , m_appDir(std::move(appDir))
    , m_settings(std::move(settings))
{
}

DependencyProbe ToolchainService::makeProbe() const
{
    return DependencyProbe(m_runner, m_appDir, m_settings);
}

ResolvedTool ToolchainService::toResolved(const ToolStatus &s)
{
    ResolvedTool t;
    t.found = s.found;
    t.program = s.program;
    t.prefixArgs = s.prefixArgs;
    t.version = s.version;
    return t;
}

DependencyReport ToolchainService::report() const
{
    return makeProbe().run();
}

ResolvedTool ToolchainService::resolveExtractor(const QString &id) const
{
    return toResolved(makeProbe().resolveTool(id, QStringLiteral("tools/") + id));
}

ToolResolver ToolchainService::extractionResolver() const
{
    ToolResolver resolver;
    const DependencyProbe probe = makeProbe();
    for (const QString &id : DependencyProbe::extractorIds())
        resolver.setTool(id, toResolved(probe.resolveTool(id, QStringLiteral("tools/") + id)));
    return resolver;
}

} // namespace forensic
