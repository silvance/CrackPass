/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "toolchainservice.h"

#include "forensic/extraction/processrunner.h"
#include "forensic/hashingservice.h"

namespace forensic {

namespace {

// Best-effort engine version/banner via the injected runner. hashcat answers
// --version (exit 0, version on the first line); John and bkcrack print an
// identifying banner when run with no arguments (to stdout or stderr). Empty on
// any failure -- provenance is best-effort and never blocks a run.
QString probeEngineVersion(ProcessRunner *runner, const QString &engineId,
                           const QString &program, const QStringList &prefixArgs)
{
    if (!runner || program.isEmpty())
        return QString();

    if (engineId == QStringLiteral("hashcat")) {
        QStringList args = prefixArgs;
        args << QStringLiteral("--version");
        const ProcessRunner::Result r = runner->run(program, args, QString(), 5000);
        if (r.started && r.exitCode == 0)
            return r.stdOut.trimmed().split(QLatin1Char('\n')).value(0).trimmed();
        return QString();
    }

    // John / bkcrack: run with no extra args and scan both streams for the
    // identifying line.
    const ProcessRunner::Result r = runner->run(program, prefixArgs, QString(), 5000);
    if (!r.started)
        return QString();
    const QString needle = engineId == QStringLiteral("john")
        ? QStringLiteral("John the Ripper")
        : QStringLiteral("bkcrack");
    const QStringList lines = (r.stdOut + QLatin1Char('\n') + r.stdErr).split(QLatin1Char('\n'));
    for (const QString &l : lines) {
        const QString t = l.trimmed();
        if (t.contains(needle, Qt::CaseInsensitive))
            return t;
    }
    for (const QString &l : lines) {
        const QString t = l.trimmed();
        if (!t.isEmpty())
            return t;
    }
    return QString();
}

} // namespace

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

QString ToolchainService::engineSettingsKey(const QString &engineId)
{
    if (engineId == QStringLiteral("hashcat")) return QStringLiteral("hashcatPath");
    if (engineId == QStringLiteral("john"))    return QStringLiteral("johnPath");
    if (engineId == QStringLiteral("bkcrack")) return QStringLiteral("bkcrackPath");
    return QString();
}

ToolchainService::ResolvedEngine ToolchainService::resolveEngine(const QString &engineId) const
{
    ResolvedEngine e;
    e.engineId = engineId;
    const QString key = engineSettingsKey(engineId);
    if (key.isEmpty()) {
        e.reason = QStringLiteral("Unknown recovery engine \"%1\".").arg(engineId);
        return e;
    }
    const ToolStatus t = makeProbe().resolveTool(engineId, key);
    if (!t.found) {
        e.reason = t.detail.isEmpty()
            ? QStringLiteral("%1 was not found (configure its path in Settings).").arg(engineId)
            : t.detail;
        return e;
    }
    e.available = true;
    e.path = t.program;
    e.version = probeEngineVersion(m_runner, engineId, t.program, t.prefixArgs);
    e.sha256 = HashingService::sha256File(t.program); // best-effort provenance
    return e;
}

QString ToolchainService::resolveEnginePath(const QString &engineId) const
{
    const QString key = engineSettingsKey(engineId);
    if (key.isEmpty())
        return QString();
    const ToolStatus t = makeProbe().resolveTool(engineId, key);
    return t.found ? t.program : QString();
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
