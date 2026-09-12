/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "dependencyprobe.h"

#include "forensic/extraction/processrunner.h"

#include <QDir>
#include <QFileInfo>
#include <QStandardPaths>
#include <QStorageInfo>

namespace forensic {

DependencyProbe::DependencyProbe(ProcessRunner *runner, QString appDir, SettingLookup settings)
    : m_runner(runner)
    , m_appDir(std::move(appDir))
    , m_settings(std::move(settings))
{
}

QStringList DependencyProbe::extractorIds()
{
    return {QStringLiteral("office2john"), QStringLiteral("pdf2john"), QStringLiteral("zip2john"),
            QStringLiteral("rar2john"), QStringLiteral("7z2john"), QStringLiteral("keepass2john")};
}

namespace {

// Wraps a resolved candidate path into a ToolStatus, handling script interpreters.
void fillFromPath(ToolStatus &t, const QString &path)
{
    QFileInfo fi(path);
    if (path.endsWith(QStringLiteral(".py"))) {
        QString py = QStandardPaths::findExecutable(QStringLiteral("python3"));
        if (py.isEmpty()) py = QStandardPaths::findExecutable(QStringLiteral("python"));
        t.interpreter = QStringLiteral("python");
        t.program = py;             // may be empty -> interpreter missing
        t.prefixArgs = {fi.absoluteFilePath()};
    } else if (path.endsWith(QStringLiteral(".pl"))) {
        t.interpreter = QStringLiteral("perl");
        t.program = QStandardPaths::findExecutable(QStringLiteral("perl"));
        t.prefixArgs = {fi.absoluteFilePath()};
    } else {
        t.program = fi.absoluteFilePath();
    }
}

} // namespace

ToolStatus DependencyProbe::resolveTool(const QString &id, const QString &settingsKey) const
{
    ToolStatus t;
    t.id = id;

    // 1. Explicit settings override.
    const QString override = m_settings ? m_settings(settingsKey) : QString();
    if (!override.isEmpty() && QFileInfo::exists(override)) {
        t.source = QStringLiteral("settings");
        fillFromPath(t, override);
        t.found = !t.program.isEmpty();
        if (!t.found)
            t.detail = QStringLiteral("interpreter for %1 not found").arg(override);
        return t;
    }

    // 2. Bundled portable layout under <appDir>/tools/.
    QStringList portable;
    if (id == QStringLiteral("hashcat")) {
        portable << QDir(m_appDir).filePath(QStringLiteral("tools/hashcat/hashcat"))
                 << QDir(m_appDir).filePath(QStringLiteral("tools/hashcat/hashcat.exe"));
    } else {
        for (const QString &base : {QStringLiteral("tools/john/run/"), QStringLiteral("tools/john/")}) {
            for (const QString &ext : {QString(), QStringLiteral(".exe"),
                                       QStringLiteral(".py"), QStringLiteral(".pl")})
                portable << QDir(m_appDir).filePath(base + id + ext);
        }
    }
    for (const QString &cand : portable) {
        if (QFileInfo::exists(cand)) {
            t.source = QStringLiteral("portable");
            fillFromPath(t, cand);
            t.found = !t.program.isEmpty();
            if (!t.found)
                t.detail = QStringLiteral("interpreter for %1 not found").arg(cand);
            return t;
        }
    }

    // 3. PATH.
    const QString onPath = QStandardPaths::findExecutable(id);
    if (!onPath.isEmpty()) {
        t.source = QStringLiteral("path");
        fillFromPath(t, onPath);
        t.found = !t.program.isEmpty();
        return t;
    }

    t.detail = QStringLiteral("not found in settings, %1/tools, or PATH").arg(m_appDir);
    return t;
}

ToolStatus DependencyProbe::probeHashcat()
{
    ToolStatus t = resolveTool(QStringLiteral("hashcat"), QStringLiteral("hashcatPath"));
    if (!t.found || !m_runner)
        return t;
    // Small self-test: --version must succeed and print a version.
    const ProcessRunner::Result r = m_runner->run(t.program, {QStringLiteral("--version")},
                                                  QString(), 5000);
    t.selfTestRun = true;
    if (r.started && r.exitCode == 0) {
        t.version = r.stdOut.trimmed().split(QLatin1Char('\n')).value(0).trimmed();
        t.selfTestOk = !t.version.isEmpty();
        t.detail = QStringLiteral("self-test: --version OK");
    } else {
        t.selfTestOk = false;
        t.detail = QStringLiteral("self-test failed: %1").arg(r.started ? r.stdErr : r.error);
    }
    return t;
}

ToolStatus DependencyProbe::probeExtractor(const QString &id)
{
    // Resolution + interpreter only. We deliberately do NOT invoke *2john with a
    // dummy argument (many block waiting on input); "found" reflects a resolvable
    // program and its interpreter dependency.
    ToolStatus t = resolveTool(id, QStringLiteral("tools/") + id);
    if (t.found)
        t.detail = t.interpreter.isEmpty()
                       ? QStringLiteral("resolved (native)")
                       : QStringLiteral("resolved via %1").arg(t.interpreter);
    return t;
}

ResourceStatus DependencyProbe::probeResources() const
{
    ResourceStatus r;
    if (m_settings) {
        r.commonWordlist = m_settings(QStringLiteral("commonWordlist"));
        r.rulesDir = m_settings(QStringLiteral("rulesDir"));
        r.caseRoot = m_settings(QStringLiteral("caseRoot"));
    }
    if (r.rulesDir.isEmpty())
        r.rulesDir = QDir(m_appDir).filePath(QStringLiteral("tools/rules"));

    r.commonWordlistOk = !r.commonWordlist.isEmpty() && QFileInfo::exists(r.commonWordlist);

    QDir rd(r.rulesDir);
    if (rd.exists())
        r.rules = rd.entryList({QStringLiteral("*.rule")}, QDir::Files, QDir::Name);

    if (!r.caseRoot.isEmpty()) {
        QFileInfo fi(r.caseRoot);
        r.caseRootWritable = fi.exists() && fi.isDir() && fi.isWritable();
        QStorageInfo si(r.caseRoot);
        if (si.isValid())
            r.freeBytes = si.bytesAvailable();
    }
    return r;
}

DependencyReport DependencyProbe::run()
{
    DependencyReport rep;
    rep.hashcat = probeHashcat();
    if (rep.hashcat.found && m_runner) {
        const ProcessRunner::Result r = m_runner->run(rep.hashcat.program, {QStringLiteral("-I")},
                                                      QString(), 10000);
        if (r.started)
            rep.hashcatBackendInfo = r.stdOut.trimmed();
    }
    for (const QString &id : extractorIds())
        rep.extractors.append(probeExtractor(id));
    rep.resources = probeResources();
    return rep;
}

} // namespace forensic
