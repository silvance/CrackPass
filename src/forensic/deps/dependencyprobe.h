/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 *
 * Discovers and health-checks the external forensic toolchain for the
 * "Dependency Doctor". Resolution order for every tool is: explicit settings
 * override -> bundled portable layout (<appDir>/tools/...) -> PATH. All probing
 * is offline; the ProcessRunner is injected so this is unit-testable.
 */
#ifndef FORENSIC_DEPENDENCYPROBE_H
#define FORENSIC_DEPENDENCYPROBE_H

#include <QHash>
#include <QString>
#include <QStringList>
#include <functional>

namespace forensic {

class ProcessRunner;

struct ToolStatus
{
    QString id;
    bool found = false;
    QString source;        // "settings" | "portable" | "path" | ""
    QString program;       // resolved program (interpreter or native tool)
    QStringList prefixArgs;// script path when run via an interpreter
    QString interpreter;   // "python" | "perl" | "" (native)
    QString version;       // best-effort; may be empty
    bool selfTestRun = false;
    bool selfTestOk = false;
    QString detail;        // human-readable note
};

struct ResourceStatus
{
    QString commonWordlist;
    bool commonWordlistOk = false;
    QString rulesDir;
    QStringList rules;      // rule files discovered
    QString caseRoot;
    bool caseRootWritable = false;
    qint64 freeBytes = -1;  // free space at the case root (-1 unknown)
};

struct DependencyReport
{
    ToolStatus hashcat;
    QString hashcatBackendInfo;   // raw `hashcat -I` output (devices)
    QList<ToolStatus> extractors; // office2john, pdf2john, ...
    ResourceStatus resources;
};

class DependencyProbe
{
public:
    using SettingLookup = std::function<QString(const QString &)>;

    DependencyProbe(ProcessRunner *runner, QString appDir, SettingLookup settings);

    DependencyReport run();

    // Exposed for testing: resolve a tool by id (hashcat or an extractor id).
    ToolStatus resolveTool(const QString &id, const QString &settingsKey) const;

    static QStringList extractorIds();

private:
    ToolStatus probeHashcat();
    ToolStatus probeExtractor(const QString &id);
    ResourceStatus probeResources() const;

    ProcessRunner *m_runner;
    QString m_appDir;
    SettingLookup m_settings;
};

} // namespace forensic

#endif // FORENSIC_DEPENDENCYPROBE_H
