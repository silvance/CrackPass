/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#ifndef FORENSIC_TOOLRESOLVER_H
#define FORENSIC_TOOLRESOLVER_H

#include <QHash>
#include <QString>
#include <QStringList>

namespace forensic {

// A resolved external tool: how to invoke it. `prefixArgs` handles interpreted
// tools (e.g. {"python"} for a *.py, or {} for a native binary/wrapper).
struct ResolvedTool
{
    bool found = false;
    QString program;
    QStringList prefixArgs;
    QString version;   // best-effort; may be empty
};

/*
 * Resolves extractor tool ids (e.g. "office2john") to an invocation. Backed by
 * an explicit map so it works fully offline and is trivially testable. In the
 * app this map is populated from settings / a bundled tools directory.
 */
class ToolResolver
{
public:
    void setTool(const QString &toolId, const ResolvedTool &tool) { m_tools.insert(toolId, tool); }
    ResolvedTool resolve(const QString &toolId) const { return m_tools.value(toolId); }
    bool has(const QString &toolId) const { return m_tools.value(toolId).found; }

private:
    QHash<QString, ResolvedTool> m_tools;
};

} // namespace forensic

#endif // FORENSIC_TOOLRESOLVER_H
