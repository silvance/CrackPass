/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 *
 * The single authoritative view of the external toolchain. The Dependency
 * Doctor (health report) and hash extraction (which tool to actually run) MUST
 * agree: it is a forensic hazard for the Doctor to report a tool as available
 * from one location while extraction silently runs a different one, or fails to
 * find it at all. Both therefore go through this service, which resolves every
 * tool with the same order (settings override -> bundled portable layout ->
 * PATH) and the same interpreter handling (a .py/.pl script run via
 * python/perl) that DependencyProbe uses.
 */
#ifndef FORENSIC_TOOLCHAINSERVICE_H
#define FORENSIC_TOOLCHAINSERVICE_H

#include "dependencyprobe.h"
#include "forensic/extraction/toolresolver.h"

#include <QString>

namespace forensic {

class ProcessRunner;

class ToolchainService
{
public:
    // `runner` is used only for the health report's self-tests (may be null when
    // only resolution is needed); `appDir` and `settings` mirror DependencyProbe.
    ToolchainService(ProcessRunner *runner, QString appDir, DependencyProbe::SettingLookup settings);

    // The authoritative resolution of a recovery ENGINE (hashcat / john /
    // bkcrack): the executable actually launched, its version banner and a
    // SHA-256 of that executable. Same resolution order as everything else
    // (settings override -> bundled portable layout -> PATH). This is the single
    // place engine paths/versions are resolved, so what a job records and what
    // the Dependency Doctor reports cannot drift from what runs.
    struct ResolvedEngine
    {
        QString engineId;
        bool available = false;
        QString path;     // resolved executable
        QString version;  // best-effort version/banner (may be empty)
        QString sha256;   // SHA-256 of the executable (empty if unreadable)
        QString reason;   // why unavailable, when !available
    };
    ResolvedEngine resolveEngine(const QString &engineId) const;

    // Just the resolved executable path for an engine (no version probe, no
    // hashing, no process launched) -- used to construct the execution backend
    // at startup with the SAME resolution the provenance path uses, so the two
    // cannot diverge. Empty when the engine is not found.
    QString resolveEnginePath(const QString &engineId) const;

    // The settings key holding an engine's configured path, or empty for an
    // unknown engine id.
    static QString engineSettingsKey(const QString &engineId);

    // Full health report for the Dependency Doctor.
    DependencyReport report() const;

    // Resolve a single extractor id (e.g. "office2john") to an invocation.
    ResolvedTool resolveExtractor(const QString &id) const;

    // The resolver hash extraction uses -- built from the SAME resolution as the
    // report, so what the Doctor shows is exactly what extraction runs.
    ToolResolver extractionResolver() const;

    // Maps a resolved DependencyProbe ToolStatus into an extraction ResolvedTool.
    static ResolvedTool toResolved(const ToolStatus &s);

private:
    DependencyProbe makeProbe() const;

    ProcessRunner *m_runner;
    QString m_appDir;
    DependencyProbe::SettingLookup m_settings;
};

} // namespace forensic

#endif // FORENSIC_TOOLCHAINSERVICE_H
