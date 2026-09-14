/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 *
 * Diagnostic integration-test runner for a disconnected forensic workstation.
 * Prints the detected toolchain and runs each corpus fixture through the full
 * chain, reporting pass/fail and the exact failure stage. No network access.
 */
#include "integrationchain.h"
#include "integrationenv.h"

#include <QCoreApplication>
#include <QFileInfo>
#include <QTemporaryDir>
#include <QTextStream>

using namespace forensic::itest;

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    QTextStream out(stdout);
    const IntegrationEnv env = IntegrationEnv::detect();

    out << "=== CaseKey integration diagnostics ===\n\n";
    out << "hashcat:\n";
    out << "  path:    " << (env.hashcat.available ? env.hashcat.program : QStringLiteral("(not found)")) << '\n';
    out << "  version: " << (env.hashcat.version.isEmpty() ? QStringLiteral("(unknown)") : env.hashcat.version) << '\n';
    out << "  backend/devices:\n";
    const QString backend = env.hashcatBackendInfo.trimmed();
    out << (backend.isEmpty() ? QStringLiteral("    (unavailable)\n")
                              : QStringLiteral("    ") + QString(backend).replace('\n', "\n    ") + '\n');

    const auto engineLine = [&out](const QString &label, const ToolInfo &t) {
        out << label << ":\n";
        out << "  path:    " << (t.available ? t.program : QStringLiteral("(not found)")) << '\n';
        out << "  version: " << (t.version.isEmpty() ? QStringLiteral("(unknown)") : t.version) << '\n';
    };
    out << '\n';
    engineLine(QStringLiteral("john"), env.john);
    engineLine(QStringLiteral("bkcrack"), env.bkcrack);

    out << "\nextraction utilities:\n";
    for (auto it = env.extractors.constBegin(); it != env.extractors.constEnd(); ++it) {
        const ToolInfo &t = it.value();
        out << "  " << it.key() << ": " << (t.available ? QStringLiteral("available") : QStringLiteral("MISSING"));
        if (t.available) {
            out << " [" << t.program << ']';
            if (!t.interpreter.isEmpty()) out << " (" << t.interpreter << ')';
        }
        out << '\n';
    }

    out << "\ncorpus: " << (env.corpusAvailable() ? env.corpusDir : QStringLiteral("(not set / no manifest)")) << '\n';
    if (!env.hashcatAvailable() || !env.corpusAvailable()) {
        out << "\nSkipping fixture runs (hashcat and/or corpus unavailable).\n";
        out.flush();
        return 0;
    }

    int passed = 0, failed = 0;
    const auto corpus = loadCorpus(env.corpusDir);

    // Run the corpus through each available password engine.
    struct EngineRun { QString id; bool available; };
    const EngineRun engines[] = {
        {QStringLiteral("hashcat"), env.hashcatAvailable()},
        {QStringLiteral("john"), env.johnAvailable()},
    };
    for (const EngineRun &eng : engines) {
        out << "\n=== fixtures (" << eng.id << ") ===\n";
        if (!eng.available) { out << "  (engine unavailable -- skipped)\n"; continue; }
        for (const FixtureSpec &fx : corpus) {
            const QString name = QFileInfo(fx.path).fileName();
            const QString tool = extractorForType(fx.expectedType);
            // John cracks the extracted hash; it has no negative-extraction row.
            if (eng.id != QStringLiteral("hashcat") && !fx.encrypted) continue;
            if (!QFileInfo::exists(fx.path)) { out << "  SKIP  " << name << " (file missing)\n"; continue; }
            if (fx.encrypted && !env.extractors.value(tool).available) {
                out << "  SKIP  " << name << " (extractor " << tool << " unavailable)\n"; continue;
            }
            QTemporaryDir caseParent;
            const ChainResult r = runChain(env, caseParent.path(), fx, tool, eng.id);
            if (r.ok) { ++passed; out << "  PASS  " << name << "  -> " << r.message << '\n'; }
            else { ++failed; out << "  FAIL  " << name << "  [stage=" << r.stage << "] " << r.message << '\n'; }
        }
    }

    // bkcrack ZipCrypto known-plaintext fixtures.
    out << "\n=== fixtures (bkcrack) ===\n";
    const auto bkcorpus = loadBkcrackCorpus(env.corpusDir);
    if (!env.bkcrackAvailable()) {
        out << "  (engine unavailable -- skipped)\n";
    } else if (bkcorpus.isEmpty()) {
        out << "  (no bkcrack fixtures in manifest)\n";
    } else {
        for (const BkcrackFixtureSpec &fx : bkcorpus) {
            const QString name = QFileInfo(fx.zipPath).fileName();
            if (!QFileInfo::exists(fx.zipPath) || !QFileInfo::exists(fx.plainFile)) {
                out << "  SKIP  " << name << " (fixture file missing)\n"; continue;
            }
            QTemporaryDir caseParent;
            const ChainResult r = runBkcrackChain(env, caseParent.path(), fx);
            if (r.ok) { ++passed; out << "  PASS  " << name << "  -> " << r.message << '\n'; }
            else { ++failed; out << "  FAIL  " << name << "  [stage=" << r.stage << "] " << r.message << '\n'; }
        }
    }

    out << "\nsummary: " << passed << " passed, " << failed << " failed\n";
    out.flush();
    return failed == 0 ? 0 : 1;
}
