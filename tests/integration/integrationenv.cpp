/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "integrationenv.h"

#include <QDir>
#include <QFileInfo>
#include <QProcess>
#include <QProcessEnvironment>
#include <QStandardPaths>

namespace forensic { namespace itest {

namespace {

const char *const kExtractorIds[] = {"office2john", "pdf2john", "zip2john",
                                     "rar2john", "7z2john", "keepass2john",
                                     "bitlocker2john"};

// Resolve a plain engine executable from an env-var override or PATH.
ToolInfo resolveEngineExe(const QString &id, const QString &overridePath)
{
    ToolInfo t;
    t.id = id;
    QString path = overridePath;
    if (path.isEmpty())
        path = QStandardPaths::findExecutable(id);
    if (!path.isEmpty() && QFileInfo::exists(path)) {
        t.program = path;
        t.available = true;
    }
    return t;
}

QString envValue(const char *key)
{
    return QProcessEnvironment::systemEnvironment().value(QString::fromLatin1(key));
}

// Resolve a *2john tool from CASEKEY_TOOLS_DIR or PATH. Handles native
// executables and .py/.pl scripts (recording the interpreter dependency).
ToolInfo resolveExtractor(const QString &id, const QString &toolsDir)
{
    ToolInfo t;
    t.id = id;
    QStringList candidates;
    if (!toolsDir.isEmpty()) {
        for (const QString &ext : {QString(), QStringLiteral(".exe"),
                                   QStringLiteral(".py"), QStringLiteral(".pl")})
            candidates << QDir(toolsDir).filePath(id + ext);
    }
    const QString onPath = QStandardPaths::findExecutable(id);
    if (!onPath.isEmpty())
        candidates << onPath;

    for (const QString &c : candidates) {
        QFileInfo fi(c);
        if (!fi.exists() || !fi.isFile())
            continue;
        if (c.endsWith(QStringLiteral(".py"))) {
            const QString py = QStandardPaths::findExecutable(QStringLiteral("python3"));
            const QString py2 = py.isEmpty() ? QStandardPaths::findExecutable(QStringLiteral("python")) : py;
            if (py2.isEmpty())
                continue; // interpreter missing
            t.program = py2;
            t.prefixArgs = {fi.absoluteFilePath()};
            t.interpreter = QStringLiteral("python");
        } else if (c.endsWith(QStringLiteral(".pl"))) {
            const QString pl = QStandardPaths::findExecutable(QStringLiteral("perl"));
            if (pl.isEmpty())
                continue;
            t.program = pl;
            t.prefixArgs = {fi.absoluteFilePath()};
            t.interpreter = QStringLiteral("perl");
        } else {
            t.program = fi.absoluteFilePath();
        }
        t.available = true;
        break;
    }
    return t;
}

} // namespace

QString IntegrationEnv::runCapture(const QString &program, const QStringList &args,
                                   int timeoutMs, bool *ok)
{
    if (ok) *ok = false;
    QProcess p;
    p.start(program, args, QIODevice::ReadOnly);
    if (!p.waitForStarted(timeoutMs))
        return QString();
    if (!p.waitForFinished(timeoutMs)) {
        p.kill();
        p.waitForFinished(1000);
        return QString();
    }
    if (ok) *ok = (p.exitStatus() == QProcess::NormalExit);
    return QString::fromUtf8(p.readAllStandardOutput() + p.readAllStandardError());
}

IntegrationEnv IntegrationEnv::detect()
{
    IntegrationEnv env;

    QString hcPath = envValue("CASEKEY_HASHCAT");
    if (hcPath.isEmpty())
        hcPath = QStandardPaths::findExecutable(QStringLiteral("hashcat"));
    if (!hcPath.isEmpty() && QFileInfo::exists(hcPath)) {
        env.hashcat.id = QStringLiteral("hashcat");
        env.hashcat.program = hcPath;
        env.hashcat.available = true;
        bool ok = false;
        env.hashcat.version = IntegrationEnv::runCapture(hcPath, {QStringLiteral("--version")}, 5000, &ok)
                                  .trimmed().split(QLatin1Char('\n')).value(0).trimmed();
        env.hashcatBackendInfo = IntegrationEnv::runCapture(hcPath, {QStringLiteral("-I")}, 10000);
    }

    // Second cracking engine (John) and the ZipCrypto engine (bkcrack), probed
    // for their version banner when present.
    env.john = resolveEngineExe(QStringLiteral("john"), envValue("CASEKEY_JOHN"));
    if (env.john.available)
        env.john.version = IntegrationEnv::runCapture(env.john.program, {}, 5000)
                               .split(QLatin1Char('\n')).value(0).trimmed();
    env.bkcrack = resolveEngineExe(QStringLiteral("bkcrack"), envValue("CASEKEY_BKCRACK"));
    if (env.bkcrack.available)
        env.bkcrack.version = IntegrationEnv::runCapture(env.bkcrack.program, {}, 5000)
                                  .split(QLatin1Char('\n')).value(0).trimmed();

    const QString toolsDir = envValue("CASEKEY_TOOLS_DIR");
    for (const char *id : kExtractorIds)
        env.extractors.insert(QString::fromLatin1(id),
                              resolveExtractor(QString::fromLatin1(id), toolsDir));

    env.corpusDir = envValue("CASEKEY_CORPUS");
    return env;
}

bool IntegrationEnv::corpusAvailable() const
{
    return !corpusDir.isEmpty()
           && QFileInfo::exists(QDir(corpusDir).filePath(QStringLiteral("manifest.json")));
}

bool IntegrationEnv::canRun(const QString &extractorToolId) const
{
    return hashcatAvailable() && corpusAvailable()
           && extractors.value(extractorToolId).available;
}

}} // namespace forensic::itest
