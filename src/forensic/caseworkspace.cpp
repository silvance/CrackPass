/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#include "caseworkspace.h"

#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QUuid>

namespace forensic {

namespace {

QString sanitizeName(const QString &name)
{
    QString s = name;
    s.replace(QRegularExpression(QStringLiteral("[^A-Za-z0-9._-]+")), QStringLiteral("_"));
    s = s.trimmed();
    if (s.isEmpty())
        s = QStringLiteral("case");
    return s;
}

const QStringList &subdirs()
{
    static const QStringList dirs = {
        QStringLiteral("evidence"), QStringLiteral("extractions"),
        QStringLiteral("jobs"), QStringLiteral("results"),
        QStringLiteral("reports"), QStringLiteral("logs"),
    };
    return dirs;
}

} // namespace

QString CaseWorkspace::evidenceDir() const    { return QDir(m_rootPath).filePath(QStringLiteral("evidence")); }
QString CaseWorkspace::jobsDir() const        { return QDir(m_rootPath).filePath(QStringLiteral("jobs")); }
QString CaseWorkspace::extractionsDir() const { return QDir(m_rootPath).filePath(QStringLiteral("extractions")); }
QString CaseWorkspace::reportsDir() const     { return QDir(m_rootPath).filePath(QStringLiteral("reports")); }
QString CaseWorkspace::logsDir() const        { return QDir(m_rootPath).filePath(QStringLiteral("logs")); }

std::unique_ptr<CaseWorkspace> CaseWorkspace::create(const QString &parentDir, const CaseInfo &info,
                                                     QString *error)
{
    CaseInfo ci = info;
    if (ci.id.isEmpty())
        ci.id = QUuid::createUuid().toString(QUuid::WithoutBraces);
    if (!ci.createdUtc.isValid())
        ci.createdUtc = QDateTime::currentDateTimeUtc();

    const QString shortId = ci.id.left(8);
    const QString dirName = QStringLiteral("%1__%2").arg(sanitizeName(ci.name), shortId);
    const QString root = QDir(parentDir).filePath(dirName);

    QDir parent(parentDir);
    if (!parent.exists() && !parent.mkpath(QStringLiteral("."))) {
        if (error) *error = QStringLiteral("Cannot create parent directory: %1").arg(parentDir);
        return nullptr;
    }
    if (QDir(root).exists()) {
        if (error) *error = QStringLiteral("Case directory already exists: %1").arg(root);
        return nullptr;
    }
    if (!QDir().mkpath(root)) {
        if (error) *error = QStringLiteral("Cannot create case directory: %1").arg(root);
        return nullptr;
    }

    auto ws = std::unique_ptr<CaseWorkspace>(new CaseWorkspace());
    ws->m_rootPath = root;
    ws->m_info = ci;

    for (const QString &d : subdirs()) {
        if (!QDir(root).mkpath(d)) {
            if (error) *error = QStringLiteral("Cannot create subdirectory: %1").arg(d);
            return nullptr;
        }
    }

    if (!ws->writeCaseManifest(error))
        return nullptr;

    ws->m_audit = std::make_unique<AuditLog>(QDir(ws->logsDir()).filePath(QStringLiteral("audit.log.jsonl")));

    QJsonObject details;
    details[QStringLiteral("name")] = ci.name;
    details[QStringLiteral("examiner")] = ci.examiner;
    ws->m_audit->append(ci.examiner.isEmpty() ? QStringLiteral("system") : ci.examiner,
                        QStringLiteral("case_created"), QStringLiteral("case"), ci.id, details);

    return ws;
}

std::unique_ptr<CaseWorkspace> CaseWorkspace::open(const QString &caseDir, QString *error)
{
    const QString manifestPath = QDir(caseDir).filePath(QStringLiteral("case.json"));
    QFile f(manifestPath);
    if (!f.open(QIODevice::ReadOnly)) {
        if (error) *error = QStringLiteral("Not a case directory (missing case.json): %1").arg(caseDir);
        return nullptr;
    }
    QJsonParseError perr;
    const QJsonDocument doc = QJsonDocument::fromJson(f.readAll(), &perr);
    f.close();
    if (perr.error != QJsonParseError::NoError || !doc.isObject()) {
        if (error) *error = QStringLiteral("Corrupt case.json: %1").arg(perr.errorString());
        return nullptr;
    }

    auto ws = std::unique_ptr<CaseWorkspace>(new CaseWorkspace());
    ws->m_rootPath = caseDir;
    ws->m_info = CaseInfo::fromJson(doc.object());
    ws->m_audit = std::make_unique<AuditLog>(QDir(ws->logsDir()).filePath(QStringLiteral("audit.log.jsonl")));
    if (!ws->m_audit->load(error))
        return nullptr;
    if (!ws->loadEvidence(error))
        return nullptr;

    return ws;
}

bool CaseWorkspace::writeCaseManifest(QString *error) const
{
    const QString path = QDir(m_rootPath).filePath(QStringLiteral("case.json"));
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        if (error) *error = QStringLiteral("Cannot write case.json: %1").arg(f.errorString());
        return false;
    }
    f.write(QJsonDocument(m_info.toJson()).toJson(QJsonDocument::Indented));
    return true;
}

bool CaseWorkspace::loadEvidence(QString *error)
{
    m_evidence.clear();
    QDir dir(evidenceDir());
    const QStringList ids = dir.entryList(QDir::Dirs | QDir::NoDotAndDotDot);
    for (const QString &id : ids) {
        const QString metaPath = dir.filePath(id + QStringLiteral("/metadata.json"));
        QFile f(metaPath);
        if (!f.open(QIODevice::ReadOnly))
            continue;
        QJsonParseError perr;
        const QJsonDocument doc = QJsonDocument::fromJson(f.readAll(), &perr);
        f.close();
        if (perr.error != QJsonParseError::NoError || !doc.isObject()) {
            if (error) *error = QStringLiteral("Corrupt evidence metadata: %1").arg(metaPath);
            return false;
        }
        m_evidence.append(EvidenceItem::fromJson(doc.object()));
    }
    return true;
}

bool CaseWorkspace::persistEvidence(const EvidenceItem &item, QString *error) const
{
    const QString dir = QDir(evidenceDir()).filePath(item.id.toString(QUuid::WithoutBraces));
    if (!QDir().mkpath(dir)) {
        if (error) *error = QStringLiteral("Cannot create evidence directory: %1").arg(dir);
        return false;
    }
    QFile f(QDir(dir).filePath(QStringLiteral("metadata.json")));
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        if (error) *error = QStringLiteral("Cannot write evidence metadata: %1").arg(f.errorString());
        return false;
    }
    f.write(QJsonDocument(item.toJson()).toJson(QJsonDocument::Indented));
    return true;
}

IntakeResult CaseWorkspace::addEvidence(const QString &sourcePath)
{
    EvidenceIntake intake(m_analyzers);
    IntakeResult result = intake.import(m_info.id, sourcePath);
    if (!result.ok)
        return result;

    QString err;
    if (!persistEvidence(result.item, &err)) {
        result.ok = false;
        result.error = err;
        return result;
    }

    m_evidence.append(result.item);

    QJsonObject details;
    details[QStringLiteral("evidenceId")] = result.item.id.toString(QUuid::WithoutBraces);
    details[QStringLiteral("filename")] = result.item.filename;
    details[QStringLiteral("originalPath")] = result.item.originalPath;
    details[QStringLiteral("size")] = static_cast<double>(result.item.size);
    details[QStringLiteral("sha256")] = result.item.sha256;
    details[QStringLiteral("artifactType")] = result.item.type.id;
    if (m_audit) {
        m_audit->append(m_info.examiner.isEmpty() ? QStringLiteral("system") : m_info.examiner,
                        QStringLiteral("evidence_added"), QStringLiteral("evidence"),
                        result.item.id.toString(QUuid::WithoutBraces), details);
    }

    return result;
}

} // namespace forensic
