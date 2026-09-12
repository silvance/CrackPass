/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "caseworkspace.h"

#include "extraction/toolresolver.h"
#include "atomicwrite.h"
#include "hashingservice.h"


#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonArray>
#include <QRegularExpression>
#include <QUuid>

namespace forensic {

bool CaseWorkspace::appendAudit(const QString &action, const QString &entityType,
                                const QString &entityId, const QJsonObject &details, QString *error)
{
    if (!m_audit)
        return true;
    const QString actor = m_info.examiner.isEmpty() ? QStringLiteral("system") : m_info.examiner;
    if (!m_audit->append(actor, action, entityType, entityId, details)) {
        if (error)
            *error = QStringLiteral("Audit write failed: %1").arg(m_audit->lastError());
        return false;
    }
    return true;
}

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
    if (!ws->appendAudit(QStringLiteral("case_created"), QStringLiteral("case"), ci.id, details, error))
        return nullptr;

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
    if (!ws->loadExtractions(error))
        return nullptr;
    if (!ws->loadJobs(error))
        return nullptr;
    if (!ws->loadCredentials(error))
        return nullptr;

    return ws;
}

bool CaseWorkspace::writeCaseManifest(QString *error) const
{
    const QString path = QDir(m_rootPath).filePath(QStringLiteral("case.json"));
    return writeFileAtomic(path, QJsonDocument(m_info.toJson()).toJson(QJsonDocument::Indented), error);
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
    return writeFileAtomic(QDir(dir).filePath(QStringLiteral("metadata.json")),
                           QJsonDocument(item.toJson()).toJson(QJsonDocument::Indented), error);
}

IntakeResult CaseWorkspace::addEvidence(const QString &sourcePath, EvidenceStorageMode mode)
{
    EvidenceIntake intake(m_analyzers);
    IntakeResult result = intake.import(m_info.id, sourcePath);
    if (!result.ok)
        return result;

    result.item.storageMode = mode;
    if (mode == EvidenceStorageMode::WorkingCopy) {
        // Import an immutable copy into the case and verify it matches the
        // source before we rely on it. The original is never modified.
        const QString relDir = QStringLiteral("evidence/%1")
                                   .arg(result.item.id.toString(QUuid::WithoutBraces));
        const QString absDir = QDir(m_rootPath).filePath(relDir);
        if (!QDir().mkpath(absDir)) {
            result.ok = false;
            result.error = QStringLiteral("Cannot create working-copy directory: %1").arg(absDir);
            return result;
        }
        const QString rel = relDir + QStringLiteral("/source.bin");
        const QString abs = QDir(m_rootPath).filePath(rel);
        QFile::remove(abs);
        if (!QFile::copy(result.item.originalPath, abs)) {
            result.ok = false;
            result.error = QStringLiteral("Could not import working copy of %1").arg(result.item.originalPath);
            return result;
        }
        const QString copySha = HashingService::sha256File(abs);
        if (copySha != result.item.sha256) {
            result.ok = false;
            result.error = QStringLiteral("Working copy hash mismatch (copy corrupted during import).");
            return result;
        }
        result.item.workingCopyPath = rel;
    }

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
    QString aerr;
    if (!appendAudit(QStringLiteral("evidence_added"), QStringLiteral("evidence"),
                     result.item.id.toString(QUuid::WithoutBraces), details, &aerr)) {
        result.ok = false;
        result.error = aerr;
        return result;
    }

    return result;
}


EvidenceItem *CaseWorkspace::evidenceById(const QUuid &id)
{
    for (EvidenceItem &e : m_evidence) {
        if (e.id == id)
            return &e;
    }
    return nullptr;
}

EncryptionState CaseWorkspace::probeEncryption(const QUuid &evidenceId) const
{
    for (const EvidenceItem &e : m_evidence) {
        if (e.id == evidenceId)
            return EncryptionProbe::probe(e.type, e.originalPath);
    }
    return EncryptionState::Unknown;
}

bool CaseWorkspace::loadExtractions(QString *error)
{
    m_extractions.clear();
    QDir dir(extractionsDir());
    const QStringList ids = dir.entryList(QDir::Dirs | QDir::NoDotAndDotDot);
    for (const QString &id : ids) {
        const QString metaPath = dir.filePath(id + QStringLiteral("/extraction.json"));
        QFile f(metaPath);
        if (!f.open(QIODevice::ReadOnly))
            continue;
        QJsonParseError perr;
        const QJsonDocument doc = QJsonDocument::fromJson(f.readAll(), &perr);
        f.close();
        if (perr.error != QJsonParseError::NoError || !doc.isObject()) {
            if (error) *error = QStringLiteral("Corrupt extraction metadata: %1").arg(metaPath);
            return false;
        }
        m_extractions.append(Extraction::fromJson(doc.object()));
    }
    return true;
}

bool CaseWorkspace::persistExtraction(const Extraction &e, QString *error) const
{
    const QString dir = QDir(extractionsDir()).filePath(e.id.toString(QUuid::WithoutBraces));
    if (!QDir().mkpath(dir)) {
        if (error) *error = QStringLiteral("Cannot create extraction directory: %1").arg(dir);
        return false;
    }
    return writeFileAtomic(QDir(dir).filePath(QStringLiteral("extraction.json")),
                           QJsonDocument(e.toJson()).toJson(QJsonDocument::Indented), error);
}

CaseWorkspace::ExtractionOutcome CaseWorkspace::extractHash(const QUuid &evidenceId,
                                                            const ExtractionContext &ctx)
{
    ExtractionOutcome outcome;

    EvidenceItem *item = evidenceById(evidenceId);
    if (!item) {
        outcome.error = QStringLiteral("No such evidence item in this case.");
        return outcome;
    }

    HashExtractor *extractor = m_extractors.extractorFor(item->type);
    if (!extractor) {
        outcome.error = QStringLiteral("No extractor is available for artifact type '%1'.")
                            .arg(item->type.isUnknown() ? QStringLiteral("unknown") : item->type.id);
        return outcome;
    }

    // Evidence integrity gate: the artifact must still match its intake hash
    // before we read it again. On mismatch we fail loudly rather than extract
    // from altered data.
    const IntegrityResult integrity = verifyEvidenceIntegrity(evidenceId);
    if (!integrity.ok) {
        outcome.error = integrity.error;
        return outcome;
    }

    Extraction rec;
    rec.id = QUuid::createUuid();
    rec.caseId = m_info.id;
    rec.evidenceId = evidenceId;
    rec.startedUtc = QDateTime::currentDateTimeUtc();

    EvidenceItem forExtraction = *item;
    forExtraction.originalPath = evidenceReadPath(*item);
    const ExtractionResult result = extractor->extract(forExtraction, ctx);

    rec.endedUtc = QDateTime::currentDateTimeUtc();
    rec.extractorId = result.extractorId;
    rec.extractorVersion = ctx.tools ? ctx.tools->resolve(extractor->toolId()).version : QString();
    rec.toolProgram = result.toolProgram;
    rec.argv = result.argv;
    rec.status = Extraction::statusToString(result.status);
    rec.message = result.message;
    rec.exitCode = result.exitCode;
    rec.candidateModes = result.candidateModes;
    // Auto-select only when exactly one mode is possible; never guess otherwise.
    rec.selectedMode = (result.candidateModes.size() == 1) ? result.candidateModes.first().mode : 0;

    // Persist artifacts (hash separate from evidence; raw logs for troubleshooting).
    const QString dir = QDir(extractionsDir()).filePath(rec.id.toString(QUuid::WithoutBraces));
    QDir().mkpath(dir);
    const auto writeFile = [&dir](const QString &name, const QByteArray &data) -> QString {
        QFile f(QDir(dir).filePath(name));
        if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate))
            return QString();
        f.write(data);
        return name;
    };
    if (!result.hash.isEmpty())
        rec.hashArtifactPath = writeFile(QStringLiteral("hash.txt"), result.hash.toUtf8());
    rec.stdoutPath = writeFile(QStringLiteral("stdout.log"), result.stdOut.toUtf8());
    rec.stderrPath = writeFile(QStringLiteral("stderr.log"), result.stdErr.toUtf8());

    QString perr;
    if (!persistExtraction(rec, &perr)) {
        outcome.error = perr;
        return outcome;
    }
    m_extractions.append(rec);

    QJsonObject details;
    details[QStringLiteral("extractionId")] = rec.id.toString(QUuid::WithoutBraces);
    details[QStringLiteral("evidenceId")] = evidenceId.toString(QUuid::WithoutBraces);
    details[QStringLiteral("extractorId")] = rec.extractorId;
    details[QStringLiteral("status")] = rec.status;
    details[QStringLiteral("exitCode")] = rec.exitCode;
    details[QStringLiteral("selectedMode")] = static_cast<double>(rec.selectedMode);
    details[QStringLiteral("candidateModeCount")] = rec.candidateModes.size();
    QString aerr;
    if (!appendAudit(QStringLiteral("hash_extracted"), QStringLiteral("extraction"),
                     rec.id.toString(QUuid::WithoutBraces), details, &aerr)) {
        outcome.error = aerr;
        return outcome;
    }

    outcome.ok = true;
    outcome.record = rec;
    outcome.result = result;
    return outcome;
}

bool CaseWorkspace::selectExtractionMode(const QUuid &extractionId, quint32 mode, QString *error)
{
    for (Extraction &e : m_extractions) {
        if (e.id != extractionId)
            continue;
        bool valid = false;
        for (const HashcatModeOption &opt : e.candidateModes) {
            if (opt.mode == mode) { valid = true; break; }
        }
        if (!valid) {
            if (error) *error = QStringLiteral("Mode %1 is not among the candidate modes.").arg(mode);
            return false;
        }
        e.selectedMode = mode;
        QString perr;
        if (!persistExtraction(e, &perr)) {
            if (error) *error = perr;
            return false;
        }
        QJsonObject details;
        details[QStringLiteral("extractionId")] = extractionId.toString(QUuid::WithoutBraces);
        details[QStringLiteral("selectedMode")] = static_cast<double>(mode);
        if (!appendAudit(QStringLiteral("extraction_mode_selected"), QStringLiteral("extraction"),
                         extractionId.toString(QUuid::WithoutBraces), details, error))
            return false;
        return true;
    }
    if (error) *error = QStringLiteral("No such extraction.");
    return false;
}



QString CaseWorkspace::jobDir(const QUuid &jobId) const
{
    return QDir(jobsDir()).filePath(jobId.toString(QUuid::WithoutBraces));
}

bool CaseWorkspace::saveJob(const CrackingJob &job, QString *error)
{
    const QString dir = jobDir(job.id);
    if (!QDir().mkpath(dir)) {
        if (error) *error = QStringLiteral("Cannot create job directory: %1").arg(dir);
        return false;
    }
    if (!writeFileAtomic(QDir(dir).filePath(QStringLiteral("job.json")),
                         QJsonDocument(job.toJson()).toJson(QJsonDocument::Indented), error))
        return false;

    const int i = [&] {
        for (int k = 0; k < m_jobs.size(); ++k)
            if (m_jobs.at(k).id == job.id) return k;
        return -1;
    }();
    const bool isNew = (i < 0);
    if (isNew)
        m_jobs.append(job);
    else
        m_jobs[i] = job;

    if (m_audit && isNew) {
        QJsonObject details;
        details[QStringLiteral("jobId")] = job.id.toString(QUuid::WithoutBraces);
        details[QStringLiteral("evidenceId")] = job.evidenceId.toString(QUuid::WithoutBraces);
        details[QStringLiteral("hashMode")] = static_cast<double>(job.hashMode);
        details[QStringLiteral("attackMode")] = job.attackMode;
        details[QStringLiteral("hashcatArgs")] = job.hashcatArgs.join(QLatin1Char(' '));
        if (!appendAudit(QStringLiteral("job_created"), QStringLiteral("job"),
                         job.id.toString(QUuid::WithoutBraces), details, error))
            return false;
    }
    return true;
}

bool CaseWorkspace::loadJobs(QString *error)
{
    m_jobs.clear();
    QDir dir(jobsDir());
    const QStringList ids = dir.entryList(QDir::Dirs | QDir::NoDotAndDotDot);
    for (const QString &id : ids) {
        QFile f(dir.filePath(id + QStringLiteral("/job.json")));
        if (!f.open(QIODevice::ReadOnly))
            continue; // plan-* dirs and other subdirs are skipped
        QJsonParseError perr;
        const QJsonDocument doc = QJsonDocument::fromJson(f.readAll(), &perr);
        f.close();
        if (perr.error != QJsonParseError::NoError || !doc.isObject()) {
            if (error) *error = QStringLiteral("Corrupt job.json in %1").arg(id);
            return false;
        }
        m_jobs.append(CrackingJob::fromJson(doc.object()));
    }
    return true;
}

bool CaseWorkspace::addRecoveredCredential(const RecoveredCredential &cred, QString *error)
{
    RecoveredCredential c = cred;
    if (c.id.isNull())
        c.id = QUuid::createUuid();
    if (c.caseId.isEmpty())
        c.caseId = m_info.id;
    m_credentials.append(c);

    // Persist the full set as results/recovered.json.
    const QString dir = QDir(m_rootPath).filePath(QStringLiteral("results"));
    QDir().mkpath(dir);
    QJsonArray arr;
    for (const RecoveredCredential &rc : m_credentials)
        arr.append(rc.toJson());
    if (!writeFileAtomic(QDir(dir).filePath(QStringLiteral("recovered.json")),
                         QJsonDocument(arr).toJson(QJsonDocument::Indented), error))
        return false;

    if (m_audit) {
        // Record recovery metadata (not the plaintext) in the audit trail.
        QJsonObject details;
        details[QStringLiteral("credentialId")] = c.id.toString(QUuid::WithoutBraces);
        details[QStringLiteral("jobId")] = c.jobId.toString(QUuid::WithoutBraces);
        details[QStringLiteral("evidenceId")] = c.evidenceId.toString(QUuid::WithoutBraces);
        if (!appendAudit(QStringLiteral("credential_recovered"), QStringLiteral("credential"),
                         c.id.toString(QUuid::WithoutBraces), details, error))
            return false;
    }
    return true;
}

bool CaseWorkspace::loadCredentials(QString *error)
{
    m_credentials.clear();
    QFile f(QDir(m_rootPath).filePath(QStringLiteral("results/recovered.json")));
    if (!f.exists())
        return true;
    if (!f.open(QIODevice::ReadOnly)) {
        if (error) *error = QStringLiteral("Cannot read recovered.json");
        return false;
    }
    QJsonParseError perr;
    const QJsonDocument doc = QJsonDocument::fromJson(f.readAll(), &perr);
    if (perr.error != QJsonParseError::NoError || !doc.isArray()) {
        if (error) *error = QStringLiteral("Corrupt recovered.json");
        return false;
    }
    for (const QJsonValue &v : doc.array())
        m_credentials.append(RecoveredCredential::fromJson(v.toObject()));
    return true;
}


QString CaseWorkspace::evidenceReadPath(const EvidenceItem &item) const
{
    if (item.storageMode == EvidenceStorageMode::WorkingCopy && !item.workingCopyPath.isEmpty())
        return QDir(m_rootPath).filePath(item.workingCopyPath);
    return item.originalPath;
}

CaseWorkspace::IntegrityResult CaseWorkspace::verifyEvidenceIntegrity(const QUuid &evidenceId)
{
    IntegrityResult r;
    EvidenceItem *item = evidenceById(evidenceId);
    if (!item) {
        r.error = QStringLiteral("No such evidence item in this case.");
        return r;
    }
    r.recordedSha256 = item->sha256;

    const QString path = evidenceReadPath(*item);
    QString hashErr;
    const QString current = HashingService::sha256File(path, &hashErr);
    if (current.isEmpty()) {
        r.checked = false;
        r.error = QStringLiteral("Cannot read artifact to verify integrity: %1").arg(hashErr);
        QJsonObject d;
        d[QStringLiteral("evidenceId")] = evidenceId.toString(QUuid::WithoutBraces);
        d[QStringLiteral("path")] = path;
        d[QStringLiteral("reason")] = QStringLiteral("unreadable");
        appendAudit(QStringLiteral("integrity_check_failed"), QStringLiteral("evidence"),
                    evidenceId.toString(QUuid::WithoutBraces), d);
        return r;
    }

    r.checked = true;
    r.currentSha256 = current;
    r.ok = (current == item->sha256);
    if (!r.ok) {
        r.error = QStringLiteral(
            "Evidence integrity check FAILED for %1.\nRecorded SHA-256: %2\nCurrent SHA-256:  %3\n"
            "The artifact has changed since intake; refusing to proceed.")
                      .arg(item->filename, item->sha256, current);
        QJsonObject d;
        d[QStringLiteral("evidenceId")] = evidenceId.toString(QUuid::WithoutBraces);
        d[QStringLiteral("recordedSha256")] = item->sha256;
        d[QStringLiteral("currentSha256")] = current;
        appendAudit(QStringLiteral("integrity_mismatch"), QStringLiteral("evidence"),
                    evidenceId.toString(QUuid::WithoutBraces), d);
    }
    return r;
}

} // namespace forensic
