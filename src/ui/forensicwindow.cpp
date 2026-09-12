/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#include "forensicwindow.h"

#include "forensic/caseworkspace.h"
#include "forensic/evidenceitem.h"
#include "forensic/extraction/encryptionprobe.h"
#include "forensic/extraction/processrunner.h"
#include "forensic/extraction/toolresolver.h"
#include "forensic/extraction/extraction.h"
#include "attackplannerdialog.h"
#include "forensic/crackingjob.h"
#include "forensic/recoveredcredential.h"
#include "forensic/execution/jobqueue.h"
#include "forensic/execution/hashcatexecutionbackend.h"
#include "forensic/execution/hashcatstatus.h"
#include "forensic/planner/attackcommandbuilder.h"
#include "forensic/report/reportbuilder.h"
#include "forensic/report/reportrenderer.h"
#include "config.h"
#include "settingsmanager.h"

#include <QApplication>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QLocale>
#include <QMessageBox>
#include <QProcess>
#include <QPushButton>
#include <QHBoxLayout>
#include <QTabWidget>
#include <QTableWidget>
#include <QToolBar>
#include <QDateTime>
#include <QDesktopServices>
#include <QUrl>
#include <QVBoxLayout>
#include <QWidget>

using forensic::CaseWorkspace;
using forensic::EvidenceItem;
using forensic::CrackingJob;
using forensic::JobQueue;
using forensic::HashcatExecutionBackend;
using forensic::JobState;

namespace {

// Tool ids used by the built-in extractors. The examiner configures a path for
// each in settings (fully offline; no downloads).
const char *const kToolIds[] = {"office2john", "pdf2john", "zip2john",
                                "rar2john", "7z2john", "keepass2john"};

forensic::ToolResolver buildToolResolver()
{
    forensic::ToolResolver resolver;
    auto &settings = SettingsManager::instance();
    for (const char *id : kToolIds) {
        const QString key = QStringLiteral("tools/") + QString::fromLatin1(id);
        const QString path = settings.getKey<QString>(key);
        if (!path.isEmpty())
            resolver.setTool(QString::fromLatin1(id), forensic::ResolvedTool{true, path, {}, QString()});
    }
    return resolver;
}

QString probeHashcatVersion(const QString &path)
{
    if (path.isEmpty())
        return QString();
    QProcess p;
    p.start(path, {QStringLiteral("--version")}, QIODevice::ReadOnly);
    if (!p.waitForStarted(3000))
        return QString();
    if (!p.waitForFinished(5000)) {
        p.kill();
        p.waitForFinished(1000);
        return QString();
    }
    return QString::fromUtf8(p.readAllStandardOutput()).trimmed()
        .split(QLatin1Char('\n')).value(0).trimmed();
}

} // namespace

ForensicWindow::ForensicWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setWindowTitle(tr("CrackPass - Forensic Mode"));
    resize(1000, 520);

    auto *toolbar = addToolBar(tr("Case"));
    toolbar->setMovable(false);
    connect(toolbar->addAction(tr("New Case...")), &QAction::triggered, this, &ForensicWindow::newCase);
    connect(toolbar->addAction(tr("Open Case...")), &QAction::triggered, this, &ForensicWindow::openCase);
    toolbar->addSeparator();
    connect(toolbar->addAction(tr("Add Artifact...")), &QAction::triggered, this, &ForensicWindow::addArtifact);
    connect(toolbar->addAction(tr("Extract Hash")), &QAction::triggered, this, &ForensicWindow::extractSelected);
    connect(toolbar->addAction(tr("Plan Attack...")), &QAction::triggered, this, &ForensicWindow::planAttackSelected);

    auto *central = new QWidget(this);
    auto *layout = new QVBoxLayout(central);

    m_caseLabel = new QLabel(tr("No case open. Create or open a case to begin."), central);
    m_caseLabel->setWordWrap(true);
    layout->addWidget(m_caseLabel);

    m_tabs = new QTabWidget(central);
    m_tabs->addTab(buildEvidenceTab(), tr("Evidence"));
    m_tabs->addTab(buildJobsTab(), tr("Jobs"));
    m_tabs->addTab(buildResultsTab(), tr("Results"));
    layout->addWidget(m_tabs);

    setCentralWidget(central);

    // Execution: one attached hashcat backend + a serial job queue. The queue
    // never starts anything not explicitly enqueued by the examiner.
    m_backend = new HashcatExecutionBackend(
        SettingsManager::instance().getKey<QString>("hashcatPath"), this);
    m_queue = new JobQueue(m_backend, this);
    connect(m_queue, &JobQueue::jobChanged, this, &ForensicWindow::onJobChanged);
    connect(m_queue, &JobQueue::jobStatus, this, &ForensicWindow::onJobStatus);
    connect(m_queue, &JobQueue::credentialRecovered, this, &ForensicWindow::onCredentialRecovered);

    setCaseActionsEnabled(false);
}

ForensicWindow::~ForensicWindow() = default;

QWidget *ForensicWindow::buildEvidenceTab()
{
    auto *w = new QWidget(this);
    auto *layout = new QVBoxLayout(w);

    auto *buttonRow = new QHBoxLayout;
    m_addButton = new QPushButton(tr("Add Artifact..."), w);
    connect(m_addButton, &QPushButton::clicked, this, &ForensicWindow::addArtifact);
    buttonRow->addWidget(m_addButton);
    m_extractButton = new QPushButton(tr("Extract Hash"), w);
    connect(m_extractButton, &QPushButton::clicked, this, &ForensicWindow::extractSelected);
    buttonRow->addWidget(m_extractButton);
    m_planButton = new QPushButton(tr("Plan Attack..."), w);
    connect(m_planButton, &QPushButton::clicked, this, &ForensicWindow::planAttackSelected);
    buttonRow->addWidget(m_planButton);
    buttonRow->addStretch();
    layout->addLayout(buttonRow);

    m_table = new QTableWidget(0, 7, w);
    m_table->setHorizontalHeaderLabels(
        {tr("Filename"), tr("Size"), tr("Detected type"), tr("SHA-256"),
         tr("Extractor"), tr("Extraction"), tr("Imported (UTC)")});
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    layout->addWidget(m_table);
    return w;
}

QWidget *ForensicWindow::buildJobsTab()
{
    auto *w = new QWidget(this);
    auto *layout = new QVBoxLayout(w);

    auto *buttonRow = new QHBoxLayout;
    auto *pause = new QPushButton(tr("Pause"), w);
    auto *resume = new QPushButton(tr("Resume"), w);
    auto *stop = new QPushButton(tr("Stop"), w);
    connect(pause, &QPushButton::clicked, this, &ForensicWindow::pauseSelectedJob);
    connect(resume, &QPushButton::clicked, this, &ForensicWindow::resumeSelectedJob);
    connect(stop, &QPushButton::clicked, this, &ForensicWindow::stopSelectedJob);
    buttonRow->addWidget(pause);
    buttonRow->addWidget(resume);
    buttonRow->addWidget(stop);
    auto *report = new QPushButton(tr("Generate Report"), w);
    connect(report, &QPushButton::clicked, this, &ForensicWindow::generateReportForSelectedJob);
    buttonRow->addWidget(report);
    buttonRow->addStretch();
    layout->addLayout(buttonRow);

    m_jobsTable = new QTableWidget(0, 12, w);
    m_jobsTable->setHorizontalHeaderLabels(
        {tr("Artifact"), tr("Hash mode"), tr("Attack"), tr("Device"), tr("Progress %"),
         tr("Speed (H/s)"), tr("Candidates"), tr("Keyspace"), tr("Runtime"), tr("ETA"),
         tr("Status"), tr("Recovered")});
    m_jobsTable->horizontalHeader()->setStretchLastSection(true);
    m_jobsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_jobsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_jobsTable->setSelectionMode(QAbstractItemView::SingleSelection);
    layout->addWidget(m_jobsTable);
    return w;
}

QWidget *ForensicWindow::buildResultsTab()
{
    auto *w = new QWidget(this);
    auto *layout = new QVBoxLayout(w);
    layout->addWidget(new QLabel(tr("Recovered credentials in this case:"), w));
    m_resultsTable = new QTableWidget(0, 5, w);
    m_resultsTable->setHorizontalHeaderLabels(
        {tr("Artifact"), tr("Plaintext"), tr("Hash"), tr("Recovered (UTC)"), tr("Job")});
    m_resultsTable->horizontalHeader()->setStretchLastSection(true);
    m_resultsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_resultsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    layout->addWidget(m_resultsTable);
    return w;
}

void ForensicWindow::setCaseActionsEnabled(bool enabled)
{
    m_addButton->setEnabled(enabled);
    m_extractButton->setEnabled(enabled);
    m_planButton->setEnabled(enabled);
}

void ForensicWindow::newCase()
{
    bool ok = false;
    const QString name = QInputDialog::getText(this, tr("New Case"), tr("Case name:"),
                                               QLineEdit::Normal, QString(), &ok);
    if (!ok || name.trimmed().isEmpty())
        return;
    const QString examiner = QInputDialog::getText(this, tr("New Case"), tr("Examiner:"),
                                                    QLineEdit::Normal, QString(), &ok);
    if (!ok)
        return;
    const QString parentDir = QFileDialog::getExistingDirectory(this, tr("Choose a folder to hold the case"));
    if (parentDir.isEmpty())
        return;

    forensic::CaseInfo info;
    info.name = name.trimmed();
    info.examiner = examiner.trimmed();

    QString error;
    auto ws = CaseWorkspace::create(parentDir, info, &error);
    if (!ws) {
        QMessageBox::warning(this, tr("New Case"), tr("Could not create case:\n%1").arg(error));
        return;
    }
    m_workspace = std::move(ws);
    setCaseActionsEnabled(true);
    refreshCaseHeader();
    reloadEvidenceTable();
}

void ForensicWindow::openCase()
{
    const QString dir = QFileDialog::getExistingDirectory(this, tr("Open Case Folder"));
    if (dir.isEmpty())
        return;
    QString error;
    auto ws = CaseWorkspace::open(dir, &error);
    if (!ws) {
        QMessageBox::warning(this, tr("Open Case"), tr("Could not open case:\n%1").arg(error));
        return;
    }
    m_workspace = std::move(ws);
    setCaseActionsEnabled(true);
    refreshCaseHeader();
    reloadEvidenceTable();
    m_jobsTable->setRowCount(0);
    for (const auto &job : m_workspace->jobs())
        upsertJobRow(job);
    refreshResults();
}

void ForensicWindow::addArtifact()
{
    if (!m_workspace)
        return;
    const QString path = QFileDialog::getOpenFileName(this, tr("Add Artifact (file / container)"));
    if (path.isEmpty())
        return;

    QApplication::setOverrideCursor(Qt::WaitCursor);
    forensic::IntakeResult result = m_workspace->addEvidence(path);
    QApplication::restoreOverrideCursor();

    if (!result.ok) {
        QMessageBox::warning(this, tr("Add Artifact"), tr("Could not add artifact:\n%1").arg(result.error));
        return;
    }
    reloadEvidenceTable();
}

void ForensicWindow::extractSelected()
{
    if (!m_workspace)
        return;
    const int row = m_table->currentRow();
    if (row < 0 || row >= m_workspace->evidence().size()) {
        QMessageBox::information(this, tr("Extract Hash"), tr("Select an artifact first."));
        return;
    }
    const EvidenceItem item = m_workspace->evidence().at(row);

    if (!m_workspace->extractors().hasExtractorFor(item.type)) {
        QMessageBox::information(this, tr("Extract Hash"),
                                 tr("No extractor is available for detected type '%1'.")
                                     .arg(item.type.isUnknown() ? tr("Unknown") : item.type.displayName));
        return;
    }

    forensic::ToolResolver tools = buildToolResolver();
    forensic::QtProcessRunner runner;
    forensic::ExtractionContext ctx;
    ctx.runner = &runner;
    ctx.tools = &tools;
    ctx.workingDir = QDir::tempPath();

    QApplication::setOverrideCursor(Qt::WaitCursor);
    auto outcome = m_workspace->extractHash(item.id, ctx);
    QApplication::restoreOverrideCursor();

    if (!outcome.ok) {
        QMessageBox::warning(this, tr("Extract Hash"), outcome.error);
        return;
    }

    const forensic::ExtractionResult &r = outcome.result;
    if (r.status == forensic::ExtractionStatus::ToolUnavailable) {
        QMessageBox::warning(this, tr("Extractor tool not configured"),
                             tr("%1\n\nConfigure the tool path under settings key 'tools/%2'.")
                                 .arg(r.message, outcome.record.extractorId));
        reloadEvidenceTable();
        return;
    }
    if (r.status != forensic::ExtractionStatus::Success) {
        QString detail = r.message;
        if (!r.stdErr.trimmed().isEmpty())
            detail += tr("\n\nTool stderr:\n%1").arg(r.stdErr.trimmed());
        QMessageBox::warning(this, tr("Extraction did not produce a hash"), detail);
        reloadEvidenceTable();
        return;
    }

    // Success. If the mode is ambiguous, ask the examiner to choose -- we never
    // silently guess.
    if (r.modeAmbiguous()) {
        QStringList options;
        for (const auto &opt : r.candidateModes)
            options << tr("%1 - %2").arg(opt.mode).arg(opt.name);
        bool ok = false;
        const QString choice = QInputDialog::getItem(
            this, tr("Select hashcat mode"),
            tr("The extracted hash matches more than one hashcat mode.\n"
               "Select the correct one:"),
            options, 0, false, &ok);
        if (ok && !choice.isEmpty()) {
            const quint32 mode = choice.section(QLatin1Char(' '), 0, 0).toUInt();
            QString err;
            if (!m_workspace->selectExtractionMode(outcome.record.id, mode, &err))
                QMessageBox::warning(this, tr("Select hashcat mode"), err);
        }
    }

    reloadEvidenceTable();

    const quint32 mode = m_workspace->extractions().isEmpty() ? 0
                        : m_workspace->extractions().last().selectedMode;
    QMessageBox::information(
        this, tr("Hash extracted"),
        tr("Extractor: %1\nHashcat mode: %2\n\nHash (stored separately in the case):\n%3")
            .arg(outcome.record.extractorId,
                 mode ? QString::number(mode) : tr("(not yet selected)"),
                 r.hash));
}

void ForensicWindow::planAttackSelected()
{
    if (!m_workspace)
        return;
    const int row = m_table->currentRow();
    if (row < 0 || row >= m_workspace->evidence().size()) {
        QMessageBox::information(this, tr("Plan Attack"), tr("Select an artifact first."));
        return;
    }
    const EvidenceItem item = m_workspace->evidence().at(row);

    // Find the most recent successful extraction for this artifact with a
    // resolved hashcat mode.
    forensic::Extraction chosen;
    bool found = false;
    for (const auto &e : m_workspace->extractions()) {
        if (e.evidenceId == item.id && e.status == QStringLiteral("success") && e.selectedMode != 0) {
            chosen = e;
            found = true;
        }
    }
    if (!found) {
        QMessageBox::information(
            this, tr("Plan Attack"),
            tr("This artifact has no extracted hash with a selected hashcat mode yet.\n"
               "Use 'Extract Hash' first (and choose a mode if prompted)."));
        return;
    }

    const QString hashFile = QDir(m_workspace->extractionsDir())
                                 .filePath(chosen.id.toString(QUuid::WithoutBraces) + "/hash.txt");
    QString hashTypeName;
    for (const auto &opt : chosen.candidateModes)
        if (opt.mode == chosen.selectedMode)
            hashTypeName = opt.name;

    const QString planDir = QDir(m_workspace->jobsDir())
                                .filePath(QStringLiteral("plan-") + QUuid::createUuid().toString(QUuid::WithoutBraces));

    AttackPlannerDialog dlg(chosen.selectedMode, hashTypeName, hashFile, planDir, this);
    dlg.exec();
    if (!dlg.queueRequested())
        return; // examiner only previewed; nothing is started

    const QString hashcatPath = SettingsManager::instance().getKey<QString>("hashcatPath");
    if (hashcatPath.isEmpty()) {
        QMessageBox::warning(this, tr("Queue Attack"),
                             tr("Configure the hashcat path in Settings before queuing a job."));
        return;
    }

    const forensic::AttackJobSpec spec = dlg.plannedSpec();
    CrackingJob job;
    job.id = QUuid::createUuid();
    job.caseId = m_workspace->info().id;
    job.evidenceId = item.id;
    job.hashMode = spec.hashMode;
    job.attackMode = spec.attackMode;
    job.hashcatPath = hashcatPath;
    job.hashcatVersion = probeHashcatVersion(hashcatPath);
    job.hashcatArgs = forensic::AttackCommandBuilder::buildArgs(spec);
    job.hashFile = spec.hashFile;
    job.wordlists = spec.wordlists;
    job.rules = spec.rules;
    job.mask = spec.mask;

    const QString jobDir = m_workspace->jobDir(job.id);
    QDir().mkpath(jobDir);
    JobQueue::JobPaths paths;
    paths.workingDir = jobDir;
    paths.sessionName = QStringLiteral("cp-") + job.id.toString(QUuid::WithoutBraces).left(8);
    paths.potfilePath = QDir(jobDir).filePath(QStringLiteral("job.potfile"));
    paths.outfilePath = QDir(jobDir).filePath(QStringLiteral("cracked.out"));
    paths.restorePath = QDir(jobDir).filePath(QStringLiteral("session.restore"));

    m_queue->enqueue(job, paths);
    m_tabs->setCurrentIndex(1); // show the Jobs tab
}

void ForensicWindow::refreshCaseHeader()
{
    if (!m_workspace) {
        m_caseLabel->setText(tr("No case open."));
        return;
    }
    const auto &info = m_workspace->info();
    m_caseLabel->setText(tr("Case: %1    Examiner: %2\nID: %3\nFolder: %4")
                             .arg(info.name,
                                  info.examiner.isEmpty() ? tr("(unspecified)") : info.examiner,
                                  info.id, m_workspace->rootPath()));
}

QString ForensicWindow::latestExtractionSummary(const QString &evidenceId) const
{
    if (!m_workspace)
        return QString();
    QString summary;
    for (const auto &e : m_workspace->extractions()) {
        if (e.evidenceId.toString(QUuid::WithoutBraces) != evidenceId)
            continue;
        if (e.status == QStringLiteral("success")) {
            if (e.selectedMode)
                summary = tr("hash -m %1").arg(e.selectedMode);
            else
                summary = tr("hash (mode: choose)");
        } else {
            summary = e.status;
        }
    }
    return summary;
}

void ForensicWindow::reloadEvidenceTable()
{
    m_table->setRowCount(0);
    if (!m_workspace)
        return;
    const QList<EvidenceItem> items = m_workspace->evidence();
    for (int i = 0; i < items.size(); ++i) {
        m_table->insertRow(i);
        appendEvidenceRow(i);
    }
    m_table->resizeColumnsToContents();
    m_table->horizontalHeader()->setStretchLastSection(true);
}

void ForensicWindow::appendEvidenceRow(int row)
{
    const EvidenceItem &e = m_workspace->evidence().at(row);

    QString extractorText = tr("No");
    if (m_workspace->extractors().hasExtractorFor(e.type))
        extractorText = tr("Yes - %1").arg(m_workspace->extractors().extractorFor(e.type)->displayName());

    const QString typeText = e.type.isUnknown()
        ? tr("Unknown")
        : tr("%1 (%2%)").arg(e.type.displayName).arg(qRound(e.type.confidence * 100));

    const auto set = [this, row](int col, const QString &text) {
        m_table->setItem(row, col, new QTableWidgetItem(text));
    };
    set(0, e.filename);
    set(1, QLocale().formattedDataSize(e.size));
    set(2, typeText);
    set(3, e.sha256);
    set(4, extractorText);
    set(5, latestExtractionSummary(e.id.toString(QUuid::WithoutBraces)));
    set(6, e.importedUtc.toString(Qt::ISODate));
}

// ---------------------------------------------------------------------------
// Jobs & Results
// ---------------------------------------------------------------------------

namespace {
QString formatDuration(qint64 seconds)
{
    if (seconds < 0)
        return QStringLiteral("-");
    const qint64 h = seconds / 3600;
    const qint64 m = (seconds % 3600) / 60;
    const qint64 s = seconds % 60;
    return QStringLiteral("%1:%2:%3")
        .arg(h, 2, 10, QLatin1Char('0'))
        .arg(m, 2, 10, QLatin1Char('0'))
        .arg(s, 2, 10, QLatin1Char('0'));
}
} // namespace

QString ForensicWindow::artifactName(const QUuid &evidenceId) const
{
    if (!m_workspace)
        return QString();
    for (const EvidenceItem &e : m_workspace->evidence())
        if (e.id == evidenceId)
            return e.filename;
    return evidenceId.toString(QUuid::WithoutBraces);
}

int ForensicWindow::jobRow(const QUuid &jobId) const
{
    for (int r = 0; r < m_jobsTable->rowCount(); ++r) {
        const QTableWidgetItem *item = m_jobsTable->item(r, 0);
        if (item && item->data(Qt::UserRole).toUuid() == jobId)
            return r;
    }
    return -1;
}

void ForensicWindow::upsertJobRow(const CrackingJob &job)
{
    int row = jobRow(job.id);
    if (row < 0) {
        row = m_jobsTable->rowCount();
        m_jobsTable->insertRow(row);
        for (int c = 0; c < m_jobsTable->columnCount(); ++c)
            m_jobsTable->setItem(row, c, new QTableWidgetItem(QStringLiteral("-")));
        m_jobsTable->item(row, 0)->setData(Qt::UserRole, QVariant::fromValue(job.id));
    }
    m_jobsTable->item(row, 0)->setText(artifactName(job.evidenceId));
    m_jobsTable->item(row, 1)->setText(QStringLiteral("-m %1").arg(job.hashMode));
    m_jobsTable->item(row, 2)->setText(forensic::attackModeName(job.attackMode));
    m_jobsTable->item(row, 10)->setText(forensic::jobStateToString(job.state));
}

void ForensicWindow::onJobChanged(const CrackingJob &job)
{
    upsertJobRow(job);
    if (m_workspace)
        m_workspace->saveJob(job); // persist reproducible record + state
}

void ForensicWindow::onJobStatus(const QUuid &jobId, const forensic::HashcatStatus &status)
{
    const int row = jobRow(jobId);
    if (row < 0)
        return;
    if (!status.devices.isEmpty())
        m_jobsTable->item(row, 3)->setText(status.devices.first().name);
    const double pct = status.progressPercent();
    m_jobsTable->item(row, 4)->setText(pct >= 0 ? QStringLiteral("%1").arg(pct, 0, 'f', 2) : QStringLiteral("-"));
    m_jobsTable->item(row, 5)->setText(QLocale().toString(status.aggregateSpeed));
    m_jobsTable->item(row, 6)->setText(QLocale().toString(status.progressDone));
    m_jobsTable->item(row, 7)->setText(QLocale().toString(status.progressTotal));

    const CrackingJob job = m_queue->jobById(jobId);
    if (job.startedUtc.isValid())
        m_jobsTable->item(row, 8)->setText(
            formatDuration(job.startedUtc.secsTo(QDateTime::currentDateTimeUtc())));
    m_jobsTable->item(row, 9)->setText(
        formatDuration(status.remainingSeconds(QDateTime::currentSecsSinceEpoch())));
}

void ForensicWindow::onCredentialRecovered(const forensic::RecoveredCredential &cred)
{
    if (m_workspace)
        m_workspace->addRecoveredCredential(cred); // tied to job/artifact/case + timestamp
    const int row = jobRow(cred.jobId);
    if (row >= 0)
        m_jobsTable->item(row, 11)->setText(cred.plaintext);
    refreshResults();
    m_tabs->setCurrentIndex(2); // surface the recovery immediately
}

void ForensicWindow::refreshResults()
{
    m_resultsTable->setRowCount(0);
    if (!m_workspace)
        return;
    const auto creds = m_workspace->recoveredCredentials();
    for (int i = 0; i < creds.size(); ++i) {
        const auto &c = creds.at(i);
        m_resultsTable->insertRow(i);
        m_resultsTable->setItem(i, 0, new QTableWidgetItem(artifactName(c.evidenceId)));
        m_resultsTable->setItem(i, 1, new QTableWidgetItem(c.plaintext));
        m_resultsTable->setItem(i, 2, new QTableWidgetItem(c.hash));
        m_resultsTable->setItem(i, 3, new QTableWidgetItem(c.recoveredUtc.toString(Qt::ISODate)));
        m_resultsTable->setItem(i, 4, new QTableWidgetItem(c.jobId.toString(QUuid::WithoutBraces).left(8)));
    }
}

void ForensicWindow::pauseSelectedJob()
{
    const int r = m_jobsTable->currentRow();
    if (r >= 0 && m_jobsTable->item(r, 0))
        m_queue->pause(m_jobsTable->item(r, 0)->data(Qt::UserRole).toUuid());
}

void ForensicWindow::resumeSelectedJob()
{
    const int r = m_jobsTable->currentRow();
    if (r >= 0 && m_jobsTable->item(r, 0))
        m_queue->resume(m_jobsTable->item(r, 0)->data(Qt::UserRole).toUuid());
}

void ForensicWindow::stopSelectedJob()
{
    const int r = m_jobsTable->currentRow();
    if (r >= 0 && m_jobsTable->item(r, 0))
        m_queue->stop(m_jobsTable->item(r, 0)->data(Qt::UserRole).toUuid());
}

void ForensicWindow::generateReportForSelectedJob()
{
    if (!m_workspace)
        return;
    const int r = m_jobsTable->currentRow();
    if (r < 0 || !m_jobsTable->item(r, 0)) {
        QMessageBox::information(this, tr("Generate Report"), tr("Select a job first."));
        return;
    }
    const QUuid jobId = m_jobsTable->item(r, 0)->data(Qt::UserRole).toUuid();
    const forensic::CrackingJob job = m_queue->hasJob(jobId) ? m_queue->jobById(jobId)
                                                             : forensic::CrackingJob{};
    forensic::CrackingJob target = job;
    if (target.id.isNull()) {
        for (const auto &j : m_workspace->jobs())
            if (j.id == jobId) target = j;
    }
    if (target.id.isNull())
        return;

    const QMessageBox::StandardButton inc = QMessageBox::question(
        this, tr("Recovered password in report"),
        tr("Include the recovered plaintext password in this report?\n\n"
           "Choose No to redact it (the report still records that recovery occurred)."),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes);
    const bool includePlaintext = (inc == QMessageBox::Yes);

    const forensic::RecoveryReport rep = forensic::ReportBuilder::build(
        *m_workspace, target, QStringLiteral(GUI_VERSION), includePlaintext);

    const QString stamp = QDateTime::currentDateTimeUtc().toString(QStringLiteral("yyyyMMdd-HHmmss"));
    const QString base = QStringLiteral("report-%1-%2")
                             .arg(jobId.toString(QUuid::WithoutBraces).left(8), stamp);
    QDir().mkpath(m_workspace->reportsDir());
    const QString htmlPath = QDir(m_workspace->reportsDir()).filePath(base + QStringLiteral(".html"));
    const QString jsonPath = QDir(m_workspace->reportsDir()).filePath(base + QStringLiteral(".json"));

    bool ok = true;
    {
        QFile f(htmlPath);
        ok = f.open(QIODevice::WriteOnly | QIODevice::Truncate)
             && f.write(forensic::ReportRenderer::toHtml(rep).toUtf8()) >= 0;
    }
    {
        QFile f(jsonPath);
        ok = ok && f.open(QIODevice::WriteOnly | QIODevice::Truncate)
             && f.write(forensic::ReportRenderer::toJson(rep)) >= 0;
    }
    if (!ok) {
        QMessageBox::warning(this, tr("Generate Report"), tr("Could not write the report files."));
        return;
    }
    if (m_workspace)
        m_workspace->audit().append(
            m_workspace->info().examiner.isEmpty() ? QStringLiteral("system") : m_workspace->info().examiner,
            QStringLiteral("report_generated"), QStringLiteral("job"),
            jobId.toString(QUuid::WithoutBraces), {});

    QMessageBox box(this);
    box.setWindowTitle(tr("Report generated"));
    box.setText(tr("Human-readable and JSON reports written to:\n%1\n%2").arg(htmlPath, jsonPath));
    box.setStandardButtons(QMessageBox::Open | QMessageBox::Ok);
    if (box.exec() == QMessageBox::Open)
        QDesktopServices::openUrl(QUrl::fromLocalFile(htmlPath));
}

