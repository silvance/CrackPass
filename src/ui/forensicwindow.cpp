/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "forensicwindow.h"

#include "forensic/caseworkspace.h"
#include "forensic/atomicwrite.h"
#include "forensic/evidenceitem.h"
#include "forensic/extraction/encryptionprobe.h"
#include "forensic/extraction/processrunner.h"
#include "forensic/extraction/toolresolver.h"
#include "forensic/extraction/extraction.h"
#include "forensic/deps/toolchainservice.h"
#include "attackplannerdialog.h"
#include "recoverpassworddialog.h"
#include "forensic/dictionary/dictionarylibrary.h"
#include "forensicsettingsdialog.h"
#include "dependencydoctordialog.h"
#include "forensic/crackingjob.h"
#include "forensic/recoveredcredential.h"
#include "forensic/execution/jobqueue.h"
#include "forensic/execution/hashcatexecutionbackend.h"
#include "forensic/execution/johnexecutionbackend.h"
#include "forensic/execution/bkcrackexecutionbackend.h"
#include "forensic/extraction/zipcipher.h"
#include "bkcrackdialog.h"
#include "forensic/execution/hashcatstatus.h"
#include "forensic/recovery/recoverycontroller.h"
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
#include <QStandardPaths>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QTabWidget>
#include <QTableWidget>
#include <QToolBar>
#include <QDateTime>
#include <QCheckBox>
#include <QClipboard>
#include <QDesktopServices>
#include <QUrl>
#include <QFont>
#include <QStackedWidget>
#include <QVBoxLayout>
#include <QWidget>

using forensic::CaseWorkspace;
using forensic::EvidenceItem;
using forensic::CrackingJob;
using forensic::JobQueue;
using forensic::HashcatExecutionBackend;
using forensic::JohnExecutionBackend;
using forensic::JobState;

namespace {

// A settings lookup + app dir for the toolchain service, so the Dependency
// Doctor and hash extraction resolve tools identically (settings -> portable
// -> PATH, with interpreter handling for .py/.pl scripts).
forensic::ToolchainService makeToolchainService(forensic::ProcessRunner *runner)
{
    auto settings = [](const QString &k) { return SettingsManager::instance().getKey<QString>(k); };
    return forensic::ToolchainService(runner, QApplication::applicationDirPath(), settings);
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

// John has no --version flag; run with no arguments (it prints its version
// banner and usage, then exits) and pick out the identifying line. Best-effort
// provenance only -- an empty result does not block the run.
QString probeJohnVersion(const QString &path)
{
    if (path.isEmpty())
        return QString();
    QProcess p;
    p.setProcessChannelMode(QProcess::MergedChannels);
    p.start(path, {}, QIODevice::ReadOnly);
    if (!p.waitForStarted(3000))
        return QString();
    if (!p.waitForFinished(5000)) {
        p.kill();
        p.waitForFinished(1000);
        return QString();
    }
    const QStringList lines = QString::fromUtf8(p.readAll()).split(QLatin1Char('\n'));
    for (const QString &l : lines) {
        const QString t = l.trimmed();
        if (t.contains(QStringLiteral("John the Ripper"), Qt::CaseInsensitive))
            return t;
    }
    return lines.value(0).trimmed();
}

// bkcrack prints its version banner when run with no arguments; capture the
// first line mentioning bkcrack. Best-effort provenance only.
QString probeBkcrackVersion(const QString &path)
{
    if (path.isEmpty())
        return QString();
    QProcess p;
    p.setProcessChannelMode(QProcess::MergedChannels);
    p.start(path, {}, QIODevice::ReadOnly);
    if (!p.waitForStarted(3000))
        return QString();
    if (!p.waitForFinished(5000)) {
        p.kill();
        p.waitForFinished(1000);
        return QString();
    }
    const QStringList lines = QString::fromUtf8(p.readAll()).split(QLatin1Char('\n'));
    for (const QString &l : lines) {
        const QString t = l.trimmed();
        if (t.contains(QStringLiteral("bkcrack"), Qt::CaseInsensitive))
            return t;
    }
    return lines.value(0).trimmed();
}

} // namespace

ForensicWindow::ForensicWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setWindowTitle(tr("CaseKey - Forensic Mode"));
    resize(1000, 520);

    auto *toolbar = addToolBar(tr("Case"));
    toolbar->setMovable(false);
    connect(toolbar->addAction(tr("New Case...")), &QAction::triggered, this, &ForensicWindow::newCase);
    connect(toolbar->addAction(tr("Open Case...")), &QAction::triggered, this, &ForensicWindow::openCase);
    toolbar->addSeparator();
    connect(toolbar->addAction(tr("Add Artifact...")), &QAction::triggered, this, &ForensicWindow::addArtifact);
    QAction *recoverAction = toolbar->addAction(tr("Recover Password..."));
    recoverAction->setToolTip(tr("Recover the selected artifact's password (extracts the hash if needed)"));
    connect(recoverAction, &QAction::triggered, this, &ForensicWindow::recoverPasswordSelected);
    connect(toolbar->addAction(tr("Extract Hash")), &QAction::triggered, this, &ForensicWindow::extractSelected);
    connect(toolbar->addAction(tr("Plan Attack...")), &QAction::triggered, this, &ForensicWindow::planAttackSelected);
    toolbar->addSeparator();
    connect(toolbar->addAction(tr("Settings...")), &QAction::triggered, this, &ForensicWindow::openForensicSettings);
    connect(toolbar->addAction(tr("Tool Status...")), &QAction::triggered, this, &ForensicWindow::openDependencyDoctor);

    // The window shows a welcome screen until a case is open, then the case
    // view (evidence / jobs / results). This keeps first contact uncluttered.
    m_rootStack = new QStackedWidget(this);

    // Page 0: welcome / empty state.
    auto *welcome = new QWidget(m_rootStack);
    auto *wl = new QVBoxLayout(welcome);
    wl->addStretch();
    auto *title = new QLabel(tr("CaseKey"), welcome);
    QFont titleFont = title->font();
    titleFont.setPointSize(titleFont.pointSize() + 10);
    titleFont.setBold(true);
    title->setFont(titleFont);
    title->setAlignment(Qt::AlignHCenter);
    wl->addWidget(title);
    auto *subtitle = new QLabel(tr("Forensic Password Recovery"), welcome);
    subtitle->setAlignment(Qt::AlignHCenter);
    wl->addWidget(subtitle);
    wl->addSpacing(24);
    auto *wbtns = new QHBoxLayout;
    wbtns->addStretch();
    auto *newBtn = new QPushButton(tr("New Case"), welcome);
    connect(newBtn, &QPushButton::clicked, this, &ForensicWindow::newCase);
    wbtns->addWidget(newBtn);
    auto *openBtn = new QPushButton(tr("Open Existing Case"), welcome);
    connect(openBtn, &QPushButton::clicked, this, &ForensicWindow::openCase);
    wbtns->addWidget(openBtn);
    wbtns->addStretch();
    wl->addLayout(wbtns);
    wl->addStretch();
    m_rootStack->addWidget(welcome);

    // Page 1: the open-case view.
    auto *central = new QWidget(m_rootStack);
    auto *layout = new QVBoxLayout(central);

    m_caseLabel = new QLabel(tr("No case open. Create or open a case to begin."), central);
    m_caseLabel->setWordWrap(true);
    layout->addWidget(m_caseLabel);

    m_tabs = new QTabWidget(central);
    m_tabs->addTab(buildEvidenceTab(), tr("Evidence"));
    m_tabs->addTab(buildJobsTab(), tr("Jobs"));
    m_tabs->addTab(buildResultsTab(), tr("Results"));
    layout->addWidget(m_tabs);
    m_rootStack->addWidget(central);

    setCentralWidget(m_rootStack);

    // Execution: one attached hashcat backend + a serial job queue. The queue
    // never starts anything not explicitly enqueued by the examiner.
    m_backend = new HashcatExecutionBackend(
        SettingsManager::instance().getKey<QString>("hashcatPath"), this);
    m_queue = new JobQueue(m_backend, this);
    // John the Ripper is a second engine; jobs whose engineId is "john" route to
    // this backend. The default (hashcat) backend still serves every other job.
    m_johnBackend = new JohnExecutionBackend(
        SettingsManager::instance().getKey<QString>("johnPath"), this);
    m_queue->registerBackend(QStringLiteral("john"), m_johnBackend);
    // bkcrack is the ZipCrypto known-plaintext engine; jobs whose engineId is
    // "bkcrack" route to this backend.
    m_bkcrackBackend = new forensic::BkcrackExecutionBackend(
        SettingsManager::instance().getKey<QString>("bkcrackPath"), this);
    m_queue->registerBackend(QStringLiteral("bkcrack"), m_bkcrackBackend);
    // The controller owns the persistence side of recovery (job state + recovered
    // credentials -> case). Construct it before wiring the display slots so its
    // writes land before the UI reads them back.
    m_recovery = new forensic::RecoveryController(m_queue, this);
    // Surface a refused attack (e.g. an engine that cannot express the plan) to
    // the examiner instead of silently doing nothing.
    connect(m_recovery, &forensic::RecoveryController::recoveryRefused, this,
            [this](const QString &reason) {
                QMessageBox::warning(this, tr("Queue Attack"), reason);
            });
    // A running job whose state could not be re-saved keeps running, but warn
    // the examiner that the on-disk record for it may be stale.
    connect(m_recovery, &forensic::RecoveryController::jobPersistenceFailed, this,
            [this](const forensic::CrackingJob &, const QString &error) {
                QMessageBox::warning(this, tr("Case persistence"),
                                     tr("A running job's state could not be saved to the case: %1")
                                         .arg(error));
            });
    connect(m_queue, &JobQueue::jobChanged, this, &ForensicWindow::onJobChanged);
    connect(m_queue, &JobQueue::jobStatus, this, &ForensicWindow::onJobStatus);
    connect(m_queue, &JobQueue::credentialRecovered, this, &ForensicWindow::onCredentialRecovered);

    setCaseActionsEnabled(false);
    updateWelcomeVisibility(); // start on the welcome screen
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
    auto *recoverButton = new QPushButton(tr("Recover Password..."), w);
    recoverButton->setDefault(true);
    recoverButton->setToolTip(tr("The primary workflow: extract the hash if needed, then run a recovery"));
    connect(recoverButton, &QPushButton::clicked, this, &ForensicWindow::recoverPasswordSelected);
    buttonRow->addWidget(recoverButton);
    m_extractButton = new QPushButton(tr("Extract Hash"), w);
    connect(m_extractButton, &QPushButton::clicked, this, &ForensicWindow::extractSelected);
    buttonRow->addWidget(m_extractButton);
    m_planButton = new QPushButton(tr("Plan Attack..."), w);
    connect(m_planButton, &QPushButton::clicked, this, &ForensicWindow::planAttackSelected);
    buttonRow->addWidget(m_planButton);
    m_bkcrackButton = new QPushButton(tr("ZipCrypto Attack..."), w);
    m_bkcrackButton->setToolTip(tr("Known-plaintext attack (bkcrack) on a legacy ZipCrypto archive"));
    connect(m_bkcrackButton, &QPushButton::clicked, this, &ForensicWindow::zipCryptoAttackSelected);
    buttonRow->addWidget(m_bkcrackButton);
    buttonRow->addStretch();
    layout->addLayout(buttonRow);

    m_evidenceEmptyHint = new QLabel(tr("No artifacts have been added.\nUse “Add Artifact…” to begin."), w);
    m_evidenceEmptyHint->setAlignment(Qt::AlignCenter);
    m_evidenceEmptyHint->setStyleSheet(QStringLiteral("color:#666;padding:24px;"));
    layout->addWidget(m_evidenceEmptyHint);

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

    auto *ctrlRow = new QHBoxLayout;
    // Recovered values (passwords AND key material) are concealed by default;
    // revealing is a deliberate examiner action.
    auto *reveal = new QCheckBox(tr("Reveal values"), w);
    connect(reveal, &QCheckBox::toggled, this, &ForensicWindow::setRevealPasswords);
    ctrlRow->addWidget(reveal);
    // The copy button's label follows the selected result's kind (Copy Password
    // vs Copy Key), so key material is never presented as a password.
    m_copyValueButton = new QPushButton(tr("Copy Value"), w);
    connect(m_copyValueButton, &QPushButton::clicked, this, &ForensicWindow::copySelectedValue);
    ctrlRow->addWidget(m_copyValueButton);
    auto *copyTarget = new QPushButton(tr("Copy Target"), w);
    connect(copyTarget, &QPushButton::clicked, this, &ForensicWindow::copySelectedTarget);
    ctrlRow->addWidget(copyTarget);
    ctrlRow->addStretch();
    layout->addLayout(ctrlRow);

    m_resultsTable = new QTableWidget(0, 6, w);
    m_resultsTable->setHorizontalHeaderLabels(
        {tr("Artifact"), tr("Type"), tr("Value"), tr("Target"), tr("Recovered (UTC)"), tr("Job")});
    m_resultsTable->horizontalHeader()->setStretchLastSection(true);
    m_resultsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_resultsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    connect(m_resultsTable, &QTableWidget::itemSelectionChanged,
            this, &ForensicWindow::updateResultCopyLabel);
    layout->addWidget(m_resultsTable);
    return w;
}

void ForensicWindow::setCaseActionsEnabled(bool enabled)
{
    m_addButton->setEnabled(enabled);
    m_extractButton->setEnabled(enabled);
    m_planButton->setEnabled(enabled);
    m_bkcrackButton->setEnabled(enabled);
}

void ForensicWindow::updateWelcomeVisibility()
{
    // Show the welcome screen until a case is open, then the case view.
    if (m_rootStack)
        m_rootStack->setCurrentIndex(m_workspace ? 1 : 0);
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
    m_recovery->setWorkspace(m_workspace.get());
    setCaseActionsEnabled(true);
    refreshCaseHeader();
    reloadEvidenceTable();
    updateWelcomeVisibility(); // reveal the case view
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
    m_recovery->setWorkspace(m_workspace.get());
    setCaseActionsEnabled(true);
    refreshCaseHeader();
    reloadEvidenceTable();
    m_jobsTable->setRowCount(0);
    // Re-register persisted jobs into the queue so resume/stop work after a
    // reopen; each restore emits jobChanged, which populates the jobs table.
    m_recovery->restoreJobs();
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

    forensic::QtProcessRunner runner;
    forensic::ToolResolver tools = makeToolchainService(&runner).extractionResolver();
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

bool ForensicWindow::ensureExtractedHash(const EvidenceItem &item, quint32 &modeOut,
                                         QString &hashFileOut, QString &hashTypeNameOut)
{
    // A helper to locate the most recent successful extraction for this artifact
    // with a resolved mode.
    auto findReady = [&](forensic::Extraction &out) -> bool {
        bool ok = false;
        for (const auto &e : m_workspace->extractions())
            if (e.evidenceId == item.id && e.status == QStringLiteral("success") && e.selectedMode != 0) {
                out = e;
                ok = true;
            }
        return ok;
    };

    forensic::Extraction chosen;
    if (!findReady(chosen)) {
        // No hash yet -- extract it now (the primary workflow auto-extracts).
        if (!m_workspace->extractors().hasExtractorFor(item.type)) {
            QMessageBox::information(
                this, tr("Recover Password"),
                tr("No hash extractor is available for detected type '%1', so its "
                   "password cannot be recovered by this workflow.")
                    .arg(item.type.isUnknown() ? tr("Unknown") : item.type.displayName));
            return false;
        }

        forensic::QtProcessRunner runner;
        forensic::ToolResolver tools = makeToolchainService(&runner).extractionResolver();
        forensic::ExtractionContext ctx;
        ctx.runner = &runner;
        ctx.tools = &tools;
        ctx.workingDir = QDir::tempPath();

        QApplication::setOverrideCursor(Qt::WaitCursor);
        auto outcome = m_workspace->extractHash(item.id, ctx);
        QApplication::restoreOverrideCursor();

        if (!outcome.ok) {
            QMessageBox::warning(this, tr("Recover Password"), outcome.error);
            return false;
        }
        const forensic::ExtractionResult &r = outcome.result;
        if (r.status == forensic::ExtractionStatus::ToolUnavailable) {
            QMessageBox::warning(this, tr("Extractor tool not configured"),
                                 tr("%1\n\nConfigure the tool path under settings key 'tools/%2'.")
                                     .arg(r.message, outcome.record.extractorId));
            reloadEvidenceTable();
            return false;
        }
        if (r.status != forensic::ExtractionStatus::Success) {
            QString detail = r.message;
            if (!r.stdErr.trimmed().isEmpty())
                detail += tr("\n\nTool stderr:\n%1").arg(r.stdErr.trimmed());
            QMessageBox::warning(this, tr("Extraction did not produce a hash"), detail);
            reloadEvidenceTable();
            return false;
        }
        // If the mode is ambiguous, ask -- we never silently guess.
        if (r.modeAmbiguous()) {
            QStringList options;
            for (const auto &opt : r.candidateModes)
                options << tr("%1 - %2").arg(opt.mode).arg(opt.name);
            bool ok = false;
            const QString choice = QInputDialog::getItem(
                this, tr("Select hash type"),
                tr("The extracted hash matches more than one type.\nSelect the correct one:"),
                options, 0, false, &ok);
            if (ok && !choice.isEmpty()) {
                const quint32 mode = choice.section(QLatin1Char(' '), 0, 0).toUInt();
                QString err;
                if (!m_workspace->selectExtractionMode(outcome.record.id, mode, &err))
                    QMessageBox::warning(this, tr("Select hash type"), err);
            }
        }
        reloadEvidenceTable();

        if (!findReady(chosen)) {
            QMessageBox::information(
                this, tr("Recover Password"),
                tr("The hash was extracted but its type is not selected yet. "
                   "Use 'Extract Hash' and choose a type, then try again."));
            return false;
        }
    }

    modeOut = chosen.selectedMode;
    hashFileOut = QDir(m_workspace->extractionsDir())
                      .filePath(chosen.id.toString(QUuid::WithoutBraces) + "/hash.txt");
    hashTypeNameOut.clear();
    for (const auto &opt : chosen.candidateModes)
        if (opt.mode == chosen.selectedMode)
            hashTypeNameOut = opt.name;
    return true;
}

bool ForensicWindow::resolveEngineTool(const QString &engineId, QString &toolPath, QString &toolVersion)
{
    if (engineId == QStringLiteral("john")) {
        toolPath = SettingsManager::instance().getKey<QString>("johnPath");
        if (toolPath.isEmpty()) {
            QMessageBox::warning(this, tr("Queue Attack"),
                                 tr("Configure the John the Ripper path in Settings before "
                                    "queuing a John job."));
            return false;
        }
        toolVersion = probeJohnVersion(toolPath);
    } else {
        toolPath = SettingsManager::instance().getKey<QString>("hashcatPath");
        if (toolPath.isEmpty()) {
            QMessageBox::warning(this, tr("Queue Attack"),
                                 tr("Configure the hashcat path in Settings before queuing a job."));
            return false;
        }
        toolVersion = probeHashcatVersion(toolPath);
    }
    return true;
}

forensic::DictionaryLibrary ForensicWindow::makeDictionaryLibrary() const
{
    forensic::DictionaryLibrary lib;

    // The bundled builtin manifest: a settings override, else next to the binary
    // (a packaged install), else the source tree (a developer build).
    const QString configured = SettingsManager::instance().getKey<QString>("dictionariesManifest");
    QStringList candidates;
    if (!configured.isEmpty())
        candidates << configured;
    const QString appDir = QApplication::applicationDirPath();
    candidates << QDir(appDir).filePath(QStringLiteral("dictionaries/manifest.json"))
               << QDir(appDir).filePath(QStringLiteral("../resources/dictionaries/manifest.json"))
               << QDir(appDir).filePath(QStringLiteral("../../resources/dictionaries/manifest.json"))
               << QDir(appDir).filePath(QStringLiteral("../share/casekey/dictionaries/manifest.json"));
    for (const QString &c : candidates) {
        if (QFileInfo::exists(c)) {
            lib.setBuiltinManifest(QDir::cleanPath(c));
            break;
        }
    }

    // Imported entries and any copies live in a writable per-user library dir.
    const QString dataDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (!dataDir.isEmpty())
        lib.setLibraryDir(QDir(dataDir).filePath(QStringLiteral("dictionaries")));

    lib.reload();
    return lib;
}

void ForensicWindow::openAdvancedPlanner(const EvidenceItem &item, quint32 mode,
                                         const QString &hashTypeName, const QString &hashFile,
                                         const QString &planDir)
{
    AttackPlannerDialog dlg(mode, hashTypeName, hashFile, planDir, this);
    dlg.exec();
    if (!dlg.queueRequested())
        return; // examiner only previewed; nothing is started

    // Resolve the binary + version for the engine the examiner chose, so the
    // recorded provenance matches the tool that actually runs.
    QString toolPath, toolVersion;
    if (!resolveEngineTool(dlg.plannedEngineId(), toolPath, toolVersion))
        return;

    // The controller builds the reproducible job, lays out its session files,
    // enqueues it, and persists the record + later state/credentials. It refuses
    // (via recoveryRefused) if the engine cannot express the attack.
    m_recovery->queueRecoveryJob(dlg.plannedSpec(), item.id, toolPath, toolVersion, dlg.plannedEngineId());
    m_tabs->setCurrentIndex(1); // show the Jobs tab
}

void ForensicWindow::recoverPasswordSelected()
{
    if (!m_workspace)
        return;
    const int row = m_table->currentRow();
    if (row < 0 || row >= m_workspace->evidence().size()) {
        QMessageBox::information(this, tr("Recover Password"), tr("Select an artifact first."));
        return;
    }
    const EvidenceItem item = m_workspace->evidence().at(row);

    quint32 mode = 0;
    QString hashFile, hashTypeName;
    if (!ensureExtractedHash(item, mode, hashFile, hashTypeName))
        return; // reason already explained

    const QString planDir = QDir(m_workspace->jobsDir())
                                .filePath(QStringLiteral("plan-") + QUuid::createUuid().toString(QUuid::WithoutBraces));

    const forensic::DictionaryLibrary library = makeDictionaryLibrary();
    RecoverPasswordDialog dlg(mode, hashTypeName, hashFile, planDir, library,
                              m_recovery->engines(), this);
    if (dlg.exec() != QDialog::Accepted)
        return;

    if (dlg.guidedRequested()) {
        openAdvancedPlanner(item, mode, hashTypeName, hashFile, planDir);
        return;
    }
    if (!dlg.startRequested())
        return;

    QString toolPath, toolVersion;
    if (!resolveEngineTool(dlg.plannedEngineId(), toolPath, toolVersion))
        return;

    m_recovery->queueRecoveryJob(dlg.plannedSpec(), item.id, toolPath, toolVersion,
                                 dlg.plannedEngineId());
    m_tabs->setCurrentIndex(1); // show the Jobs tab
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
    // resolved hashcat mode. (Plan Attack requires the hash to exist already;
    // the primary "Recover Password" workflow is the one that auto-extracts.)
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

    openAdvancedPlanner(item, chosen.selectedMode, hashTypeName, hashFile, planDir);
}

void ForensicWindow::zipCryptoAttackSelected()
{
    if (!m_workspace)
        return;
    const int row = m_table->currentRow();
    if (row < 0 || row >= m_workspace->evidence().size()) {
        QMessageBox::information(this, tr("ZipCrypto Attack"), tr("Select an artifact first."));
        return;
    }
    const EvidenceItem item = m_workspace->evidence().at(row);
    const QString zipPath = m_workspace->evidenceReadPath(item);

    // bkcrack applies only to legacy ZipCrypto; classify first and refuse AES /
    // unencrypted archives with a clear pointer to the password path.
    const forensic::ZipCipherScan scan = forensic::ZipCipherClassifier::scan(zipPath);
    if (!scan.isZip) {
        QMessageBox::information(this, tr("ZipCrypto Attack"),
                                 tr("This artifact is not a ZIP archive."));
        return;
    }
    if (!scan.hasZipCrypto()) {
        const QString why = scan.hasAes()
            ? tr("This archive uses WinZip AES encryption, which bkcrack cannot attack.")
            : tr("This archive has no ZipCrypto-encrypted entries.");
        QMessageBox::information(
            this, tr("ZipCrypto Attack"),
            why + QLatin1Char('\n')
                + tr("Use 'Extract Hash' to recover the password with hashcat or John instead."));
        return;
    }

    BkcrackDialog dlg(zipPath, scan.zipCryptoEntryNames(), this);
    if (dlg.exec() != QDialog::Accepted)
        return; // cancelled

    const QString toolPath = SettingsManager::instance().getKey<QString>("bkcrackPath");
    if (toolPath.isEmpty()) {
        QMessageBox::warning(this, tr("ZipCrypto Attack"),
                             tr("Configure the bkcrack path in Settings before queuing a job."));
        return;
    }
    // The controller builds and persists the reproducible bkcrack job; it refuses
    // (via recoveryRefused) if the spec cannot be turned into a command.
    m_recovery->queueBkcrackJob(dlg.plannedSpec(), item.id, toolPath, probeBkcrackVersion(toolPath));
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
    // Empty-state hint: show it only when the case has no artifacts yet.
    if (m_evidenceEmptyHint)
        m_evidenceEmptyHint->setVisible(items.isEmpty());
    m_table->setVisible(!items.isEmpty());
}

void ForensicWindow::appendEvidenceRow(int row)
{
    const EvidenceItem e = m_workspace->evidence().at(row); // by value: evidence() returns a temporary

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
    // Display only; the RecoveryController persists the job record + state.
    upsertJobRow(job);
}

void ForensicWindow::onJobStatus(const QUuid &jobId, const forensic::RecoveryStatus &status)
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
    // The RecoveryController persists the credential (it is connected first, so
    // it has already been written to the case by the time we refresh below).
    const int row = jobRow(cred.jobId);
    if (row >= 0) {
        // Conceal the recovered value here too (same policy as the Results tab):
        // the real value rides in UserRole; the cell shows bullets until revealed.
        QTableWidgetItem *item = m_jobsTable->item(row, 11);
        item->setData(Qt::UserRole, cred.plaintext);
        item->setText(m_revealPasswords ? cred.plaintext : QStringLiteral("••••••"));
    }
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
        // Type: password vs key material, so a bkcrack key is never shown as a
        // "plaintext" password.
        m_resultsTable->setItem(i, 1, new QTableWidgetItem(forensic::resultKindNoun(c.kind)));
        // The recovered value (password or key material) is concealed by default;
        // the actual value lives in UserRole so Reveal and Copy work without
        // displaying it. The kind rides along so the copy button can label itself.
        auto *val = new QTableWidgetItem(m_revealPasswords ? c.plaintext
                                                           : QStringLiteral("\u2022\u2022\u2022\u2022\u2022\u2022"));
        val->setData(Qt::UserRole, c.plaintext);
        val->setData(Qt::UserRole + 1, static_cast<int>(c.kind));
        m_resultsTable->setItem(i, 2, val);
        auto *target = new QTableWidgetItem(c.hash);
        target->setData(Qt::UserRole, c.hash);
        m_resultsTable->setItem(i, 3, target);
        m_resultsTable->setItem(i, 4, new QTableWidgetItem(c.recoveredUtc.toString(Qt::ISODate)));
        m_resultsTable->setItem(i, 5, new QTableWidgetItem(c.jobId.toString(QUuid::WithoutBraces).left(8)));
    }
    updateResultCopyLabel();
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

    // Redact by default: the examiner must deliberately opt in to embedding the
    // recovered plaintext in an exportable report. The default action is No so
    // that simply confirming the dialog produces a redacted report.
    const QMessageBox::StandardButton inc = QMessageBox::question(
        this, tr("Recovered password in report"),
        tr("Include the recovered plaintext password in this report?\n\n"
           "Choose No to redact it (the report still records that recovery occurred)."),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    const bool includePlaintext = (inc == QMessageBox::Yes);

    const forensic::RecoveryReport rep = forensic::ReportBuilder::build(
        *m_workspace, target, QStringLiteral(GUI_VERSION), includePlaintext);

    const QString stamp = QDateTime::currentDateTimeUtc().toString(QStringLiteral("yyyyMMdd-HHmmss"));
    const QString base = QStringLiteral("report-%1-%2")
                             .arg(jobId.toString(QUuid::WithoutBraces).left(8), stamp);
    QDir().mkpath(m_workspace->reportsDir());
    const QString htmlPath = QDir(m_workspace->reportsDir()).filePath(base + QStringLiteral(".html"));
    const QString jsonPath = QDir(m_workspace->reportsDir()).filePath(base + QStringLiteral(".json"));

    // Reports are part of the forensic record: write them atomically so a crash
    // cannot leave a half-rendered report behind.
    QString werr;
    if (!forensic::writeFileAtomic(htmlPath, forensic::ReportRenderer::toHtml(rep).toUtf8(), &werr)
        || !forensic::writeFileAtomic(jsonPath, forensic::ReportRenderer::toJson(rep), &werr)) {
        QMessageBox::warning(this, tr("Generate Report"),
                             tr("Could not write the report files: %1").arg(werr));
        return;
    }
    if (m_workspace && !m_workspace->audit().append(
            m_workspace->info().examiner.isEmpty() ? QStringLiteral("system") : m_workspace->info().examiner,
            QStringLiteral("report_generated"), QStringLiteral("job"),
            jobId.toString(QUuid::WithoutBraces), {})) {
        QMessageBox::warning(this, tr("Generate Report"),
                             tr("The report was written but the audit entry could not be recorded: %1")
                                 .arg(m_workspace->audit().lastError()));
    }

    QMessageBox box(this);
    box.setWindowTitle(tr("Report generated"));
    box.setText(tr("Human-readable and JSON reports written to:\n%1\n%2").arg(htmlPath, jsonPath));
    box.setStandardButtons(QMessageBox::Open | QMessageBox::Ok);
    if (box.exec() == QMessageBox::Open)
        QDesktopServices::openUrl(QUrl::fromLocalFile(htmlPath));
}


void ForensicWindow::openForensicSettings()
{
    ForensicSettingsDialog dlg(this);
    dlg.exec();
}

void ForensicWindow::openDependencyDoctor()
{
    DependencyDoctorDialog dlg(this);
    dlg.exec();
}

void ForensicWindow::setRevealPasswords(bool on)
{
    m_revealPasswords = on;
    refreshResults();
    // Apply the same visibility policy to the Jobs table's recovered column.
    for (int r = 0; r < m_jobsTable->rowCount(); ++r) {
        QTableWidgetItem *item = m_jobsTable->item(r, 11);
        if (!item)
            continue;
        const QString value = item->data(Qt::UserRole).toString();
        if (!value.isEmpty())
            item->setText(on ? value : QStringLiteral("••••••"));
    }
}

void ForensicWindow::updateResultCopyLabel()
{
    if (!m_copyValueButton)
        return;
    const int r = m_resultsTable->currentRow();
    QString label = tr("Copy Value");
    if (r >= 0 && m_resultsTable->item(r, 2)) {
        const auto kind = static_cast<forensic::ResultKind>(
            m_resultsTable->item(r, 2)->data(Qt::UserRole + 1).toInt());
        label = (kind == forensic::ResultKind::Password) ? tr("Copy Password") : tr("Copy Key");
    }
    m_copyValueButton->setText(label);
}

void ForensicWindow::copySelectedValue()
{
    const int r = m_resultsTable->currentRow();
    if (r < 0 || !m_resultsTable->item(r, 2))
        return;
    QApplication::clipboard()->setText(m_resultsTable->item(r, 2)->data(Qt::UserRole).toString());
}

void ForensicWindow::copySelectedTarget()
{
    const int r = m_resultsTable->currentRow();
    if (r < 0 || !m_resultsTable->item(r, 3))
        return;
    QApplication::clipboard()->setText(m_resultsTable->item(r, 3)->data(Qt::UserRole).toString());
}
