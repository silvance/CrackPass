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
#include "settingsmanager.h"

#include <QApplication>
#include <QDir>
#include <QFileDialog>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QLocale>
#include <QMessageBox>
#include <QPushButton>
#include <QTableWidget>
#include <QToolBar>
#include <QVBoxLayout>
#include <QWidget>

using forensic::CaseWorkspace;
using forensic::EvidenceItem;

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

    auto *buttons = new QWidget(central);
    auto *buttonRow = new QVBoxLayout(buttons);
    buttonRow->setContentsMargins(0, 0, 0, 0);
    m_addButton = new QPushButton(tr("Add Artifact..."), buttons);
    connect(m_addButton, &QPushButton::clicked, this, &ForensicWindow::addArtifact);
    buttonRow->addWidget(m_addButton);
    m_extractButton = new QPushButton(tr("Extract Hash from Selected Artifact"), buttons);
    connect(m_extractButton, &QPushButton::clicked, this, &ForensicWindow::extractSelected);
    buttonRow->addWidget(m_extractButton);
    m_planButton = new QPushButton(tr("Plan Attack on Selected Artifact..."), buttons);
    connect(m_planButton, &QPushButton::clicked, this, &ForensicWindow::planAttackSelected);
    buttonRow->addWidget(m_planButton);
    layout->addWidget(buttons);

    m_table = new QTableWidget(0, 7, central);
    m_table->setHorizontalHeaderLabels(
        {tr("Filename"), tr("Size"), tr("Detected type"), tr("SHA-256"),
         tr("Extractor"), tr("Extraction"), tr("Imported (UTC)")});
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    layout->addWidget(m_table);

    setCentralWidget(central);
    setCaseActionsEnabled(false);
}

ForensicWindow::~ForensicWindow() = default;

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
