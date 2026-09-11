/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#include "forensicwindow.h"

#include "forensic/caseworkspace.h"
#include "forensic/evidenceitem.h"

#include <QApplication>
#include <QDateTime>
#include <QFileDialog>
#include <QFormLayout>
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

ForensicWindow::ForensicWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setWindowTitle(tr("CrackPass - Forensic Mode"));
    resize(900, 500);

    auto *toolbar = addToolBar(tr("Case"));
    toolbar->setMovable(false);
    QAction *newAction = toolbar->addAction(tr("New Case..."));
    QAction *openAction = toolbar->addAction(tr("Open Case..."));
    toolbar->addSeparator();
    QAction *addAction = toolbar->addAction(tr("Add Artifact..."));
    connect(newAction, &QAction::triggered, this, &ForensicWindow::newCase);
    connect(openAction, &QAction::triggered, this, &ForensicWindow::openCase);
    connect(addAction, &QAction::triggered, this, &ForensicWindow::addArtifact);

    auto *central = new QWidget(this);
    auto *layout = new QVBoxLayout(central);

    m_caseLabel = new QLabel(tr("No case open. Create or open a case to begin."), central);
    m_caseLabel->setWordWrap(true);
    layout->addWidget(m_caseLabel);

    m_addButton = new QPushButton(tr("Add Artifact..."), central);
    connect(m_addButton, &QPushButton::clicked, this, &ForensicWindow::addArtifact);
    layout->addWidget(m_addButton);

    m_table = new QTableWidget(0, 6, central);
    m_table->setHorizontalHeaderLabels(
        {tr("Filename"), tr("Size"), tr("Detected type"), tr("SHA-256"),
         tr("Extractor"), tr("Imported (UTC)")});
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    layout->addWidget(m_table);

    setCentralWidget(central);
    setCaseActionsEnabled(false);
}

ForensicWindow::~ForensicWindow() = default;

void ForensicWindow::setCaseActionsEnabled(bool enabled)
{
    m_addButton->setEnabled(enabled);
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
    const QString parentDir = QFileDialog::getExistingDirectory(
        this, tr("Choose a folder to hold the case"));
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

    const bool hasExtractor = m_workspace->extractors().hasExtractorFor(e.type);
    QString extractorText = tr("No");
    if (hasExtractor) {
        forensic::HashExtractor *ex = m_workspace->extractors().extractorFor(e.type);
        extractorText = tr("Yes - %1 (-m %2)").arg(ex->displayName()).arg(ex->defaultHashMode());
    }

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
    set(5, e.importedUtc.toString(Qt::ISODate));
}
