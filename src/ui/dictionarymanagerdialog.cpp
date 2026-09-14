/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "dictionarymanagerdialog.h"

#include <QApplication>
#include <QCheckBox>
#include <QDialogButtonBox>
#include <QFileInfo>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QLocale>
#include <QMessageBox>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QFileDialog>

using namespace forensic;

namespace {

QString statusText(const DictionaryLibrary &lib, const DictionaryEntry &e)
{
    if (!e.fileExists())
        return QObject::tr("Missing — file not supplied");
    if (e.sha256.isEmpty())
        return QObject::tr("Present — not validated");
    switch (lib.checkIntegrity(e.id)) {
    case DictionaryLibrary::IntegrityStatus::Present:  return QObject::tr("Present — verified");
    case DictionaryLibrary::IntegrityStatus::Modified: return QObject::tr("Modified — SHA-256 changed");
    case DictionaryLibrary::IntegrityStatus::Missing:  return QObject::tr("Missing");
    case DictionaryLibrary::IntegrityStatus::Unverifiable: return QObject::tr("Present — not validated");
    }
    return QString();
}

} // namespace

DictionaryManagerDialog::DictionaryManagerDialog(DictionaryLibrary library, QWidget *parent)
    : QDialog(parent)
    , m_library(std::move(library))
{
    setWindowTitle(tr("Dictionaries"));
    resize(760, 420);

    auto *root = new QVBoxLayout(this);
    auto *intro = new QLabel(
        tr("Wordlists available for Dictionary attacks. Built-in lists ship with "
           "CaseKey; imported lists are yours. Validating records a wordlist's "
           "SHA-256 and candidate count so the case can prove which list ran."),
        this);
    intro->setWordWrap(true);
    root->addWidget(intro);

    m_table = new QTableWidget(0, 5, this);
    m_table->setHorizontalHeaderLabels(
        {tr("Name"), tr("Origin"), tr("Status"), tr("Candidates"), tr("Path")});
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    root->addWidget(m_table);

    m_hint = new QLabel(this);
    m_hint->setWordWrap(true);
    m_hint->setStyleSheet(QStringLiteral("color:#666;"));
    root->addWidget(m_hint);

    auto *row = new QHBoxLayout;
    auto *importButton = new QPushButton(tr("Import…"), this);
    connect(importButton, &QPushButton::clicked, this, &DictionaryManagerDialog::importWordlist);
    row->addWidget(importButton);
    m_validateButton = new QPushButton(tr("Validate"), this);
    connect(m_validateButton, &QPushButton::clicked, this, &DictionaryManagerDialog::validateSelected);
    row->addWidget(m_validateButton);
    m_removeButton = new QPushButton(tr("Remove"), this);
    connect(m_removeButton, &QPushButton::clicked, this, &DictionaryManagerDialog::removeSelected);
    row->addWidget(m_removeButton);
    row->addStretch();
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    row->addWidget(buttons);
    root->addLayout(row);

    connect(m_table, &QTableWidget::itemSelectionChanged, this, [this] {
        // Remove is only meaningful for imported entries.
        bool found = false;
        const DictionaryEntry e = m_library.entry(selectedId(), &found);
        m_removeButton->setEnabled(found && !e.isBuiltin());
        m_validateButton->setEnabled(found && e.fileExists());
    });

    refresh();
}

QString DictionaryManagerDialog::selectedId() const
{
    const int r = m_table->currentRow();
    if (r < 0 || r >= m_table->rowCount())
        return {};
    const QTableWidgetItem *it = m_table->item(r, 0);
    return it ? it->data(Qt::UserRole).toString() : QString();
}

void DictionaryManagerDialog::refresh()
{
    const QString keep = selectedId();
    const QList<DictionaryEntry> entries = m_library.entries();
    m_table->setRowCount(entries.size());
    int selectRow = -1;
    for (int i = 0; i < entries.size(); ++i) {
        const DictionaryEntry &e = entries.at(i);
        auto *name = new QTableWidgetItem(e.displayName);
        name->setData(Qt::UserRole, e.id);
        m_table->setItem(i, 0, name);
        m_table->setItem(i, 1, new QTableWidgetItem(
            e.isBuiltin() ? tr("Built-in") : tr("Imported")));
        m_table->setItem(i, 2, new QTableWidgetItem(statusText(m_library, e)));
        m_table->setItem(i, 3, new QTableWidgetItem(
            e.candidateCount >= 0 ? QLocale().toString(qlonglong(e.candidateCount)) : QStringLiteral("—")));
        m_table->setItem(i, 4, new QTableWidgetItem(e.absolutePath));
        if (e.id == keep)
            selectRow = i;
    }
    if (selectRow >= 0)
        m_table->selectRow(selectRow);

    m_hint->setText(entries.isEmpty()
        ? tr("No dictionaries yet. Use Import… to add a wordlist.")
        : QString());
    m_removeButton->setEnabled(false);
    m_validateButton->setEnabled(false);
}

void DictionaryManagerDialog::importWordlist()
{
    const QString path = QFileDialog::getOpenFileName(this, tr("Import wordlist"));
    if (path.isEmpty())
        return;

    // Collect provenance + how to hold the file.
    QDialog dlg(this);
    dlg.setWindowTitle(tr("Import wordlist"));
    auto *form = new QFormLayout(&dlg);
    auto *name = new QLineEdit(QFileInfo(path).completeBaseName(), &dlg);
    form->addRow(tr("Display name:"), name);
    auto *description = new QLineEdit(&dlg);
    form->addRow(tr("Description:"), description);
    auto *source = new QLineEdit(&dlg);
    source->setPlaceholderText(tr("Where did this wordlist come from?"));
    form->addRow(tr("Source:"), source);
    auto *license = new QLineEdit(&dlg);
    license->setPlaceholderText(tr("License / attribution obligations"));
    form->addRow(tr("License:"), license);
    auto *copy = new QCheckBox(tr("Copy the file into the library (else reference it in place)"), &dlg);
    copy->setChecked(true);
    form->addRow(QString(), copy);
    auto *box = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    connect(box, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(box, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    form->addRow(box);
    if (dlg.exec() != QDialog::Accepted)
        return;

    QString err;
    QApplication::setOverrideCursor(Qt::WaitCursor); // hashing + counting can take a moment
    const QString id = m_library.importWordlist(path, name->text().trimmed(), description->text().trimmed(),
                                                source->text().trimmed(), license->text().trimmed(),
                                                copy->isChecked(), &err);
    QApplication::restoreOverrideCursor();
    if (id.isEmpty()) {
        QMessageBox::warning(this, tr("Import wordlist"), err);
        return;
    }
    refresh();
}

void DictionaryManagerDialog::removeSelected()
{
    const QString id = selectedId();
    if (id.isEmpty())
        return;
    bool found = false;
    const DictionaryEntry e = m_library.entry(id, &found);
    if (!found)
        return;
    if (QMessageBox::question(
            this, tr("Remove dictionary"),
            tr("Remove “%1” from the library?%2")
                .arg(e.displayName,
                     e.copiedIntoLibrary ? tr("\n\nThe library's copy will be deleted.")
                                         : tr("\n\nThe original file will be left in place.")))
        != QMessageBox::Yes)
        return;
    QString err;
    if (!m_library.removeImported(id, &err)) {
        QMessageBox::warning(this, tr("Remove dictionary"), err);
        return;
    }
    refresh();
}

void DictionaryManagerDialog::validateSelected()
{
    const QString id = selectedId();
    if (id.isEmpty())
        return;
    bool found = false;
    const DictionaryEntry e = m_library.entry(id, &found);
    if (!found)
        return;

    QString err, sha;
    qint64 count = -1;
    QApplication::setOverrideCursor(Qt::WaitCursor);
    const bool ok = m_library.revalidate(id, &count, &sha, &err);
    QApplication::restoreOverrideCursor();
    if (!ok) {
        QMessageBox::warning(this, tr("Validate dictionary"), err);
        refresh();
        return;
    }
    const QString note = e.isBuiltin()
        ? tr("Built-in wordlists keep the baseline recorded in the bundled manifest, "
             "so this only shows the current values.")
        : tr("Recorded as the new baseline for this imported wordlist.");
    QMessageBox::information(
        this, tr("Validate dictionary"),
        tr("%1\n\nCandidates: %2\nSHA-256: %3\n\n%4")
            .arg(e.displayName, QLocale().toString(qlonglong(count)), sha, note));
    refresh();
}
