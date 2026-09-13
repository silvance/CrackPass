/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "bkcrackdialog.h"

#include "forensic/bkcrack/bkcrackcommandbuilder.h"

#include <QComboBox>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QRadioButton>
#include <QSpinBox>
#include <QVBoxLayout>

using forensic::BkcrackAttackSpec;
using forensic::BkcrackCommandBuilder;

BkcrackDialog::BkcrackDialog(const QString &zipPath, const QStringList &zipCryptoEntries,
                             QWidget *parent)
    : QDialog(parent)
    , m_zipPath(zipPath)
{
    setWindowTitle(tr("ZipCrypto Attack (bkcrack)"));
    resize(640, 420);
    auto *root = new QVBoxLayout(this);

    root->addWidget(new QLabel(
        tr("bkcrack recovers the archive's internal keys from known plaintext -- "
           "not a password. Provide the exact original bytes of one entry, or a run "
           "of bytes you know appear at a given offset."),
        this));

    auto *form = new QFormLayout;
    m_entry = new QComboBox(this);
    m_entry->addItems(zipCryptoEntries);
    form->addRow(tr("Target entry:"), m_entry);
    root->addLayout(form);

    // Known plaintext: a file, or bytes-at-offset. Exactly one is used.
    auto *src = new QGroupBox(tr("Known plaintext"), this);
    auto *sl = new QVBoxLayout(src);

    m_useFile = new QRadioButton(tr("Plaintext file (the known original of the entry, or a prefix)"), src);
    m_useFile->setChecked(true);
    sl->addWidget(m_useFile);
    auto *fileRow = new QHBoxLayout;
    m_plainFile = new QLineEdit(src);
    auto *browse = new QPushButton(tr("Browse..."), src);
    connect(browse, &QPushButton::clicked, this, &BkcrackDialog::browseForPlainFile);
    fileRow->addWidget(m_plainFile, 1);
    fileRow->addWidget(browse);
    sl->addLayout(fileRow);

    m_useHex = new QRadioButton(tr("Known bytes (hexadecimal) at an offset"), src);
    sl->addWidget(m_useHex);
    auto *hexForm = new QFormLayout;
    m_plainHex = new QLineEdit(src);
    m_plainHex->setPlaceholderText(tr("e.g. 504b0304140000000800 (at least 12 bytes)"));
    hexForm->addRow(tr("Bytes (hex):"), m_plainHex);
    m_offset = new QSpinBox(src);
    m_offset->setRange(0, 1000000000);
    hexForm->addRow(tr("Offset:"), m_offset);
    sl->addLayout(hexForm);
    root->addWidget(src);

    m_status = new QLabel(this);
    m_status->setWordWrap(true);
    root->addWidget(m_status);

    auto *buttons = new QDialogButtonBox(this);
    buttons->addButton(tr("Queue Attack"), QDialogButtonBox::AcceptRole);
    buttons->addButton(QDialogButtonBox::Cancel);
    connect(buttons, &QDialogButtonBox::accepted, this, &BkcrackDialog::tryAccept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    root->addWidget(buttons);

    connect(m_useFile, &QRadioButton::toggled, this, &BkcrackDialog::updateEnabled);
    connect(m_useHex, &QRadioButton::toggled, this, &BkcrackDialog::updateEnabled);
    updateEnabled();
}

void BkcrackDialog::updateEnabled()
{
    const bool file = m_useFile->isChecked();
    m_plainFile->setEnabled(file);
    m_plainHex->setEnabled(!file);
    m_offset->setEnabled(!file);
}

void BkcrackDialog::browseForPlainFile()
{
    const QString p = QFileDialog::getOpenFileName(this, tr("Select known plaintext file"));
    if (!p.isEmpty()) {
        m_plainFile->setText(p);
        m_useFile->setChecked(true);
    }
}

forensic::BkcrackAttackSpec BkcrackDialog::collectSpec() const
{
    BkcrackAttackSpec spec;
    spec.zipPath = m_zipPath;
    spec.targetEntry = m_entry->currentText();
    if (m_useFile->isChecked()) {
        spec.plainFile = m_plainFile->text().trimmed();
    } else {
        spec.plainHex = m_plainHex->text().trimmed();
        spec.plainOffset = m_offset->value();
    }
    return spec;
}

void BkcrackDialog::tryAccept()
{
    const BkcrackAttackSpec spec = collectSpec();
    // Validate through the same builder that will produce the command, so the
    // examiner sees the exact reason an incomplete attack is refused.
    const forensic::BkcrackBuildResult r = BkcrackCommandBuilder::build(spec);
    if (!r.valid) {
        m_status->setText(tr("Cannot queue: %1").arg(r.error));
        return;
    }
    m_spec = spec;
    accept();
}
