/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "forensicsettingsdialog.h"
#include "settingsmanager.h"

#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>

ForensicSettingsDialog::ForensicSettingsDialog(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(tr("Forensic Settings"));
    resize(700, 520);
    auto *root = new QVBoxLayout(this);

    root->addWidget(new QLabel(tr("Configure the external tools and resources CaseKey uses. "
                                  "Leave a field blank to fall back to the bundled tools/ layout or PATH."), this));

    auto *engine = new QGroupBox(tr("Cracking engine"), this);
    auto *ef = new QFormLayout(engine);
    addPathRow(ef, tr("hashcat executable"), QStringLiteral("hashcatPath"), false);
    root->addWidget(engine);

    auto *extractors = new QGroupBox(tr("Extraction utilities (John the Ripper Jumbo)"), this);
    auto *xf = new QFormLayout(extractors);
    for (const QString &id : {"office2john", "pdf2john", "zip2john", "rar2john", "7z2john", "keepass2john"})
        addPathRow(xf, id, QStringLiteral("tools/") + id, false);
    root->addWidget(extractors);

    auto *res = new QGroupBox(tr("Resources"), this);
    auto *rf = new QFormLayout(res);
    addPathRow(rf, tr("Common-passwords wordlist"), QStringLiteral("commonWordlist"), false);
    addPathRow(rf, tr("Rules directory"), QStringLiteral("rulesDir"), true);
    addPathRow(rf, tr("Default case location"), QStringLiteral("caseRoot"), true);
    root->addWidget(res);

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel, this);
    connect(buttons, &QDialogButtonBox::accepted, this, &ForensicSettingsDialog::save);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    root->addWidget(buttons);
}

QLineEdit *ForensicSettingsDialog::addPathRow(QFormLayout *form, const QString &label,
                                              const QString &key, bool directory)
{
    auto *row = new QHBoxLayout;
    auto *edit = new QLineEdit(this);
    edit->setText(SettingsManager::instance().getKey<QString>(key));
    auto *browse = new QPushButton(tr("Browse..."), this);
    connect(browse, &QPushButton::clicked, this, [this, edit, directory] {
        const QString p = directory ? QFileDialog::getExistingDirectory(this, tr("Select directory"))
                                     : QFileDialog::getOpenFileName(this, tr("Select file"));
        if (!p.isEmpty())
            edit->setText(p);
    });
    row->addWidget(edit, 1);
    row->addWidget(browse);
    form->addRow(label, row);
    m_edits.insert(key, edit);
    m_isDir.insert(key, directory);
    return edit;
}

void ForensicSettingsDialog::save()
{
    auto &s = SettingsManager::instance();
    for (auto it = m_edits.constBegin(); it != m_edits.constEnd(); ++it)
        s.setKey(it.key(), it.value()->text().trimmed());
    accept();
}
