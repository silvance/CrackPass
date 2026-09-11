/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#include "appshell.h"

#include "forensicwindow.h"
#include "mainwindow.h"

#include <QApplication>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>

AppShell::AppShell(QWidget *parent)
    : QWidget(parent)
{
    setWindowTitle(tr("CrackPass"));

    auto *layout = new QVBoxLayout(this);

    auto *title = new QLabel(tr("<h2>CrackPass</h2><p>Select a workflow.</p>"), this);
    title->setTextFormat(Qt::RichText);
    layout->addWidget(title);

    auto *forensicButton = new QPushButton(tr("Forensic / Guided Mode"), this);
    forensicButton->setMinimumHeight(48);
    forensicButton->setToolTip(tr("Case-based, examiner-oriented workflow."));
    connect(forensicButton, &QPushButton::clicked, this, &AppShell::openForensicMode);
    layout->addWidget(forensicButton);

    auto *advancedButton = new QPushButton(tr("Advanced Hashcat Mode"), this);
    advancedButton->setMinimumHeight(48);
    advancedButton->setToolTip(tr("The existing low-level hashcat GUI."));
    connect(advancedButton, &QPushButton::clicked, this, &AppShell::openAdvancedMode);
    layout->addWidget(advancedButton);

    layout->addStretch();
}

void AppShell::openForensicMode()
{
    if (!m_forensic) {
        m_forensic = new ForensicWindow;
        m_forensic->setAttribute(Qt::WA_DeleteOnClose);
    }
    m_forensic->show();
    m_forensic->raise();
    m_forensic->activateWindow();
}

void AppShell::openAdvancedMode()
{
    if (!m_advanced) {
        m_advanced = new MainWindow;
        m_advanced->setAttribute(Qt::WA_DeleteOnClose);
    }
    m_advanced->show();
    m_advanced->raise();
    m_advanced->activateWindow();
}
