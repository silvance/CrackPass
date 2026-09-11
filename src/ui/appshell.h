/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#ifndef UI_APPSHELL_H
#define UI_APPSHELL_H

#include <QWidget>
#include <QPointer>

class MainWindow;
class ForensicWindow;

/*
 * Launcher that lets the examiner pick a workflow:
 *   - Forensic / Guided Mode (new)
 *   - Advanced Hashcat Mode (the existing MainWindow, unchanged)
 *
 * This keeps the upstream MainWindow fully intact while adding the forensic
 * entry point.
 */
class AppShell : public QWidget
{
    Q_OBJECT

public:
    explicit AppShell(QWidget *parent = nullptr);

private slots:
    void openForensicMode();
    void openAdvancedMode();

private:
    QPointer<ForensicWindow> m_forensic;
    QPointer<MainWindow> m_advanced;
};

#endif // UI_APPSHELL_H
