/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: Rainer Größlinger
 */

#include <QApplication>
#include "ui/appshell.h"
#include "config.h"

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    a.setApplicationVersion(GUI_VERSION);

    // The launcher lets the user choose between the new Forensic / Guided Mode
    // and the existing Advanced Hashcat Mode (MainWindow). MainWindow itself is
    // unchanged; see the note in the commit message / README on why this entry
    // point moved from MainWindow to AppShell.
    AppShell shell;
    shell.show();

    return a.exec();
}
