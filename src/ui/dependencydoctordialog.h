/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef UI_DEPENDENCYDOCTORDIALOG_H
#define UI_DEPENDENCYDOCTORDIALOG_H

#include <QDialog>

class QTreeWidget;

/*
 * "System / Tool Status" (Dependency Doctor): shows the detected forensic
 * toolchain and resources so an examiner can deploy and operate CaseKey
 * without understanding the internals. Read-only; a Re-scan button re-probes.
 */
class DependencyDoctorDialog : public QDialog
{
    Q_OBJECT
public:
    explicit DependencyDoctorDialog(QWidget *parent = nullptr);

private slots:
    void rescan();

private:
    QTreeWidget *m_tree = nullptr;
};

#endif // UI_DEPENDENCYDOCTORDIALOG_H
