/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef UI_FORENSICSETTINGSDIALOG_H
#define UI_FORENSICSETTINGSDIALOG_H

#include <QDialog>
#include <QHash>

class QLineEdit;

/*
 * Settings for every forensic dependency, so an examiner configures paths here
 * instead of editing hidden QSettings keys. Values persist to SettingsManager
 * under the same keys the rest of the app reads (hashcatPath, tools/<id>,
 * commonWordlist, rulesDir, caseRoot).
 */
class ForensicSettingsDialog : public QDialog
{
    Q_OBJECT
public:
    explicit ForensicSettingsDialog(QWidget *parent = nullptr);

private slots:
    void save();

private:
    QLineEdit *addPathRow(class QFormLayout *form, const QString &label, const QString &key,
                          bool directory);

    QHash<QString, QLineEdit *> m_edits; // settings key -> editor
    QHash<QString, bool> m_isDir;        // settings key -> pick-directory
};

#endif // UI_FORENSICSETTINGSDIALOG_H
