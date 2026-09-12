/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#ifndef UI_ATTACKPLANNERDIALOG_H
#define UI_ATTACKPLANNERDIALOG_H

#include "forensic/planner/attackplanner.h"
#include "forensic/planner/attackjobspec.h"
#include <QDialog>

class QComboBox;
class QLineEdit;
class QSpinBox;
class QPlainTextEdit;
class QCheckBox;
class QLabel;

/*
 * Guided, examiner-friendly attack planner. It collects case knowledge and a
 * template, then shows exactly what hashcat would be told (mode, attack mode,
 * wordlists, rules, mask, keyspace, devices, full command) BEFORE anything is
 * run. It never launches an attack -- it produces and displays a plan.
 *
 * Hashcat is not hidden: the "Custom / Advanced" template and the shown command
 * keep the low-level view available, alongside the separate Advanced Mode.
 */
class AttackPlannerDialog : public QDialog
{
    Q_OBJECT

public:
    AttackPlannerDialog(quint32 hashMode, const QString &hashTypeName,
                        const QString &hashFile, const QString &planDir,
                        QWidget *parent = nullptr);

public:
    // True if the examiner chose to queue; the spec to run.
    bool queueRequested() const { return m_queueRequested; }
    forensic::AttackJobSpec plannedSpec() const { return m_lastSpec; }

private slots:
    void updatePreview();
    void requestQueue();

private:
    forensic::CaseKnowledge collectKnowledge() const;
    forensic::AttackTemplate currentTemplate() const;

    quint32 m_hashMode;
    QString m_hashTypeName;
    QString m_hashFile;
    QString m_planDir;

    QComboBox *m_template = nullptr;
    QSpinBox *m_minLen = nullptr;
    QSpinBox *m_maxLen = nullptr;
    QLineEdit *m_prefix = nullptr;
    QLineEdit *m_suffix = nullptr;
    QLineEdit *m_knownPositions = nullptr;
    QLineEdit *m_baseWords = nullptr;
    QLineEdit *m_names = nullptr;
    QLineEdit *m_usernames = nullptr;
    QLineEdit *m_emails = nullptr;
    QLineEdit *m_previous = nullptr;
    QSpinBox *m_yearFrom = nullptr;
    QSpinBox *m_yearTo = nullptr;
    QLineEdit *m_commonWordlist = nullptr;
    QLineEdit *m_customArgs = nullptr;
    QCheckBox *m_clsLower = nullptr;
    QCheckBox *m_clsUpper = nullptr;
    QCheckBox *m_clsDigit = nullptr;
    QCheckBox *m_clsSpecial = nullptr;

    forensic::AttackJobSpec m_lastSpec;
    bool m_lastOk = false;
    bool m_queueRequested = false;

    QPlainTextEdit *m_preview = nullptr;
    QPlainTextEdit *m_command = nullptr;
    QLabel *m_status = nullptr;
};

#endif // UI_ATTACKPLANNERDIALOG_H
