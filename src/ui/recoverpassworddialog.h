/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef UI_RECOVERPASSWORDDIALOG_H
#define UI_RECOVERPASSWORDDIALOG_H

#include "forensic/crackingjob.h"
#include "forensic/dictionary/dictionarylibrary.h"
#include "forensic/planner/attackjobspec.h"
#include "forensic/recovery/recoveryengineregistry.h"
#include "forensic/recovery/recoverystrategy.h"

#include <QDialog>

class QComboBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QStackedWidget;

/*
 * The primary "Recover Password" workflow: pick a strategy and go.
 *
 * It leads with the simplest choice -- a Dictionary attack against a managed
 * wordlist (CaseKey Common by default) that needs no knowledge of the case --
 * and chooses the recovery engine automatically (preferring hashcat, falling
 * back only when hashcat cannot express the attack). It plans the attack live
 * and shows, in plain language, what will run and with which engine before the
 * examiner starts it. A "Pattern" strategy offers a straightforward mask, and
 * "Guided / advanced" hands off to the full AttackPlannerDialog for case
 * knowledge and every template -- so no capability is lost, only deferred.
 *
 * The dialog does not launch anything; on accept it exposes the planned spec
 * and the chosen engine for the window to persist and enqueue.
 */
class RecoverPasswordDialog : public QDialog
{
    Q_OBJECT

public:
    RecoverPasswordDialog(quint32 hashMode, const QString &hashTypeName,
                          const QString &hashFile, const QString &planDir,
                          const forensic::DictionaryLibrary &library,
                          const forensic::RecoveryEngineRegistry &engines,
                          QWidget *parent = nullptr);

    // True when the examiner asked to start a Dictionary/Pattern recovery here.
    bool startRequested() const { return m_startRequested; }
    // True when the examiner chose Guided/advanced: the window should open the
    // full AttackPlannerDialog instead of queueing from this dialog.
    bool guidedRequested() const { return m_guidedRequested; }

    forensic::AttackJobSpec plannedSpec() const { return m_spec; }
    QString plannedEngineId() const { return m_engineId; }
    // The chosen dictionary's provenance (Dictionary strategy only; unset id
    // otherwise), for stamping onto the job and report. Its SHA-256 is the digest
    // computed at Start, after the drift check passed.
    forensic::DictionaryProvenance chosenDictionary() const { return m_dictionaryProvenance; }

private slots:
    void strategyChanged();
    void replan();
    void onPrimaryClicked();

private:
    forensic::RecoveryStrategy currentStrategy() const;
    void populateDictionaries();

    quint32 m_hashMode;
    QString m_hashTypeName;
    QString m_hashFile;
    QString m_planDir;
    forensic::DictionaryLibrary m_library;
    forensic::RecoveryEngineRegistry m_engines;

    QComboBox *m_strategy = nullptr;
    QLabel *m_strategyDesc = nullptr;
    QStackedWidget *m_inputs = nullptr; // per-strategy inputs (dict picker / mask / guided note)
    QComboBox *m_dictionary = nullptr;
    QLabel *m_dictionaryInfo = nullptr;
    QLineEdit *m_mask = nullptr;
    QLabel *m_summary = nullptr;   // plain-language "what will run"
    QWidget *m_advanced = nullptr; // collapsible technical detail (hidden by default)
    QLabel *m_details = nullptr;   // hash type/mode, attack mode, engine, dictionary
    QPlainTextEdit *m_command = nullptr; // the exact command (transparency)
    QPushButton *m_primary = nullptr; // Start Recovery / Open Advanced Planner

    // Live planning result.
    forensic::AttackJobSpec m_spec;
    QString m_engineId;
    QString m_dictionaryId;
    forensic::DictionaryProvenance m_dictionaryProvenance; // filled at Start
    bool m_planOk = false; // a runnable plan with an engine that can express it

    bool m_startRequested = false;
    bool m_guidedRequested = false;
};

#endif // UI_RECOVERPASSWORDDIALOG_H
