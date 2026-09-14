/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef UI_DICTIONARYMANAGERDIALOG_H
#define UI_DICTIONARYMANAGERDIALOG_H

#include "forensic/dictionary/dictionarylibrary.h"

#include <QDialog>

class QLabel;
class QPushButton;
class QTableWidget;

/*
 * Manage the local dictionary library: see every wordlist (built-in and
 * imported) with its origin, on-disk status, candidate count and path; import
 * a new wordlist (copying it into the library or referencing it in place, with
 * source/license recorded); remove an imported one; and validate a wordlist to
 * (re)record its SHA-256 + candidate count.
 *
 * It operates on its own DictionaryLibrary (constructed from the same locations
 * the app uses); changes persist to the writable library manifest on disk, so
 * the recovery workflow picks them up the next time it builds the library.
 */
class DictionaryManagerDialog : public QDialog
{
    Q_OBJECT

public:
    explicit DictionaryManagerDialog(forensic::DictionaryLibrary library,
                                     QWidget *parent = nullptr);

private slots:
    void refresh();
    void importWordlist();
    void removeSelected();
    void validateSelected();

private:
    QString selectedId() const;

    forensic::DictionaryLibrary m_library;
    QTableWidget *m_table = nullptr;
    QPushButton *m_removeButton = nullptr;
    QPushButton *m_validateButton = nullptr;
    QLabel *m_hint = nullptr;
};

#endif // UI_DICTIONARYMANAGERDIALOG_H
