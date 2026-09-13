/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 *
 * Collects the inputs for a bkcrack (ZipCrypto known-plaintext) attack: the
 * target encrypted entry (chosen from the archive's ZipCrypto entries) and the
 * known plaintext -- either a plaintext file or a run of known bytes at an
 * offset. It validates the choice through BkcrackCommandBuilder before it can be
 * queued, so an incomplete attack is refused here with a clear reason rather
 * than failing later.
 */
#ifndef UI_BKCRACKDIALOG_H
#define UI_BKCRACKDIALOG_H

#include "forensic/bkcrack/bkcrackattackspec.h"

#include <QDialog>
#include <QString>
#include <QStringList>

class QComboBox;
class QLabel;
class QLineEdit;
class QRadioButton;
class QSpinBox;

class BkcrackDialog : public QDialog
{
    Q_OBJECT

public:
    BkcrackDialog(const QString &zipPath, const QStringList &zipCryptoEntries,
                  QWidget *parent = nullptr);

    // Valid only after the dialog is accepted.
    forensic::BkcrackAttackSpec plannedSpec() const { return m_spec; }

private slots:
    void updateEnabled();
    void browseForPlainFile();
    void tryAccept();

private:
    forensic::BkcrackAttackSpec collectSpec() const;

    QString m_zipPath;

    QComboBox *m_entry = nullptr;
    QRadioButton *m_useFile = nullptr;
    QRadioButton *m_useHex = nullptr;
    QLineEdit *m_plainFile = nullptr;
    QLineEdit *m_plainHex = nullptr;
    QSpinBox *m_offset = nullptr;
    QLabel *m_status = nullptr;

    forensic::BkcrackAttackSpec m_spec;
};

#endif // UI_BKCRACKDIALOG_H
