/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#ifndef UI_FORENSICWINDOW_H
#define UI_FORENSICWINDOW_H

#include <QMainWindow>
#include <memory>

class QLabel;
class QPushButton;
class QTableWidget;

namespace forensic { class CaseWorkspace; }

/*
 * Minimal Forensic Mode window. It is a thin view: all logic lives in the
 * forensic core library. It can create/open a case, add an artifact, and show
 * each artifact's metadata, SHA-256, detected type, and extractor coverage.
 * No password attacks are performed.
 */
class ForensicWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit ForensicWindow(QWidget *parent = nullptr);
    ~ForensicWindow() override;

private slots:
    void newCase();
    void openCase();
    void addArtifact();
    void extractSelected();
    void planAttackSelected();

private:
    void refreshCaseHeader();
    void reloadEvidenceTable();
    void appendEvidenceRow(int row);
    void setCaseActionsEnabled(bool enabled);
    QString latestExtractionSummary(const QString &evidenceId) const;

    std::unique_ptr<forensic::CaseWorkspace> m_workspace;

    QLabel *m_caseLabel = nullptr;
    QPushButton *m_addButton = nullptr;
    QPushButton *m_extractButton = nullptr;
    QPushButton *m_planButton = nullptr;
    QTableWidget *m_table = nullptr;
};

#endif // UI_FORENSICWINDOW_H
