/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef UI_FORENSICWINDOW_H
#define UI_FORENSICWINDOW_H

#include <QMainWindow>
#include <QUuid>
#include <memory>

class QLabel;
class QPushButton;
class QStackedWidget;
class QTableWidget;
class QTabWidget;

namespace forensic {
class CaseWorkspace;
class JobQueue;
class JobExecutionBackend;
class RecoveryController;
struct CrackingJob;
struct RecoveredCredential;
struct RecoveryStatus;
}

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
    void zipCryptoAttackSelected();

    void onJobChanged(const forensic::CrackingJob &job);
    void onJobStatus(const QUuid &jobId, const forensic::RecoveryStatus &status);
    void onCredentialRecovered(const forensic::RecoveredCredential &cred);
    void pauseSelectedJob();
    void resumeSelectedJob();
    void stopSelectedJob();
    void generateReportForSelectedJob();
    void openForensicSettings();
    void openDependencyDoctor();
    void copySelectedValue();
    void copySelectedTarget();
    void setRevealPasswords(bool on);
    void updateResultCopyLabel();

private:
    void refreshCaseHeader();
    void reloadEvidenceTable();
    void appendEvidenceRow(int row);
    void setCaseActionsEnabled(bool enabled);
    QString latestExtractionSummary(const QString &evidenceId) const;

    QWidget *buildEvidenceTab();
    QWidget *buildJobsTab();
    QWidget *buildResultsTab();
    int jobRow(const QUuid &jobId) const;
    void upsertJobRow(const forensic::CrackingJob &job);
    void refreshResults();
    QString artifactName(const QUuid &evidenceId) const;

    std::unique_ptr<forensic::CaseWorkspace> m_workspace;
    forensic::JobExecutionBackend *m_backend = nullptr;     // default engine (hashcat)
    forensic::JobExecutionBackend *m_johnBackend = nullptr;    // John the Ripper
    forensic::JobExecutionBackend *m_bkcrackBackend = nullptr; // bkcrack (ZipCrypto)
    forensic::JobQueue *m_queue = nullptr;
    forensic::RecoveryController *m_recovery = nullptr;

    void updateWelcomeVisibility();

    QStackedWidget *m_rootStack = nullptr; // welcome screen vs. the open-case view
    QLabel *m_caseLabel = nullptr;
    QLabel *m_evidenceEmptyHint = nullptr; // shown in the Evidence tab when empty
    QPushButton *m_addButton = nullptr;
    QPushButton *m_extractButton = nullptr;
    QPushButton *m_planButton = nullptr;
    QPushButton *m_bkcrackButton = nullptr;
    QTableWidget *m_table = nullptr;

    QTabWidget *m_tabs = nullptr;
    QTableWidget *m_jobsTable = nullptr;
    QTableWidget *m_resultsTable = nullptr;
    QPushButton *m_copyValueButton = nullptr;
    bool m_revealPasswords = false;
};

#endif // UI_FORENSICWINDOW_H
