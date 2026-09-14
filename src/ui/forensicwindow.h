/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#ifndef UI_FORENSICWINDOW_H
#define UI_FORENSICWINDOW_H

#include <QMainWindow>
#include <QUuid>
#include <memory>

class QAction;
class QLabel;
class QMenu;
class QPushButton;
class QStackedWidget;
class QTableWidget;
class QTabWidget;

namespace forensic {
class CaseWorkspace;
class DictionaryLibrary;
class JobQueue;
class JobExecutionBackend;
class RecoveryController;
struct CrackingJob;
struct Extraction;
struct EvidenceItem;
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
    void recoverPasswordSelected();
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
    void openDictionaryManager();
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

    // Ensure the artifact has a successful extraction with a selected hash mode,
    // running extraction (and prompting for the mode) if needed. Returns true and
    // fills the hash file + type name when ready; false (after explaining) if not.
    bool ensureExtractedHash(const forensic::EvidenceItem &item,
                             quint32 &modeOut, QString &hashFileOut, QString &hashTypeNameOut);
    // Resolve the configured binary + version for an engine ("hashcat"/"john"),
    // warning and returning false when the path is not configured.
    bool resolveEngineTool(const QString &engineId, QString &toolPath, QString &toolVersion);
    // Open the full guided planner for an already-extracted hash and queue what
    // it plans. Shared by "Plan Attack…" and the wizard's Guided strategy.
    void openAdvancedPlanner(const forensic::EvidenceItem &item, quint32 mode,
                             const QString &hashTypeName, const QString &hashFile,
                             const QString &planDir);
    // Build the managed dictionary library (bundled manifest + user library dir).
    forensic::DictionaryLibrary makeDictionaryLibrary() const;

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
    QPushButton *m_recoverButton = nullptr;
    // The technical / specialized actions, shared between the toolbar's and the
    // evidence tab's "Advanced" menus. Gated by setCaseActionsEnabled().
    QAction *m_extractAction = nullptr;
    QAction *m_planAction = nullptr;
    QAction *m_bkcrackAction = nullptr;
    QAction *m_dictionariesAction = nullptr; // manage the dictionary library (no case needed)
    QMenu *buildAdvancedMenu(QWidget *parent);
    QTableWidget *m_table = nullptr;

    QTabWidget *m_tabs = nullptr;
    QLabel *m_jobsEmptyHint = nullptr;
    void updateJobsEmptyHint();
    QTableWidget *m_jobsTable = nullptr;
    QTableWidget *m_resultsTable = nullptr;
    QPushButton *m_copyValueButton = nullptr;
    bool m_revealPasswords = false;
};

#endif // UI_FORENSICWINDOW_H
