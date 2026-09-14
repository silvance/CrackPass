/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "recoverpassworddialog.h"

#include "forensic/planner/attackplanner.h"
#include "forensic/planner/knowledgematerializer.h"

#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QFrame>
#include <QLabel>
#include <QLineEdit>
#include <QLocale>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QStackedWidget>
#include <QVBoxLayout>

using namespace forensic;

namespace {

QString formatCount(qint64 n)
{
    return n < 0 ? QObject::tr("an unknown number of") : QLocale().toString(qlonglong(n));
}

} // namespace

RecoverPasswordDialog::RecoverPasswordDialog(quint32 hashMode, const QString &hashTypeName,
                                             const QString &hashFile, const QString &planDir,
                                             const DictionaryLibrary &library,
                                             const RecoveryEngineRegistry &engines,
                                             QWidget *parent)
    : QDialog(parent)
    , m_hashMode(hashMode)
    , m_hashTypeName(hashTypeName)
    , m_hashFile(hashFile)
    , m_planDir(planDir)
    , m_library(library)
    , m_engines(engines)
{
    setWindowTitle(tr("Recover Password"));
    setMinimumWidth(560);

    auto *root = new QVBoxLayout(this);

    auto *heading = new QLabel(tr("Recover the password for this artifact."), this);
    QFont hf = heading->font();
    hf.setBold(true);
    heading->setFont(hf);
    root->addWidget(heading);
    if (!m_hashTypeName.isEmpty()) {
        auto *sub = new QLabel(tr("Detected protection: %1").arg(m_hashTypeName), this);
        sub->setStyleSheet(QStringLiteral("color:#666;"));
        root->addWidget(sub);
    }
    root->addSpacing(8);

    // Strategy chooser.
    auto *form = new QFormLayout;
    m_strategy = new QComboBox(this);
    for (const StrategyInfo &s : recoveryStrategies()) {
        const QString label = s.recommended ? tr("%1 (recommended)").arg(s.label) : s.label;
        m_strategy->addItem(label, s.id);
    }
    form->addRow(tr("Strategy:"), m_strategy);
    root->addLayout(form);

    m_strategyDesc = new QLabel(this);
    m_strategyDesc->setWordWrap(true);
    m_strategyDesc->setStyleSheet(QStringLiteral("color:#555;"));
    root->addWidget(m_strategyDesc);
    root->addSpacing(6);

    // Per-strategy inputs.
    m_inputs = new QStackedWidget(this);

    // Page 0: Dictionary picker.
    auto *dictPage = new QWidget(m_inputs);
    auto *dictForm = new QFormLayout(dictPage);
    m_dictionary = new QComboBox(dictPage);
    dictForm->addRow(tr("Dictionary:"), m_dictionary);
    m_dictionaryInfo = new QLabel(dictPage);
    m_dictionaryInfo->setWordWrap(true);
    m_dictionaryInfo->setStyleSheet(QStringLiteral("color:#666;"));
    dictForm->addRow(QString(), m_dictionaryInfo);
    m_inputs->addWidget(dictPage);

    // Page 1: Pattern (mask).
    auto *maskPage = new QWidget(m_inputs);
    auto *maskForm = new QFormLayout(maskPage);
    m_mask = new QLineEdit(maskPage);
    m_mask->setPlaceholderText(QStringLiteral("?d?d?d?d?d?d"));
    m_mask->setText(QStringLiteral("?d?d?d?d?d?d"));
    maskForm->addRow(tr("Pattern (mask):"), m_mask);
    auto *maskHint = new QLabel(
        tr("?d digit · ?l lower · ?u upper · ?s symbol · ?a any. Literal characters "
           "are matched as-is."), maskPage);
    maskHint->setWordWrap(true);
    maskHint->setStyleSheet(QStringLiteral("color:#666;"));
    maskForm->addRow(QString(), maskHint);
    m_inputs->addWidget(maskPage);

    // Page 2: Guided / advanced note.
    auto *guidedPage = new QWidget(m_inputs);
    auto *guidedLayout = new QVBoxLayout(guidedPage);
    auto *guidedNote = new QLabel(
        tr("Opens the advanced planner, where you can supply case knowledge "
           "(names, dates, base words) and choose from every attack template."),
        guidedPage);
    guidedNote->setWordWrap(true);
    guidedLayout->addWidget(guidedNote);
    guidedLayout->addStretch();
    m_inputs->addWidget(guidedPage);

    root->addWidget(m_inputs);

    // A divider, then the plain-language summary and the exact command.
    auto *line = new QFrame(this);
    line->setFrameShape(QFrame::HLine);
    line->setFrameShadow(QFrame::Sunken);
    root->addWidget(line);

    m_summary = new QLabel(this);
    m_summary->setWordWrap(true);
    root->addWidget(m_summary);

    m_command = new QPlainTextEdit(this);
    m_command->setReadOnly(true);
    m_command->setMaximumHeight(60);
    m_command->setStyleSheet(QStringLiteral("font-family:monospace;color:#333;background:#f7f7f7;"));
    root->addWidget(m_command);

    // Buttons.
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, this);
    m_primary = buttons->addButton(tr("Start Recovery"), QDialogButtonBox::AcceptRole);
    connect(m_primary, &QPushButton::clicked, this, &RecoverPasswordDialog::onPrimaryClicked);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    root->addWidget(buttons);

    populateDictionaries();

    connect(m_strategy, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &RecoverPasswordDialog::strategyChanged);
    connect(m_dictionary, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &RecoverPasswordDialog::replan);
    connect(m_mask, &QLineEdit::textChanged, this, &RecoverPasswordDialog::replan);

    strategyChanged(); // sets inputs page + first plan
}

void RecoverPasswordDialog::populateDictionaries()
{
    m_dictionary->clear();
    const QList<DictionaryEntry> entries = m_library.entries();
    for (const DictionaryEntry &e : entries) {
        QString label = e.displayName;
        if (!e.fileExists())
            label += tr("  — file not supplied");
        else if (e.candidateCount >= 0)
            label += tr("  — %1 candidates").arg(formatCount(e.candidateCount));
        m_dictionary->addItem(label, e.id);
    }
    // Default to the library's case-knowledge-free default (CaseKey Common).
    const QString def = m_library.defaultEntryId();
    const int idx = m_dictionary->findData(def);
    if (idx >= 0)
        m_dictionary->setCurrentIndex(idx);
}

RecoveryStrategy RecoverPasswordDialog::currentStrategy() const
{
    const QString id = m_strategy->currentData().toString();
    for (const StrategyInfo &s : recoveryStrategies())
        if (s.id == id)
            return s.strategy;
    return RecoveryStrategy::Dictionary;
}

void RecoverPasswordDialog::strategyChanged()
{
    const StrategyInfo info = strategyInfo(currentStrategy());
    m_strategyDesc->setText(info.description);
    if (info.usesDictionary)
        m_inputs->setCurrentIndex(0);
    else if (info.usesMask)
        m_inputs->setCurrentIndex(1);
    else
        m_inputs->setCurrentIndex(2);
    replan();
}

void RecoverPasswordDialog::replan()
{
    m_planOk = false;
    m_spec = AttackJobSpec{};
    m_engineId.clear();
    m_dictionaryId.clear();
    m_command->clear();

    const RecoveryStrategy strat = currentStrategy();

    if (strat == RecoveryStrategy::GuidedAdvanced) {
        m_primary->setText(tr("Open Advanced Planner…"));
        m_primary->setEnabled(true);
        m_summary->setText(tr("Choose case knowledge and a template in the advanced planner."));
        return;
    }
    m_primary->setText(tr("Start Recovery"));

    QString problem;
    if (strat == RecoveryStrategy::Dictionary) {
        if (m_dictionary->count() == 0) {
            problem = tr("No dictionaries are available. Add one under "
                         "Settings → Dictionaries, then try again.");
        } else {
            m_dictionaryId = m_dictionary->currentData().toString();
            bool found = false;
            const DictionaryEntry entry = m_library.entry(m_dictionaryId, &found);
            if (!found || !entry.fileExists()) {
                problem = tr("The wordlist file for “%1” is not present. Supply it "
                             "(or choose another dictionary) before starting.")
                              .arg(entry.displayName.isEmpty() ? m_dictionaryId : entry.displayName);
            } else {
                PlannerContext ctx;
                ctx.hashMode = m_hashMode;
                ctx.hashTypeName = m_hashTypeName;
                ctx.hashFile = m_hashFile;
                ctx.planDir = m_planDir;
                ctx.commonWordlist = entry.absolutePath;
                const PlanResult r = AttackPlanner().plan(AttackTemplate::CommonPasswords,
                                                          CaseKnowledge{}, ctx);
                if (!r.ok)
                    problem = r.error;
                else
                    m_spec = r.spec;
            }
        }
    } else { // Mask
        const QString mask = m_mask->text().trimmed();
        if (mask.isEmpty()) {
            problem = tr("Enter a pattern (mask) to try.");
        } else {
            m_spec.hashMode = m_hashMode;
            m_spec.hashFile = m_hashFile;
            m_spec.attackMode = AttackModeNum::BruteForceMask;
            m_spec.mask = mask;
        }
    }

    if (!problem.isEmpty()) {
        m_summary->setText(problem);
        m_primary->setEnabled(false);
        return;
    }

    // Automatic engine selection: prefer hashcat, fall back only when it cannot
    // express the attack; refuse (with a reason) when no engine can.
    QString reason;
    const RecoveryEngine *engine = m_engines.selectForSpec(m_spec, &reason);
    if (!engine) {
        m_summary->setText(tr("No available recovery engine can run this attack: %1").arg(reason));
        m_primary->setEnabled(false);
        return;
    }
    m_engineId = engine->id();

    // Plain-language summary of what will run.
    QString summary;
    if (strat == RecoveryStrategy::Dictionary) {
        bool found = false;
        const DictionaryEntry entry = m_library.entry(m_dictionaryId, &found);
        summary = tr("Try the “%1” wordlist (%2 candidates) using %3. "
                     "This needs nothing known about the case.")
                      .arg(entry.displayName, formatCount(entry.candidateCount), engine->displayName());
    } else {
        const qint64 keyspace = KnowledgeMaterializer::estimateKeyspace(m_spec);
        summary = tr("Try every candidate matching %1 (%2 candidates) using %3.")
                      .arg(m_spec.mask, formatCount(keyspace), engine->displayName());
    }
    m_summary->setText(summary);

    // The exact command, for transparency (CaseKey never hides the engine).
    m_command->setPlainText(engine->displayName() + QLatin1Char(' ')
                            + engine->buildArgs(m_spec).join(QLatin1Char(' ')));

    m_planOk = true;
    m_primary->setEnabled(true);
}

void RecoverPasswordDialog::onPrimaryClicked()
{
    if (currentStrategy() == RecoveryStrategy::GuidedAdvanced) {
        m_guidedRequested = true;
        accept();
        return;
    }
    if (!m_planOk)
        return;
    m_startRequested = true;
    accept();
}
