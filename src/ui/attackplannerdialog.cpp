/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "attackplannerdialog.h"

#include "forensic/planner/attackcommandbuilder.h"
#include "forensic/planner/knowledgematerializer.h"

#include <QProcess>
#include <QRegularExpression>
#include <QFont>

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QLocale>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QVBoxLayout>

using namespace forensic;

namespace {

QStringList splitList(const QString &text)
{
    QStringList out;
    const QStringList parts = text.split(QRegularExpression(QStringLiteral("[,;\\n]")), Qt::SkipEmptyParts);
    for (const QString &p : parts) {
        const QString t = p.trimmed();
        if (!t.isEmpty())
            out << t;
    }
    return out;
}

} // namespace

AttackPlannerDialog::AttackPlannerDialog(quint32 hashMode, const QString &hashTypeName,
                                         const QString &hashFile, const QString &planDir,
                                         QWidget *parent)
    : QDialog(parent)
    , m_hashMode(hashMode)
    , m_hashTypeName(hashTypeName)
    , m_hashFile(hashFile)
    , m_planDir(planDir)
{
    setWindowTitle(tr("Plan Attack"));
    resize(900, 640);

    auto *root = new QVBoxLayout(this);

    auto *top = new QHBoxLayout;
    top->addWidget(new QLabel(tr("Template:"), this));
    m_template = new QComboBox(this);
    m_template->addItem(tr("Quick Attempt"), int(AttackTemplate::QuickAttempt));
    m_template->addItem(tr("Common Passwords"), int(AttackTemplate::CommonPasswords));
    m_template->addItem(tr("Case Wordlist"), int(AttackTemplate::CaseWordlist));
    m_template->addItem(tr("Wordlist + Rules"), int(AttackTemplate::WordlistRules));
    m_template->addItem(tr("Known Password Variations"), int(AttackTemplate::KnownPasswordVariations));
    m_template->addItem(tr("Mask Attack"), int(AttackTemplate::MaskAttack));
    m_template->addItem(tr("Hybrid Attack"), int(AttackTemplate::HybridAttack));
    m_template->addItem(tr("Custom / Advanced"), int(AttackTemplate::CustomAdvanced));
    top->addWidget(m_template, 1);

    // Recovery engine selector, populated from the engine registry so a new
    // engine appears here automatically. hashcat is the default and expresses
    // every template; John runs only the attacks it can express exactly (the
    // preview says so before the examiner can queue).
    top->addWidget(new QLabel(tr("Engine:"), this));
    m_engine = new QComboBox(this);
    for (const forensic::RecoveryEngine *e : m_engines.engines())
        m_engine->addItem(e->displayName(), e->id());
    const int def = m_engine->findData(forensic::RecoveryEngineRegistry::defaultEngineId());
    if (def >= 0)
        m_engine->setCurrentIndex(def);
    top->addWidget(m_engine);
    root->addLayout(top);

    auto *knowledge = new QGroupBox(tr("Case knowledge (optional - becomes explicit wordlists, masks and rules)"), this);
    auto *form = new QFormLayout(knowledge);

    auto *lenRow = new QHBoxLayout;
    m_minLen = new QSpinBox(this); m_minLen->setRange(0, 64); m_minLen->setSpecialValueText(tr("unset"));
    m_maxLen = new QSpinBox(this); m_maxLen->setRange(0, 64); m_maxLen->setSpecialValueText(tr("unset"));
    lenRow->addWidget(new QLabel(tr("min"), this)); lenRow->addWidget(m_minLen);
    lenRow->addWidget(new QLabel(tr("max"), this)); lenRow->addWidget(m_maxLen);
    lenRow->addStretch();
    form->addRow(tr("Length:"), lenRow);

    m_prefix = new QLineEdit(this);
    m_suffix = new QLineEdit(this);
    form->addRow(tr("Known prefix:"), m_prefix);
    form->addRow(tr("Known suffix:"), m_suffix);

    m_knownPositions = new QLineEdit(this);
    m_knownPositions->setPlaceholderText(tr("0-based, e.g. 0:P, 3:!, 5:a"));
    form->addRow(tr("Known positions:"), m_knownPositions);

    auto *clsRow = new QHBoxLayout;
    m_clsLower = new QCheckBox(tr("lower"), this);
    m_clsUpper = new QCheckBox(tr("upper"), this);
    m_clsDigit = new QCheckBox(tr("digits"), this);
    m_clsSpecial = new QCheckBox(tr("special"), this);
    clsRow->addWidget(m_clsLower); clsRow->addWidget(m_clsUpper);
    clsRow->addWidget(m_clsDigit); clsRow->addWidget(m_clsSpecial);
    clsRow->addStretch();
    form->addRow(tr("Required classes:"), clsRow);

    m_baseWords = new QLineEdit(this);
    m_names = new QLineEdit(this);
    m_usernames = new QLineEdit(this);
    m_emails = new QLineEdit(this);
    m_previous = new QLineEdit(this);
    for (QLineEdit *e : {m_baseWords, m_names, m_usernames, m_emails, m_previous})
        e->setPlaceholderText(tr("comma or newline separated"));
    form->addRow(tr("Suspected base words:"), m_baseWords);
    form->addRow(tr("Names:"), m_names);
    form->addRow(tr("Usernames:"), m_usernames);
    form->addRow(tr("Email addresses:"), m_emails);
    form->addRow(tr("Previously recovered:"), m_previous);

    auto *yearRow = new QHBoxLayout;
    m_yearFrom = new QSpinBox(this); m_yearFrom->setRange(0, 2100); m_yearFrom->setSpecialValueText(tr("unset"));
    m_yearTo = new QSpinBox(this); m_yearTo->setRange(0, 2100); m_yearTo->setSpecialValueText(tr("unset"));
    yearRow->addWidget(new QLabel(tr("from"), this)); yearRow->addWidget(m_yearFrom);
    yearRow->addWidget(new QLabel(tr("to"), this)); yearRow->addWidget(m_yearTo);
    yearRow->addStretch();
    form->addRow(tr("Year range:"), yearRow);

    auto *commonRow = new QHBoxLayout;
    m_commonWordlist = new QLineEdit(this);
    m_commonWordlist->setPlaceholderText(tr("path to an external wordlist (advanced/offline)"));
    // This is the ADVANCED path: browse to an arbitrary external wordlist. The
    // normal, managed dictionary (CaseKey Common, etc.) is chosen in the
    // "Recover Password" workflow via the Dictionary library, not here.
    m_commonWordlist->setToolTip(tr("Advanced: an arbitrary external wordlist. For the normal "
                                    "workflow, use Recover Password and pick a managed "
                                    "dictionary instead. Prefilled from the legacy default "
                                    "wordlist setting if one is configured."));
    auto *browse = new QPushButton(tr("Browse..."), this);
    connect(browse, &QPushButton::clicked, this, [this] {
        const QString p = QFileDialog::getOpenFileName(this, tr("Select wordlist"));
        if (!p.isEmpty()) m_commonWordlist->setText(p);
    });
    commonRow->addWidget(m_commonWordlist, 1);
    commonRow->addWidget(browse);
    form->addRow(tr("External wordlist (advanced):"), commonRow);

    m_customArgs = new QLineEdit(this);
    m_customArgs->setPlaceholderText(tr("extra hashcat args for Custom / Advanced"));
    form->addRow(tr("Custom args:"), m_customArgs);

    root->addWidget(knowledge);

    root->addWidget(new QLabel(tr("<b>Plan preview</b> (nothing is executed):"), this));
    m_preview = new QPlainTextEdit(this);
    m_preview->setReadOnly(true);
    root->addWidget(m_preview, 1);

    root->addWidget(new QLabel(tr("Generated hashcat command:"), this));
    m_command = new QPlainTextEdit(this);
    m_command->setReadOnly(true);
    m_command->setMaximumHeight(70);
    QFont mono(QStringLiteral("monospace"));
    mono.setStyleHint(QFont::TypeWriter);
    m_command->setFont(mono);
    root->addWidget(m_command);

    m_status = new QLabel(this);
    m_status->setWordWrap(true);
    root->addWidget(m_status);

    auto *buttons = new QDialogButtonBox(this);
    buttons->addButton(tr("Update Preview"), QDialogButtonBox::ApplyRole);
    auto *queueBtn = buttons->addButton(tr("Queue Attack"), QDialogButtonBox::AcceptRole);
    buttons->addButton(QDialogButtonBox::Close);
    connect(buttons, &QDialogButtonBox::clicked, this, [this, buttons](QAbstractButton *b) {
        const auto role = buttons->buttonRole(b);
        if (role == QDialogButtonBox::ApplyRole)
            updatePreview();
        else if (role == QDialogButtonBox::AcceptRole)
            requestQueue();
        else
            reject();
    });
    root->addWidget(buttons);

    // Live preview on the common interactions.
    connect(m_template, &QComboBox::currentIndexChanged, this, &AttackPlannerDialog::updatePreview);
    connect(m_engine, &QComboBox::currentIndexChanged, this, &AttackPlannerDialog::updatePreview);
    updatePreview();
    Q_UNUSED(queueBtn);
}

QString AttackPlannerDialog::plannedEngineId() const
{
    return m_engine->currentData().toString();
}

void AttackPlannerDialog::requestQueue()
{
    updatePreview();
    if (!m_lastOk) {
        m_status->setText(tr("Cannot queue: the plan is not valid yet."));
        return;
    }
    if (!m_engineOk) {
        // The selected engine cannot express this attack; refuse rather than
        // queue an approximation (the reason is already shown in the status).
        return;
    }
    m_queueRequested = true;
    accept();
}

AttackTemplate AttackPlannerDialog::currentTemplate() const
{
    return static_cast<AttackTemplate>(m_template->currentData().toInt());
}

CaseKnowledge AttackPlannerDialog::collectKnowledge() const
{
    CaseKnowledge k;
    k.minLength = m_minLen->value() > 0 ? m_minLen->value() : -1;
    k.maxLength = m_maxLen->value() > 0 ? m_maxLen->value() : -1;
    k.knownPrefix = m_prefix->text();
    k.knownSuffix = m_suffix->text();
    k.knownPositions = KnowledgeMaterializer::parseKnownPositions(m_knownPositions->text());
    if (m_clsLower->isChecked())   k.requiredClasses |= CharClass::Lower;
    if (m_clsUpper->isChecked())   k.requiredClasses |= CharClass::Upper;
    if (m_clsDigit->isChecked())   k.requiredClasses |= CharClass::Digit;
    if (m_clsSpecial->isChecked()) k.requiredClasses |= CharClass::Special;
    k.baseWords = splitList(m_baseWords->text());
    k.names = splitList(m_names->text());
    k.usernames = splitList(m_usernames->text());
    k.emails = splitList(m_emails->text());
    k.previousPasswords = splitList(m_previous->text());
    k.yearFrom = m_yearFrom->value() > 0 ? m_yearFrom->value() : -1;
    k.yearTo = m_yearTo->value() > 0 ? m_yearTo->value() : -1;
    return k;
}

void AttackPlannerDialog::updatePreview()
{
    PlannerContext ctx;
    ctx.hashMode = m_hashMode;
    ctx.hashTypeName = m_hashTypeName;
    ctx.hashFile = m_hashFile;
    ctx.planDir = m_planDir;
    ctx.commonWordlist = m_commonWordlist->text().trimmed();
    ctx.customArgs = QProcess::splitCommand(m_customArgs->text());
    ctx.devices = {tr("(selected at run time / in Advanced Mode)")};

    AttackPlanner planner;
    const PlanResult r = planner.plan(currentTemplate(), collectKnowledge(), ctx);
    m_lastOk = r.ok;
    m_lastSpec = r.spec;
    m_engineOk = false; // recomputed below once we have a valid spec + engine

    if (!r.ok) {
        m_preview->setPlainText(QString());
        m_command->setPlainText(QString());
        m_status->setText(tr("Cannot build this plan yet: %1").arg(r.error));
        return;
    }

    const RecoveryEngine *engine = m_engines.find(plannedEngineId());
    const QString engineName = engine ? engine->displayName() : plannedEngineId();
    // A valid plan may still be unexpressible by the chosen engine (e.g. John
    // cannot run hashcat rule files). Ask the engine before offering to queue.
    const QString engineReason = engine ? engine->unsupportedReason(r.spec)
                                        : tr("unknown engine");
    m_engineOk = engine && engineReason.isEmpty();

    const AttackPreview &p = r.preview;
    const QString keyspace = p.estimatedKeyspace >= 0
        ? QLocale().toString(p.estimatedKeyspace)
        : tr("unknown / not applicable");

    QString text;
    text += tr("Template:        %1\n").arg(p.templateName);
    text += tr("Engine:          %1\n").arg(engineName);
    text += tr("Hash type:       %1\n").arg(p.hashTypeName.isEmpty() ? tr("(unnamed)") : p.hashTypeName);
    text += tr("Hashcat mode:    -m %1\n").arg(p.hashMode);
    text += tr("Attack mode:     -a %1  (%2)\n").arg(p.attackMode).arg(p.attackModeName);
    text += tr("Wordlists:       %1\n").arg(p.wordlists.isEmpty() ? tr("(none)") : p.wordlists.join(QStringLiteral(", ")));
    text += tr("Rules:           %1\n").arg(p.rules.isEmpty() ? tr("(none)") : p.rules.join(QStringLiteral(", ")));
    text += tr("Mask:            %1\n").arg(p.mask.isEmpty() ? tr("(none)") : p.mask);
    text += tr("Est. keyspace:   %1\n").arg(keyspace);
    text += tr("Devices:         %1\n").arg(p.devices.join(QStringLiteral(", ")));
    if (!r.generatedFiles.isEmpty())
        text += tr("Generated files: %1\n").arg(r.generatedFiles.join(QStringLiteral(", ")));
    if (!r.spec.notes.isEmpty())
        text += tr("Notes:           %1\n").arg(r.spec.notes);
    m_preview->setPlainText(text);

    // Show the command for the SELECTED engine, built from the same spec.
    if (m_engineOk) {
        const QString argv = engine->buildArgs(r.spec).join(QLatin1Char(' '));
        m_command->setPlainText(engineName + QLatin1Char(' ') + argv);
        m_status->setText(tr("This is a preview only. No attack is started. Review the "
                             "command, then Queue Attack to run it with %1.").arg(engineName));
    } else {
        m_command->setPlainText(tr("(not runnable by %1)").arg(engineName));
        m_status->setText(tr("%1 cannot run this attack: %2\n"
                             "Switch the engine to hashcat, or adjust the plan.")
                              .arg(engineName, engineReason));
    }
}
