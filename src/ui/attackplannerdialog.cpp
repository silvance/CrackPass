/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#include "attackplannerdialog.h"

#include "forensic/planner/attackcommandbuilder.h"

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
    m_commonWordlist->setPlaceholderText(tr("path to a common-passwords wordlist (offline)"));
    auto *browse = new QPushButton(tr("Browse..."), this);
    connect(browse, &QPushButton::clicked, this, [this] {
        const QString p = QFileDialog::getOpenFileName(this, tr("Select wordlist"));
        if (!p.isEmpty()) m_commonWordlist->setText(p);
    });
    commonRow->addWidget(m_commonWordlist, 1);
    commonRow->addWidget(browse);
    form->addRow(tr("Common wordlist:"), commonRow);

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
    buttons->addButton(QDialogButtonBox::Close);
    connect(buttons, &QDialogButtonBox::clicked, this, [this, buttons](QAbstractButton *b) {
        if (buttons->buttonRole(b) == QDialogButtonBox::ApplyRole)
            updatePreview();
        else
            reject();
    });
    root->addWidget(buttons);

    // Live preview on the common interactions.
    connect(m_template, &QComboBox::currentIndexChanged, this, &AttackPlannerDialog::updatePreview);
    updatePreview();
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

    if (!r.ok) {
        m_preview->setPlainText(QString());
        m_command->setPlainText(QString());
        m_status->setText(tr("Cannot build this plan yet: %1").arg(r.error));
        return;
    }

    const AttackPreview &p = r.preview;
    const QString keyspace = p.estimatedKeyspace >= 0
        ? QLocale().toString(p.estimatedKeyspace)
        : tr("unknown / not applicable");

    QString text;
    text += tr("Template:        %1\n").arg(p.templateName);
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

    m_command->setPlainText(p.command.join(QLatin1Char(' ')));
    m_status->setText(tr("This is a preview only. No attack is started. Review the command, "
                         "then run it from Advanced Hashcat Mode."));
}
