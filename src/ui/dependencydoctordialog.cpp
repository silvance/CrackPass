/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "dependencydoctordialog.h"

#include "forensic/deps/dependencyprobe.h"
#include "forensic/extraction/processrunner.h"
#include "settingsmanager.h"

#include <QApplication>
#include <QDialogButtonBox>
#include <QHeaderView>
#include <QLocale>
#include <QPushButton>
#include <QTreeWidget>
#include <QVBoxLayout>

using forensic::DependencyProbe;
using forensic::DependencyReport;
using forensic::ToolStatus;

namespace {
QString yn(bool b) { return b ? QObject::tr("yes") : QObject::tr("no"); }

QTreeWidgetItem *kv(QTreeWidgetItem *parent, const QString &k, const QString &v)
{
    auto *i = new QTreeWidgetItem(parent);
    i->setText(0, k);
    i->setText(1, v.isEmpty() ? QStringLiteral("-") : v);
    return i;
}
} // namespace

DependencyDoctorDialog::DependencyDoctorDialog(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(tr("System / Tool Status"));
    resize(760, 560);
    auto *root = new QVBoxLayout(this);

    m_tree = new QTreeWidget(this);
    m_tree->setColumnCount(2);
    m_tree->setHeaderLabels({tr("Item"), tr("Status")});
    m_tree->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_tree->header()->setStretchLastSection(true);
    root->addWidget(m_tree);

    auto *buttons = new QDialogButtonBox(this);
    auto *rescanBtn = buttons->addButton(tr("Re-scan"), QDialogButtonBox::ActionRole);
    buttons->addButton(QDialogButtonBox::Close);
    connect(rescanBtn, &QPushButton::clicked, this, &DependencyDoctorDialog::rescan);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    root->addWidget(buttons);

    rescan();
}

void DependencyDoctorDialog::rescan()
{
    m_tree->clear();

    forensic::QtProcessRunner runner;
    auto settings = [](const QString &k) { return SettingsManager::instance().getKey<QString>(k); };
    DependencyProbe probe(&runner, QApplication::applicationDirPath(), settings);

    QApplication::setOverrideCursor(Qt::WaitCursor);
    const DependencyReport rep = probe.run();
    QApplication::restoreOverrideCursor();

    // hashcat
    auto *hc = new QTreeWidgetItem(m_tree);
    hc->setText(0, tr("hashcat"));
    hc->setText(1, rep.hashcat.found ? tr("detected") : tr("NOT FOUND"));
    kv(hc, tr("Path"), rep.hashcat.program);
    kv(hc, tr("Resolved via"), rep.hashcat.source);
    kv(hc, tr("Version"), rep.hashcat.version);
    kv(hc, tr("Self-test"), rep.hashcat.selfTestRun
                                ? (rep.hashcat.selfTestOk ? tr("passed") : tr("FAILED"))
                                : tr("not run"));
    if (!rep.hashcat.detail.isEmpty())
        kv(hc, tr("Detail"), rep.hashcat.detail);
    auto *dev = kv(hc, tr("Backend / devices"), QString());
    dev->setText(1, rep.hashcatBackendInfo.isEmpty() ? tr("(unavailable)")
                                                      : rep.hashcatBackendInfo.left(2000));
    hc->setExpanded(true);

    // extractors
    auto *ex = new QTreeWidgetItem(m_tree);
    ex->setText(0, tr("Extraction utilities"));
    int available = 0;
    for (const ToolStatus &t : rep.extractors) {
        auto *ti = new QTreeWidgetItem(ex);
        ti->setText(0, t.id);
        ti->setText(1, t.found ? tr("available") : tr("MISSING"));
        if (t.found) {
            ++available;
            kv(ti, tr("Path"), t.program);
            kv(ti, tr("Resolved via"), t.source);
            if (!t.interpreter.isEmpty())
                kv(ti, tr("Interpreter"), t.interpreter);
        }
        if (!t.detail.isEmpty())
            kv(ti, tr("Detail"), t.detail);
    }
    ex->setText(1, tr("%1 of %2 available").arg(available).arg(rep.extractors.size()));
    ex->setExpanded(true);

    // resources
    auto *res = new QTreeWidgetItem(m_tree);
    res->setText(0, tr("Resources"));
    kv(res, tr("Common wordlist"),
       rep.resources.commonWordlist.isEmpty()
           ? tr("(not set)")
           : QStringLiteral("%1 (%2)").arg(rep.resources.commonWordlist,
                                           yn(rep.resources.commonWordlistOk)));
    kv(res, tr("Rules"), tr("%1 in %2").arg(rep.resources.rules.size()).arg(rep.resources.rulesDir));
    kv(res, tr("Case location writable"),
       rep.resources.caseRoot.isEmpty() ? tr("(not set)")
                                        : QStringLiteral("%1 (%2)").arg(rep.resources.caseRoot,
                                                                        yn(rep.resources.caseRootWritable)));
    kv(res, tr("Free space"),
       rep.resources.freeBytes < 0 ? tr("(unknown)")
                                   : QLocale().formattedDataSize(rep.resources.freeBytes));
    res->setExpanded(true);
}
