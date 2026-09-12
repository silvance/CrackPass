/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
 */
#include "forensic/casetransaction.h"
#include "forensic/auditlog.h"

#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <QtTest>

using forensic::AuditLog;
using forensic::CaseTransaction;

class TestCaseTransaction : public QObject
{
    Q_OBJECT

private:
    static QByteArray read(const QString &path)
    {
        QFile f(path);
        return f.open(QIODevice::ReadOnly) ? f.readAll() : QByteArray("<unreadable>");
    }
    static void writeFile(const QString &path, const QByteArray &data)
    {
        QFile f(path); f.open(QIODevice::WriteOnly | QIODevice::Truncate); f.write(data); f.close();
    }

private slots:
    void commitWritesFileAndAuditTogether();
    void commitCreatesParentDirectories();
    void auditFailureRollsBackExistingFile();
    void auditFailureRemovesNewlyCreatedFile();
    void stateWriteFailureLeavesNoAudit();
    void firstWriteRolledBackWhenLaterWriteFails();
    void nullAuditPerformsWritesOnly();
};

void TestCaseTransaction::commitWritesFileAndAuditTogether()
{
    QTemporaryDir dir;
    AuditLog audit(dir.filePath("audit.jsonl"));
    const QString target = dir.filePath("sub/state.json");

    CaseTransaction tx(&audit, QStringLiteral("examiner"));
    tx.write(target, QByteArray("{\"k\":1}"))
      .audit(QStringLiteral("case_created"), QStringLiteral("case"), QStringLiteral("c1"), {});

    QString err;
    QVERIFY2(tx.commit(&err), qPrintable(err));
    QCOMPARE(read(target), QByteArray("{\"k\":1}"));
    QCOMPARE(audit.events().size(), 1);
    QCOMPARE(audit.events().at(0).action, QStringLiteral("case_created"));
    QVERIFY(audit.verify());
}

void TestCaseTransaction::commitCreatesParentDirectories()
{
    QTemporaryDir dir;
    AuditLog audit(dir.filePath("audit.jsonl"));
    const QString target = dir.filePath("a/b/c/state.json");
    CaseTransaction tx(&audit, QStringLiteral("examiner"));
    tx.write(target, QByteArray("X"));
    QVERIFY(tx.commit());
    QVERIFY(QFile::exists(target));
}

void TestCaseTransaction::auditFailureRollsBackExistingFile()
{
    QTemporaryDir dir;
    const QString target = dir.filePath("state.json");
    writeFile(target, QByteArray("OLD"));

    // Audit path under a directory that cannot be created => append() fails.
    AuditLog badAudit(QStringLiteral("/no/such/dir/audit.jsonl"));
    CaseTransaction tx(&badAudit, QStringLiteral("examiner"));
    tx.write(target, QByteArray("NEW"))
      .audit(QStringLiteral("act"), QStringLiteral("type"), QStringLiteral("id"), {});

    QString err;
    QVERIFY(!tx.commit(&err));
    QVERIFY(!err.isEmpty());
    // The state write must have been rolled back to its prior contents...
    QCOMPARE(read(target), QByteArray("OLD"));
    // ...and the audit chain never advanced.
    QVERIFY(badAudit.events().isEmpty());
}

void TestCaseTransaction::auditFailureRemovesNewlyCreatedFile()
{
    QTemporaryDir dir;
    const QString target = dir.filePath("brand-new.json"); // does not exist yet

    AuditLog badAudit(QStringLiteral("/no/such/dir/audit.jsonl"));
    CaseTransaction tx(&badAudit, QStringLiteral("examiner"));
    tx.write(target, QByteArray("NEW"))
      .audit(QStringLiteral("act"), QStringLiteral("type"), QStringLiteral("id"), {});

    QVERIFY(!tx.commit());
    // A file that did not exist before the transaction must not survive a rollback.
    QVERIFY(!QFile::exists(target));
    QVERIFY(badAudit.events().isEmpty());
}

void TestCaseTransaction::stateWriteFailureLeavesNoAudit()
{
    QTemporaryDir dir;
    AuditLog audit(dir.filePath("audit.jsonl"));

    // Make the write's parent path a regular file so mkpath of the directory fails.
    const QString blocker = dir.filePath("blocker");
    writeFile(blocker, QByteArray("x"));
    const QString target = dir.filePath("blocker/state.json");

    CaseTransaction tx(&audit, QStringLiteral("examiner"));
    tx.write(target, QByteArray("NEW"))
      .audit(QStringLiteral("act"), QStringLiteral("type"), QStringLiteral("id"), {});

    QString err;
    QVERIFY(!tx.commit(&err));
    // The audit entry must never be appended when the state write cannot happen.
    QVERIFY(audit.events().isEmpty());
    QVERIFY(!QFile::exists(dir.filePath("audit.jsonl")));
}

void TestCaseTransaction::firstWriteRolledBackWhenLaterWriteFails()
{
    QTemporaryDir dir;
    AuditLog audit(dir.filePath("audit.jsonl"));

    const QString t1 = dir.filePath("a.json");
    writeFile(t1, QByteArray("OLD1"));
    const QString blocker = dir.filePath("blk");
    writeFile(blocker, QByteArray("x"));
    const QString t2 = dir.filePath("blk/b.json"); // parent is a file => write fails

    CaseTransaction tx(&audit, QStringLiteral("examiner"));
    tx.write(t1, QByteArray("NEW1"))
      .write(t2, QByteArray("NEW2"))
      .audit(QStringLiteral("act"), QStringLiteral("type"), QStringLiteral("id"), {});

    QVERIFY(!tx.commit());
    // The already-applied first write is undone when a later one fails.
    QCOMPARE(read(t1), QByteArray("OLD1"));
    QVERIFY(audit.events().isEmpty());
}

void TestCaseTransaction::nullAuditPerformsWritesOnly()
{
    QTemporaryDir dir;
    const QString target = dir.filePath("state.json");

    CaseTransaction tx(nullptr, QStringLiteral("examiner"));
    tx.write(target, QByteArray("DATA"))
      .audit(QStringLiteral("ignored"), QStringLiteral("t"), QStringLiteral("i"), {});

    QVERIFY(tx.commit());
    QCOMPARE(read(target), QByteArray("DATA"));
}

QTEST_GUILESS_MAIN(TestCaseTransaction)
#include "test_casetransaction.moc"
