/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CrackPass contributors
 */
#include "forensic/auditlog.h"

#include <QFile>
#include <QJsonObject>
#include <QTemporaryDir>
#include <QtTest>

using forensic::AuditLog;

class TestAuditLog : public QObject
{
    Q_OBJECT

private slots:
    void appendAndVerify();
    void reloadPreservesChain();
    void tamperingIsDetected();
    void deletionIsDetected();
};

void TestAuditLog::appendAndVerify()
{
    QTemporaryDir dir;
    AuditLog log(dir.filePath("audit.jsonl"));
    log.append("examiner", "case_created", "case", "c1", {});
    QJsonObject d; d["filename"] = "secret.pdf";
    log.append("examiner", "evidence_added", "evidence", "e1", d);

    QCOMPARE(log.events().size(), 2);
    QVERIFY(!log.headHash().isEmpty());
    QVERIFY(log.verify());
    // First event links to empty genesis hash.
    QCOMPARE(log.events().at(0).prevHash, QString());
    QCOMPARE(log.events().at(1).prevHash, log.events().at(0).hash);
}

void TestAuditLog::reloadPreservesChain()
{
    QTemporaryDir dir;
    const QString path = dir.filePath("audit.jsonl");
    QString head;
    {
        AuditLog log(path);
        log.append("examiner", "case_created", "case", "c1", {});
        log.append("examiner", "evidence_added", "evidence", "e1", {});
        head = log.headHash();
    }
    AuditLog reloaded(path);
    QVERIFY(reloaded.load());
    QCOMPARE(reloaded.events().size(), 2);
    QCOMPARE(reloaded.headHash(), head);
    QVERIFY(reloaded.verify());
}

void TestAuditLog::tamperingIsDetected()
{
    QTemporaryDir dir;
    const QString path = dir.filePath("audit.jsonl");
    {
        AuditLog log(path);
        log.append("examiner", "case_created", "case", "c1", {});
        QJsonObject d; d["filename"] = "secret.pdf";
        log.append("examiner", "evidence_added", "evidence", "e1", d);
    }
    // Tamper: change a field in the file without recomputing the hash.
    QFile f(path);
    QVERIFY(f.open(QIODevice::ReadOnly));
    QByteArray content = f.readAll();
    f.close();
    content.replace("secret.pdf", "benign.txt");
    QVERIFY(f.open(QIODevice::WriteOnly | QIODevice::Truncate));
    f.write(content);
    f.close();

    AuditLog reloaded(path);
    QVERIFY(reloaded.load());
    QString error;
    QVERIFY(!reloaded.verify(&error));
    QVERIFY(!error.isEmpty());
}

void TestAuditLog::deletionIsDetected()
{
    QTemporaryDir dir;
    const QString path = dir.filePath("audit.jsonl");
    {
        AuditLog log(path);
        log.append("examiner", "case_created", "case", "c1", {});
        log.append("examiner", "e2", "x", "id2", {});
        log.append("examiner", "e3", "x", "id3", {});
    }
    // Delete the middle line: the chain linkage must break.
    QFile f(path);
    QVERIFY(f.open(QIODevice::ReadOnly));
    const QList<QByteArray> lines = f.readAll().split('\n');
    f.close();
    QVERIFY(f.open(QIODevice::WriteOnly | QIODevice::Truncate));
    f.write(lines.at(0)); f.write("\n");
    f.write(lines.at(2)); f.write("\n");
    f.close();

    AuditLog reloaded(path);
    QVERIFY(reloaded.load());
    QVERIFY(!reloaded.verify());
}

QTEST_GUILESS_MAIN(TestAuditLog)
#include "test_auditlog.moc"
