/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * SPDX-FileCopyrightText: CaseKey contributors
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
    void tailTruncationIsDetectedViaAnchor();
    void wholeLogDeletionIsDetectedViaAnchor();
    void anchorStaysInSyncAcrossReload();
    void appendFailureDoesNotAdvanceChain();
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

    // load() itself must reject a tampered chain (never open as if valid).
    AuditLog reloaded(path);
    QString error;
    QVERIFY(!reloaded.load(&error));
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
    QVERIFY(!reloaded.load());
}


void TestAuditLog::tailTruncationIsDetectedViaAnchor()
{
    // Dropping entries from the END leaves a chain that is internally consistent
    // but shorter than the anchor records, so load() must reject it.
    QTemporaryDir dir;
    const QString path = dir.filePath("audit.jsonl");
    {
        AuditLog log(path);
        log.append("examiner", "case_created", "case", "c1", {});
        log.append("examiner", "e2", "x", "id2", {});
        log.append("examiner", "e3", "x", "id3", {});
    }
    // Keep only the first two events (drop the trailing one). The anchor still
    // records three events with the third's head hash.
    QFile f(path);
    QVERIFY(f.open(QIODevice::ReadOnly));
    const QList<QByteArray> lines = f.readAll().split('\n');
    f.close();
    QVERIFY(f.open(QIODevice::WriteOnly | QIODevice::Truncate));
    f.write(lines.at(0)); f.write("\n");
    f.write(lines.at(1)); f.write("\n");
    f.close();

    AuditLog reloaded(path);
    QString err;
    QVERIFY(!reloaded.load(&err));       // now detected via the anchor
    QVERIFY(!err.isEmpty());
}

void TestAuditLog::wholeLogDeletionIsDetectedViaAnchor()
{
    // Deleting the entire log while the anchor survives must be detected: the
    // anchor expects events that no longer exist.
    QTemporaryDir dir;
    const QString path = dir.filePath("audit.jsonl");
    {
        AuditLog log(path);
        log.append("examiner", "case_created", "case", "c1", {});
        log.append("examiner", "e2", "x", "id2", {});
    }
    QVERIFY(QFile::remove(path));        // anchor (path + ".anchor") remains

    AuditLog reloaded(path);
    QVERIFY(!reloaded.load());
}

void TestAuditLog::anchorStaysInSyncAcrossReload()
{
    // A legitimate log always matches its anchor across reloads.
    QTemporaryDir dir;
    const QString path = dir.filePath("audit.jsonl");
    QString head;
    {
        AuditLog log(path);
        log.append("examiner", "case_created", "case", "c1", {});
        log.append("examiner", "e2", "x", "id2", {});
        head = log.headHash();
    }
    QVERIFY(QFile::exists(path + ".anchor"));
    AuditLog reloaded(path);
    QVERIFY(reloaded.load());
    QCOMPARE(reloaded.events().size(), 2);
    QCOMPARE(reloaded.headHash(), head);

    // A further append keeps the anchor in step for the next reload.
    QVERIFY(reloaded.append("examiner", "e3", "x", "id3", {}));
    AuditLog again(path);
    QVERIFY(again.load());
    QCOMPARE(again.events().size(), 3);
    QCOMPARE(again.headHash(), reloaded.headHash());
}

void TestAuditLog::appendFailureDoesNotAdvanceChain()
{
    // A path under a non-existent directory cannot be opened for append.
    AuditLog log(QStringLiteral("/no/such/dir/audit.jsonl"));
    const bool ok = log.append("examiner", "case_created", "case", "c1", {});
    QVERIFY(!ok);                       // reported failure
    QVERIFY(!log.lastError().isEmpty());
    QVERIFY(log.headHash().isEmpty());  // in-memory chain did NOT advance
    QCOMPARE(log.events().size(), 0);
}

QTEST_GUILESS_MAIN(TestAuditLog)
#include "test_auditlog.moc"
